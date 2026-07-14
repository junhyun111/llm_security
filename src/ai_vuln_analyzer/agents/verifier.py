from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.analysis.cfg_analyzer import CfgAnalyzer
from ai_vuln_analyzer.core.schemas import PatchSuggestion, VerificationResult, VulnerabilityFinding
from ai_vuln_analyzer.verifier.real_patch import RealPatchValidator
from ai_vuln_analyzer.verifier.integrated_patch import IntegratedPatchValidator


class Verifier:
    def __init__(
        self,
        agents: list[BaseAgent],
        confidence_threshold: float,
        ast_analyzer: AstAnalyzer | None = None,
        cfg_analyzer: CfgAnalyzer | None = None,
    ) -> None:
        self.agents = agents
        self.confidence_threshold = confidence_threshold
        self.ast_analyzer = ast_analyzer or AstAnalyzer()
        self.cfg_analyzer = cfg_analyzer or CfgAnalyzer(self.ast_analyzer)
        self.real_patch_validator = RealPatchValidator(self.ast_analyzer, self.cfg_analyzer)
        self.integrated_patch_validator = IntegratedPatchValidator(
            self.ast_analyzer, self.cfg_analyzer, self.real_patch_validator
        )

    def verify_integrated(
        self,
        findings: list[VulnerabilityFinding],
        patches: list[PatchSuggestion],
        project_files: list[str | Path],
    ):
        return self.integrated_patch_validator.validate(
            findings, patches, project_files, self.agents
        )

    def verify(
        self,
        findings: list[VulnerabilityFinding],
        patches: list[PatchSuggestion],
        project_files: list[str | Path] | None = None,
    ) -> list[VerificationResult]:
        patch_map = {patch.finding_id: patch for patch in patches}
        results: list[VerificationResult] = []
        for finding in findings:
            patch = patch_map[finding.id]
            rerun_agents = [agent.agent_name for agent in self.agents if finding.cwe in agent.covered_cwes]
            if patch.patched_code.startswith("/* review required */"):
                results.append(self._manual_review_result(finding, rerun_agents))
                continue
            try:
                validation = self.real_patch_validator.validate(
                    finding, patch, self.agents, project_files=project_files
                )
            except (OSError, ValueError) as exc:
                results.append(VerificationResult(
                    finding_id=finding.id, verified=False, confidence=0.1,
                    reason=f"Patch could not be materialized for validation: {exc}",
                    rerun_agents=rerun_agents,
                    remaining_risks=["Patch application failed", "Manual review required"],
                ))
                continue

            verified = (
                validation.parse_succeeded
                and validation.compile_succeeded is True
                and not validation.vulnerability_re_detected
                and not validation.introduced_identifiers
            )
            confidence = 0.96 if verified else self._failure_confidence(validation)
            reason, risks = self._reason(validation)
            results.append(VerificationResult(
                finding_id=finding.id,
                verified=verified and confidence >= self.confidence_threshold,
                confidence=confidence,
                reason=reason,
                rerun_agents=rerun_agents,
                remaining_risks=risks,
                parse_succeeded=validation.parse_succeeded,
                compile_succeeded=validation.compile_succeeded,
                vulnerability_re_detected=validation.vulnerability_re_detected,
                compiler_output=validation.compiler_output,
                introduced_identifiers=list(validation.introduced_identifiers),
            ))
        return results

    def _manual_review_result(
        self, finding: VulnerabilityFinding, rerun_agents: list[str]
    ) -> VerificationResult:
        return VerificationResult(
            finding_id=finding.id, verified=False, confidence=0.15,
            reason="No context-safe automatic rewrite was generated.",
            rerun_agents=rerun_agents,
            remaining_risks=["Original vulnerability remains", "Manual patch required"],
            vulnerability_re_detected=True,
        )

    def _failure_confidence(self, validation) -> float:
        if not validation.parse_succeeded or validation.compile_succeeded is False:
            return 0.1
        if validation.vulnerability_re_detected:
            return 0.2
        if validation.compile_succeeded is None:
            return 0.65
        return 0.4

    def _reason(self, validation) -> tuple[str, list[str]]:
        failures = []
        risks = []
        if not validation.parse_succeeded:
            failures.append("the patched file has AST parse errors")
            risks.append("Patch is not syntactically valid")
        if validation.compile_succeeded is False:
            failures.append("the patch introduces a compilation failure")
            risks.append("Patched source does not compile")
        elif validation.compile_succeeded is None:
            failures.append("compilation could not be established")
            risks.append("Compile verification unavailable or baseline build is inconclusive")
        if validation.vulnerability_re_detected:
            failures.append("the responsible agent still detects the vulnerability")
            risks.append("Original vulnerability may remain reachable")
        if validation.introduced_identifiers:
            failures.append(
                "the patch introduces identifiers absent from the original file: "
                + ", ".join(validation.introduced_identifiers)
            )
            risks.append("Patch may reference undefined identifiers")
        if failures:
            return "Patch was not verified because " + "; ".join(failures) + ".", risks
        return "Patched source parses, compiles, and is no longer detected by the responsible agent.", []
