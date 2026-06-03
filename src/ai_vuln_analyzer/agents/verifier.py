from __future__ import annotations

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.analysis.cfg_analyzer import CfgAnalyzer
from ai_vuln_analyzer.core.schemas import PatchSuggestion, VerificationResult, VulnerabilityFinding
from ai_vuln_analyzer.verifier.confidence import calculate_confidence
from ai_vuln_analyzer.verifier.patch_checker import PatchChecker


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
        self.cfg_analyzer = cfg_analyzer or CfgAnalyzer()
        self.patch_checker = PatchChecker()

    def verify(
        self,
        findings: list[VulnerabilityFinding],
        patches: list[PatchSuggestion],
    ) -> list[VerificationResult]:
        patch_map = {patch.finding_id: patch for patch in patches}
        results: list[VerificationResult] = []
        for finding in findings:
            patch = patch_map[finding.id]
            rerun_agents = [agent.agent_name for agent in self.agents if finding.cwe in agent.covered_cwes]
            agent_rerun_score = self._agent_rerun_score(finding, patch)
            ast_patch_score = self.patch_checker.ast_patch_score(finding, patch)
            rule_based_score = self.patch_checker.rule_based_score(finding, patch)
            confidence = calculate_confidence(
                agent_rerun_score=agent_rerun_score,
                ast_patch_score=ast_patch_score,
                rule_based_score=rule_based_score,
                llm_confidence=patch.confidence,
            )
            verified = confidence >= self.confidence_threshold
            reason = (
                "Patch introduces expected guard patterns and lowers re-detection risk."
                if verified
                else "Patch signal is insufficient; vulnerable pattern may still be reachable."
            )
            remaining_risks = [] if verified else ["Manual review recommended", "Re-run planner with failure rationale"]
            results.append(
                VerificationResult(
                    finding_id=finding.id,
                    verified=verified,
                    confidence=confidence,
                    reason=reason,
                    rerun_agents=rerun_agents,
                    remaining_risks=remaining_risks,
                )
            )
        return results

    def _agent_rerun_score(self, finding: VulnerabilityFinding, patch: PatchSuggestion) -> float:
        text = patch.patched_code
        if finding.sink == "strcpy" and "strcpy(" not in text and "strncpy(" in text:
            return 0.92
        if finding.sink == "memcpy" and "SIZE_MAX" in text:
            return 0.9
        if finding.cwe == "CWE-416" and "removed unsafe use" in text:
            return 0.82
        if finding.cwe == "CWE-416" and "p = NULL" in text and "if (p != NULL)" in text:
            return 0.84
        if finding.cwe == "CWE-476" and "== NULL" in text:
            return 0.88
        return 0.35
