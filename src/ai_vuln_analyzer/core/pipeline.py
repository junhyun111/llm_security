from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.agents.bof_oob_agent import BofOobAgent
from ai_vuln_analyzer.agents.integer_agent import IntegerAgent
from ai_vuln_analyzer.agents.manager import Manager
from ai_vuln_analyzer.agents.null_uninit_agent import NullUninitAgent
from ai_vuln_analyzer.agents.planner import Planner
from ai_vuln_analyzer.agents.student import Student
from ai_vuln_analyzer.agents.semantic_agents import (
    CommandInjectionAgent,
    FormatStringAgent,
    OffByOneAgent,
    PathTraversalAgent,
    UnsafeInputAgent,
    WeakRandomAgent,
)
from ai_vuln_analyzer.agents.teacher import Teacher
from ai_vuln_analyzer.agents.uaf_df_agent import UafDfAgent
from ai_vuln_analyzer.agents.verifier import Verifier
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.analysis.cfg_analyzer import CfgAnalyzer
from ai_vuln_analyzer.analysis.file_collector import collect_cpp_files
from ai_vuln_analyzer.analysis.program_flow import link_program_taint
from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.report import build_summary
from ai_vuln_analyzer.core.schemas import AnalysisFailure, FinalReport, PipelineArtifacts, VulnerabilityFinding
from ai_vuln_analyzer.llm.anthropic_client import AnthropicClient
from ai_vuln_analyzer.llm.base import LLMClient
from ai_vuln_analyzer.llm.mock_client import MockLLMClient
from ai_vuln_analyzer.llm.openai_client import OpenAIClient
from ai_vuln_analyzer.llm.resilient_client import ResilientLLMClient


def build_llm_client(settings: Settings) -> LLMClient:
    provider = settings.provider_normalized
    if provider == "openai":
        if not settings.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is required for provider=openai")
        client = OpenAIClient(settings.openai_api_key, model=settings.openai_model)
        return ResilientLLMClient(client, settings.llm_max_retries, settings.llm_retry_base_seconds)
    if provider == "openrouter":
        if not settings.openrouter_api_key:
            raise RuntimeError("OPENROUTER_API_KEY is required for provider=openrouter")
        headers = {}
        if settings.openrouter_site_url:
            headers["HTTP-Referer"] = settings.openrouter_site_url
        if settings.openrouter_app_name:
            headers["X-Title"] = settings.openrouter_app_name
        client = OpenAIClient(
            settings.openrouter_api_key,
            model=settings.openrouter_model,
            base_url=settings.openrouter_base_url,
            default_headers=headers,
        )
        return ResilientLLMClient(client, settings.llm_max_retries, settings.llm_retry_base_seconds)
    if provider == "anthropic":
        if not settings.anthropic_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is required for provider=anthropic")
        client = AnthropicClient(settings.anthropic_api_key, model=settings.anthropic_model)
        return ResilientLLMClient(client, settings.llm_max_retries, settings.llm_retry_base_seconds)
    return MockLLMClient()


class VulnerabilityPipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.llm = build_llm_client(settings)
        self.ast_analyzer = AstAnalyzer()
        self.cfg_analyzer = CfgAnalyzer(self.ast_analyzer)
        self.planner = Planner(self.llm)
        self.agents = [
            BofOobAgent(self.llm),
            UafDfAgent(self.llm),
            IntegerAgent(self.llm),
            NullUninitAgent(self.llm),
            CommandInjectionAgent(self.llm),
            FormatStringAgent(self.llm),
            PathTraversalAgent(self.llm),
            UnsafeInputAgent(self.llm),
            WeakRandomAgent(self.llm),
            OffByOneAgent(self.llm),
        ]
        self.manager = Manager(self.agents)
        self.teacher = Teacher(self.llm)
        self.student = Student(self.llm)
        self.verifier = Verifier(self.agents, settings.confidence_threshold, self.ast_analyzer, self.cfg_analyzer)

    def run(self, target_path: str | Path) -> FinalReport:
        files = collect_cpp_files(target_path)
        raw_ast = []
        cfg_results = []
        analyzed_files = []
        failures: list[AnalysisFailure] = []
        for file in files:
            try:
                ast_result = self.ast_analyzer.analyze(file)
                raw_ast.append(ast_result)
                analyzed_files.append(file)
                if ast_result.parse_errors:
                    failures.append(AnalysisFailure(
                        file=str(file), stage="ast",
                        error=f"tree-sitter reported {ast_result.parse_errors} parse error node(s)",
                    ))
            except Exception as exc:
                failures.append(AnalysisFailure(
                    file=str(file), stage="ast", error=str(exc).strip() or exc.__class__.__name__,
                ))
                continue
            try:
                cfg_results.append(self.cfg_analyzer.analyze(file))
            except Exception as exc:
                failures.append(AnalysisFailure(
                    file=str(file), stage="cfg", error=str(exc).strip() or exc.__class__.__name__,
                ))
        ast_results = link_program_taint(raw_ast)
        planner_decision = self.planner.plan(ast_results)
        llm_error = getattr(self.llm, "last_error", None)
        selected_agents = self.manager.select_agents(planner_decision)
        findings = self._merge_findings(agent.run(ast_results, cfg_results) for agent in selected_agents)
        findings = self._classify_relationships(findings)
        findings = self.teacher.annotate(findings)
        patches = self.student.generate_patches(findings)
        round_no = 1
        verifications = self.verifier.verify(findings, patches, project_files=analyzed_files)
        integrated_verification = self.verifier.verify_integrated(findings, patches, analyzed_files)
        verification_map = {item.finding_id: item for item in verifications}
        updated_findings = []
        for finding in findings:
            verification = verification_map.get(finding.id)
            if verification and verification.verified:
                status = "verified"
            elif (
                verification
                and verification.parse_succeeded is True
                and verification.compile_succeeded is None
                and verification.vulnerability_re_detected is False
            ):
                status = "unresolved"
            elif verification:
                status = "rejected"
            else:
                status = finding.status
            updated_findings.append(finding.model_copy(update={"status": status}))
        artifacts = PipelineArtifacts(
            analyzed_files=[str(file) for file in files],
            planner_decision=planner_decision,
            findings=updated_findings,
            patches=patches,
            verifications=verifications,
            integrated_verification=integrated_verification,
            analysis_failures=failures,
            llm_warning=(
                f"LLM provider failed after retries; static analysis continued without LLM output: {llm_error}"
                if llm_error else None
            ),
            rounds=round_no,
        )
        report = FinalReport(summary={}, artifacts=artifacts)
        report.summary = build_summary(report)
        return report

    def _merge_findings(self, finding_groups) -> list[VulnerabilityFinding]:
        merged: dict[tuple[str, str, int | None, str], VulnerabilityFinding] = {}
        for group in finding_groups:
            for finding in group:
                key = (
                    finding.location.file,
                    finding.cwe,
                    finding.location.line_start,
                    finding.vulnerability_type,
                )
                existing = merged.get(key)
                if not existing or finding.confidence > existing.confidence:
                    merged[key] = finding
        return list(merged.values())

    def _classify_relationships(
        self, findings: list[VulnerabilityFinding]
    ) -> list[VulnerabilityFinding]:
        primary_cwes = {"CWE-22", "CWE-78", "CWE-134", "CWE-242"}
        memory_cwes = {"CWE-120", "CWE-121", "CWE-122", "CWE-787"}
        updated = list(findings)
        for index, finding in enumerate(updated):
            if finding.cwe not in memory_cwes:
                continue
            source_tokens = {token for token in (finding.source or "").split(", ") if token}
            related = next((
                candidate
                for candidate in updated
                if candidate.id != finding.id
                and candidate.cwe in primary_cwes
                and candidate.location.file == finding.location.file
                and candidate.location.function == finding.location.function
                and (
                    bool(source_tokens & {
                        token for token in (candidate.source or "").split(", ") if token
                    })
                    or candidate.location.line_start == finding.location.line_start
                )
            ), None)
            if related:
                updated[index] = finding.model_copy(update={
                    "finding_role": "secondary",
                    "related_finding_id": related.id,
                })
        return updated
