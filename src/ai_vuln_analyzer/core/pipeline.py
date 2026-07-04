from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.agents.bof_oob_agent import BofOobAgent
from ai_vuln_analyzer.agents.integer_agent import IntegerAgent
from ai_vuln_analyzer.agents.manager import Manager
from ai_vuln_analyzer.agents.null_uninit_agent import NullUninitAgent
from ai_vuln_analyzer.agents.planner import Planner
from ai_vuln_analyzer.agents.student import Student
from ai_vuln_analyzer.agents.teacher import Teacher
from ai_vuln_analyzer.agents.uaf_df_agent import UafDfAgent
from ai_vuln_analyzer.agents.verifier import Verifier
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.analysis.cfg_analyzer import CfgAnalyzer
from ai_vuln_analyzer.analysis.file_collector import collect_cpp_files
from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.report import build_summary
from ai_vuln_analyzer.core.schemas import FinalReport, PipelineArtifacts, VulnerabilityFinding
from ai_vuln_analyzer.llm.anthropic_client import AnthropicClient
from ai_vuln_analyzer.llm.base import LLMClient
from ai_vuln_analyzer.llm.mock_client import MockLLMClient
from ai_vuln_analyzer.llm.openai_client import OpenAIClient
from ai_vuln_analyzer.verifier.loop_controller import LoopController


def build_llm_client(settings: Settings) -> LLMClient:
    provider = settings.provider_normalized
    if provider == "openai":
        if not settings.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is required for provider=openai")
        return OpenAIClient(settings.openai_api_key, model=settings.openai_model)
    if provider == "openrouter":
        if not settings.openrouter_api_key:
            raise RuntimeError("OPENROUTER_API_KEY is required for provider=openrouter")
        headers = {}
        if settings.openrouter_site_url:
            headers["HTTP-Referer"] = settings.openrouter_site_url
        if settings.openrouter_app_name:
            headers["X-Title"] = settings.openrouter_app_name
        return OpenAIClient(
            settings.openrouter_api_key,
            model=settings.openrouter_model,
            base_url=settings.openrouter_base_url,
            default_headers=headers,
        )
    if provider == "anthropic":
        if not settings.anthropic_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is required for provider=anthropic")
        return AnthropicClient(settings.anthropic_api_key, model=settings.anthropic_model)
    return MockLLMClient()


class VulnerabilityPipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.llm = build_llm_client(settings)
        self.ast_analyzer = AstAnalyzer()
        self.cfg_analyzer = CfgAnalyzer()
        self.planner = Planner(self.llm)
        self.agents = [
            BofOobAgent(self.llm),
            UafDfAgent(self.llm),
            IntegerAgent(self.llm),
            NullUninitAgent(self.llm),
        ]
        self.manager = Manager(self.agents)
        self.teacher = Teacher(self.llm)
        self.student = Student(self.llm)
        self.verifier = Verifier(self.agents, settings.confidence_threshold, self.ast_analyzer, self.cfg_analyzer)
        self.loop_controller = LoopController(settings.max_rounds)

    def run(self, target_path: str | Path) -> FinalReport:
        files = collect_cpp_files(target_path)
        ast_results = [self.ast_analyzer.analyze(file) for file in files]
        cfg_results = [self.cfg_analyzer.analyze(file) for file in files]
        planner_decision = self.planner.plan(ast_results)
        selected_agents = self.manager.select_agents(planner_decision)
        findings = self._merge_findings(agent.run(ast_results, cfg_results) for agent in selected_agents)
        findings = self.teacher.annotate(findings)
        patches = self.student.generate_patches(findings)
        history: list[float] = []
        round_no = 1
        verifications = self.verifier.verify(findings, patches)
        while True:
            avg_confidence = sum(item.confidence for item in verifications) / max(len(verifications), 1)
            history.append(avg_confidence)
            all_verified = all(item.verified for item in verifications) if verifications else True
            if all_verified or self.loop_controller.should_stop(history, round_no):
                break
            round_no += 1
            break
        verification_map = {item.finding_id: item for item in verifications}
        updated_findings = []
        for finding in findings:
            verification = verification_map.get(finding.id)
            if verification and verification.verified:
                status = "verified"
            elif verification and round_no >= self.settings.max_rounds:
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
