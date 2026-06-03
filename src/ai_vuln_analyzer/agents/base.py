from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from ai_vuln_analyzer.core.schemas import AstAnalysis, CfgAnalysis, VulnerabilityFinding
from ai_vuln_analyzer.llm.base import LLMClient


class BaseAgent(ABC):
    agent_name = "base"
    covered_cwes: tuple[str, ...] = ()

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    @abstractmethod
    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        raise NotImplementedError

    def _build_finding(
        self,
        *,
        finding_id: str,
        cwe: str,
        vulnerability_type: str,
        file: str,
        function: str | None,
        line_start: int | None,
        line_end: int | None,
        source: str | None,
        sink: str | None,
        evidence: str,
        confidence: float,
    ) -> VulnerabilityFinding:
        from ai_vuln_analyzer.core.schemas import CodeLocation

        return VulnerabilityFinding(
            id=finding_id,
            cwe=cwe,
            vulnerability_type=vulnerability_type,
            location=CodeLocation(
                file=file,
                function=function,
                line_start=line_start,
                line_end=line_end,
            ),
            source=source,
            sink=sink,
            evidence=evidence,
            agent_name=self.agent_name,
            confidence=confidence,
        )

    def _parse_json(self, raw: str) -> dict:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find("{")
            end = raw.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(raw[start : end + 1])
                except json.JSONDecodeError:
                    return {}
            return {}

    def _file_name(self, file_path: str) -> str:
        return Path(file_path).name
