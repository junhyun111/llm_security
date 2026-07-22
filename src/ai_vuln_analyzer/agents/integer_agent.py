from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.core.schemas import AstAnalysis, CfgAnalysis, VulnerabilityFinding


class IntegerAgent(BaseAgent):
    agent_name = "integer_agent"
    covered_cwes = ("CWE-190", "CWE-191")

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for item in ast:
            lines = Path(item.file).read_text(encoding="utf-8").splitlines()
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if "*" in stripped and ("malloc(" in stripped or "calloc(" in stripped or "memcpy(" in stripped):
                    function = next((func for func in item.functions if func.line_start <= lineno <= func.line_end), None)
                    findings.append(
                        self._build_finding(
                            finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{lineno}",
                            cwe="CWE-190",
                            vulnerability_type="Integer Overflow / Size Calculation Error",
                            file=item.file,
                            function=function.name if function else None,
                            line_start=lineno,
                            line_end=lineno,
                            source="size/count arithmetic",
                            sink="allocation or copy length",
                            evidence=f"Potential unchecked multiplication in memory-related expression: {stripped}",
                            confidence=0.8,
                        )
                    )
        return findings
