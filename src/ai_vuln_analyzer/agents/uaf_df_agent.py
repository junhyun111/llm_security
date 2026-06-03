from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.core.schemas import AstAnalysis, CfgAnalysis, VulnerabilityFinding


class UafDfAgent(BaseAgent):
    agent_name = "uaf_df_agent"
    covered_cwes = ("CWE-416", "CWE-415")

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for item in ast:
            lines = Path(item.file).read_text(encoding="utf-8").splitlines()
            freed_vars: dict[str, int] = {}
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("free("):
                    var = stripped.removeprefix("free(").split(")")[0].strip("&* ")
                    freed_vars[var] = lineno
                for var, freed_line in freed_vars.items():
                    if lineno > freed_line and var and var in stripped and "free(" not in stripped:
                        cwe = "CWE-416"
                        vuln_type = "Use-After-Free"
                        if stripped.startswith("free(") and var in stripped:
                            cwe = "CWE-415"
                            vuln_type = "Double Free"
                        function = next((func for func in item.functions if func.line_start <= lineno <= func.line_end), None)
                        findings.append(
                            self._build_finding(
                                finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{freed_line}:{lineno}",
                                cwe=cwe,
                                vulnerability_type=vuln_type,
                                file=item.file,
                                function=function.name if function else None,
                                line_start=freed_line,
                                line_end=lineno,
                                source=var,
                                sink="free/use",
                                evidence=f"Pointer '{var}' is freed at line {freed_line} and referenced again at line {lineno}.",
                                confidence=0.86,
                            )
                        )
                        break
        return findings
