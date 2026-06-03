from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.core.schemas import AstAnalysis, CfgAnalysis, VulnerabilityFinding


class NullUninitAgent(BaseAgent):
    agent_name = "null_uninit_agent"
    covered_cwes = ("CWE-476", "CWE-457")

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for item in ast:
            lines = Path(item.file).read_text(encoding="utf-8").splitlines()
            alloc_vars: dict[str, int] = {}
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if "malloc(" in stripped and "=" in stripped:
                    var = stripped.split("=")[0].split()[-1].strip("*")
                    alloc_vars[var] = lineno
                for var, alloc_line in alloc_vars.items():
                    if lineno > alloc_line and var and f"{var}," in stripped and "strcpy(" in stripped:
                        function = next((func for func in item.functions if func.line_start <= lineno <= func.line_end), None)
                        findings.append(
                            self._build_finding(
                                finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{alloc_line}:{lineno}",
                                cwe="CWE-476",
                                vulnerability_type="NULL Pointer Dereference",
                                file=item.file,
                                function=function.name if function else None,
                                line_start=alloc_line,
                                line_end=lineno,
                                source=var,
                                sink="dereference/copy",
                                evidence=f"Allocated pointer '{var}' is dereferenced without an explicit null check before use.",
                                confidence=0.79,
                            )
                        )
                        break
        return findings
