from __future__ import annotations

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.core.schemas import AstAnalysis, CfgAnalysis, VulnerabilityFinding


class BofOobAgent(BaseAgent):
    agent_name = "bof_oob_agent"
    covered_cwes = ("CWE-121", "CWE-122", "CWE-787")

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for item in ast:
            for call in item.dangerous_calls:
                if call["api"] in {"strcpy", "strncpy", "memcpy", "memmove", "sprintf", "snprintf"}:
                    function = next(
                        (
                            func
                            for func in item.functions
                            if func.line_start <= call["line"] <= func.line_end
                        ),
                        None,
                    )
                    cwe = "CWE-787" if call["api"] in {"memcpy", "memmove", "strncpy", "snprintf"} else "CWE-121"
                    findings.append(
                        self._build_finding(
                            finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{call['line']}",
                            cwe=cwe,
                            vulnerability_type="Buffer Overflow / Out-of-Bounds",
                            file=item.file,
                            function=function.name if function else None,
                            line_start=call["line"],
                            line_end=call["line"],
                            source="external input or computed length",
                            sink=call["api"],
                            evidence=f"{call['api']} is used without visible destination bounds validation: {call['content']}",
                            confidence=0.84,
                        )
                    )
        return findings
