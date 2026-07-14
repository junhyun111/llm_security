from __future__ import annotations

import ast as python_ast

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.analysis.semantic_flow import base_identifier
from ai_vuln_analyzer.core.schemas import AstAnalysis, CfgAnalysis, VulnerabilityFinding


class BofOobAgent(BaseAgent):
    agent_name = "bof_oob_agent"
    covered_cwes = ("CWE-120", "CWE-121", "CWE-122", "CWE-787")

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        unsafe_apis = {"strcpy", "strcat", "sprintf"}
        bounded_apis = {"memcpy", "memmove", "strncpy", "strncat", "snprintf"}
        for item in ast:
            functions = {function.name: function for function in item.functions}
            for event in item.events:
                if event.kind != "call" or not event.callee:
                    continue
                api = event.callee.split("::")[-1]
                if api not in unsafe_apis | bounded_apis:
                    continue
                function = functions.get(event.function or "")
                destination = base_identifier(event.arguments[0]) if event.arguments else None
                fixed_destination = bool(function and destination in function.array_sizes)
                source_is_tainted = any(index > 0 for index in event.tainted_arguments)
                if api == "strcpy" and fixed_destination and self._literal_fits(function.array_sizes[destination], event.arguments):
                    continue
                suspicious_length = api in bounded_apis and self._has_suspicious_length(api, event.arguments, event.tainted_arguments)
                if api in bounded_apis and not suspicious_length:
                    continue
                if api in unsafe_apis and not (fixed_destination or source_is_tainted):
                    continue
                cwe = "CWE-121" if fixed_destination else "CWE-787"
                reason = "a fixed-size destination" if fixed_destination else "tainted input or length"
                findings.append(self._build_finding(
                    finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{event.line_start}",
                    cwe=cwe,
                    vulnerability_type="Buffer Overflow / Out-of-Bounds",
                    file=item.file,
                    function=event.function,
                    line_start=event.line_start,
                    line_end=event.line_end,
                    source=", ".join(event.taint_sources) or "copy source/length",
                    sink=api,
                    evidence=f"{api} writes to {reason} without a proven bound: {event.text.strip()}",
                    confidence=0.9 if fixed_destination and source_is_tainted else 0.82,
                ))
        return findings

    def _has_suspicious_length(self, api: str, arguments: list[str], tainted: list[int]) -> bool:
        length_index = {"strncpy": 2, "strncat": 2, "memcpy": 2, "memmove": 2, "snprintf": 1}[api]
        if length_index >= len(arguments):
            return True
        length = arguments[length_index]
        if length_index in tainted:
            return True
        return "*" in length and "SIZE_MAX" not in length

    def _literal_fits(self, capacity: str, arguments: list[str]) -> bool:
        if len(arguments) < 2 or not capacity.isdigit():
            return False
        try:
            value = python_ast.literal_eval(arguments[1])
        except (SyntaxError, ValueError):
            return False
        return isinstance(value, str) and len(value.encode("utf-8")) < int(capacity)
