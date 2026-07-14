from __future__ import annotations

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.core.schemas import AstAnalysis, CfgAnalysis, SemanticEvent, VulnerabilityFinding


class IntegerAgent(BaseAgent):
    agent_name = "integer_agent"
    covered_cwes = ("CWE-190", "CWE-191")
    SIZE_INDEX = {"malloc": 0, "realloc": 1, "memcpy": 2, "memmove": 2}

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for item in ast:
            for event in item.events:
                if event.kind != "call" or not event.callee:
                    continue
                api = event.callee.split("::")[-1]
                expression = self._size_expression(api, event)
                if expression is None or not self._unchecked_size(item, event, expression):
                    continue
                findings.append(self._build_finding(
                    finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{event.line_start}",
                    cwe="CWE-190", vulnerability_type="Integer Overflow / Size Calculation Error",
                    file=item.file, function=event.function,
                    line_start=event.line_start, line_end=event.line_end,
                    source=expression, sink=api,
                    evidence=f"Unchecked size arithmetic '{expression}' reaches {api}: {event.text.strip()}",
                    confidence=0.86 if event.tainted_arguments else 0.78,
                ))
        return findings

    def _size_expression(self, api: str, event: SemanticEvent) -> str | None:
        if api == "calloc" and len(event.arguments) >= 2:
            return f"({event.arguments[0]}) * ({event.arguments[1]})"
        index = self.SIZE_INDEX.get(api)
        if index is None or index >= len(event.arguments):
            return None
        expression = event.arguments[index]
        return expression if "*" in expression else None

    def _unchecked_size(self, item: AstAnalysis, event: SemanticEvent, expression: str) -> bool:
        prior_conditions = [
            candidate.text
            for candidate in item.events
            if candidate.function == event.function
            and candidate.kind == "condition"
            and candidate.line_start <= event.line_start
        ]
        guarded = any(
            "SIZE_MAX" in condition and ("/" in condition or expression in condition)
            for condition in prior_conditions
        )
        return not guarded
