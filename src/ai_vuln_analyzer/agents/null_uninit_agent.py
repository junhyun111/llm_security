from __future__ import annotations

import re

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.analysis.semantic_flow import base_identifier
from ai_vuln_analyzer.core.schemas import AstAnalysis, CfgAnalysis, SemanticEvent, VulnerabilityFinding


class NullUninitAgent(BaseAgent):
    agent_name = "null_uninit_agent"
    covered_cwes = ("CWE-476", "CWE-457")

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for item in ast:
            for function in item.functions:
                events = sorted(
                    (event for event in item.events if event.function == function.name),
                    key=lambda event: (event.line_start, event.line_end, event.kind),
                )
                findings.extend(self._analyze_function(item, events))
        return findings

    def _analyze_function(
        self, item: AstAnalysis, events: list[SemanticEvent]
    ) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        allocations: dict[str, int] = {}
        reported: set[str] = set()

        for event in events:
            api = (event.callee or "").split("::")[-1]
            if event.kind == "call" and api in {"malloc", "calloc", "realloc"} and event.target:
                pointer = base_identifier(event.target)
                if pointer:
                    allocations[pointer] = event.line_start
                continue
            if event.kind == "condition":
                continue
            for pointer, allocation_line in allocations.items():
                if (
                    pointer in reported
                    or not self._dereferences(event, pointer)
                    or self._is_protected(events, event, pointer)
                ):
                    continue
                reported.add(pointer)
                findings.append(self._build_finding(
                    finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{allocation_line}:{event.line_start}",
                    cwe="CWE-476", vulnerability_type="NULL Pointer Dereference",
                    file=item.file, function=event.function,
                    line_start=allocation_line, line_end=event.line_end,
                    source=pointer, sink=api or event.kind,
                    evidence=f"Allocation result '{pointer}' is used at line {event.line_start} without a dominating null check.",
                    confidence=0.84,
                ))
        return findings

    def _is_protected(
        self, events: list[SemanticEvent], use: SemanticEvent, pointer: str
    ) -> bool:
        for condition in events:
            if condition.kind != "condition" or condition.line_start > use.line_start:
                continue
            compact = re.sub(r"\s+", "", condition.text).strip("()")
            scope_end = condition.scope_end_line or condition.line_end
            positive = any(pattern in compact for pattern in {
                f"{pointer}!=NULL", f"NULL!={pointer}",
                f"{pointer}!=nullptr", f"nullptr!={pointer}",
            }) or compact == pointer
            if positive and condition.line_start <= use.line_start <= scope_end:
                return True

            negative = any(pattern in compact for pattern in {
                f"!{pointer}", f"{pointer}==NULL", f"NULL=={pointer}",
                f"{pointer}==nullptr", f"nullptr=={pointer}",
            })
            exits_on_null = any(
                event.kind == "return"
                and condition.line_start <= event.line_start <= scope_end
                for event in events
            )
            if negative and exits_on_null and scope_end < use.line_start:
                return True
        return False

    def _dereferences(self, event: SemanticEvent, pointer: str) -> bool:
        if pointer not in event.identifiers:
            return False
        if event.kind == "call":
            api = (event.callee or "").split("::")[-1]
            if api in {"free", "realloc"}:
                return False
            return any(pointer in argument for argument in event.arguments)
        if event.kind in {"assignment", "return"}:
            return bool(re.search(rf"(?:\*\s*{re.escape(pointer)}\b|\b{re.escape(pointer)}\s*(?:\[|->))", event.text))
        return False
