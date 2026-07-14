from __future__ import annotations

import re

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.analysis.semantic_flow import base_identifier
from ai_vuln_analyzer.core.schemas import AstAnalysis, CfgAnalysis, SemanticEvent, VulnerabilityFinding


class UafDfAgent(BaseAgent):
    agent_name = "uaf_df_agent"
    covered_cwes = ("CWE-416", "CWE-415")

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for item in ast:
            for function in item.functions:
                events = [event for event in item.events if event.function == function.name]
                findings.extend(self._analyze_function(item, sorted(events, key=self._event_order)))
        return findings

    def _analyze_function(self, item: AstAnalysis, events: list[SemanticEvent]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        freed: dict[str, int] = {}
        aliases: dict[str, set[str]] = {}
        reported_uses: set[tuple[str, int]] = set()

        for event in events:
            api = (event.callee or "").split("::")[-1]
            if event.kind in {"assignment", "declaration"} and event.target:
                target = event.target.strip("*&() ")
                if re.fullmatch(r"[A-Za-z_]\w*", target):
                    self._detach_alias(target, aliases)
                    freed.pop(target, None)
                    rhs = event.text.split("=", 1)[-1].rstrip("; ") if "=" in event.text else ""
                    rhs_pointer = rhs.strip("*&() ")
                    if re.fullmatch(r"[A-Za-z_]\w*", rhs_pointer):
                        self._join_aliases(target, rhs_pointer, aliases)

            if event.kind == "call" and api == "free" and event.arguments:
                pointer = base_identifier(event.arguments[0])
                if not pointer:
                    continue
                alias_group = aliases.get(pointer, {pointer})
                previous_free = next((freed[name] for name in alias_group if name in freed), None)
                if previous_free is not None:
                    findings.append(self._finding(
                        item, event, pointer, previous_free, "CWE-415", "Double Free", "free",
                    ))
                else:
                    for name in alias_group:
                        freed[name] = event.line_start
                continue

            for pointer, free_line in freed.items():
                if not self._dereferences(event, pointer) or (pointer, event.line_start) in reported_uses:
                    continue
                reported_uses.add((pointer, event.line_start))
                findings.append(self._finding(
                    item, event, pointer, free_line, "CWE-416", "Use-After-Free", api or event.kind,
                ))
        return findings

    def _join_aliases(self, left: str, right: str, aliases: dict[str, set[str]]) -> None:
        group = set(aliases.get(left, {left})) | set(aliases.get(right, {right}))
        for name in group:
            aliases[name] = group

    def _detach_alias(self, name: str, aliases: dict[str, set[str]]) -> None:
        group = aliases.pop(name, None)
        if not group:
            return
        remaining = set(group) - {name}
        for alias in remaining:
            aliases[alias] = remaining

    def _dereferences(self, event: SemanticEvent, pointer: str) -> bool:
        if pointer not in event.identifiers:
            return False
        if event.kind == "call":
            return any(pointer in argument for argument in event.arguments)
        if event.kind == "assignment":
            target = event.target or ""
            rhs = event.text.split("=", 1)[-1]
            return pointer in rhs or pointer in target and any(token in target for token in {"[", "->", "*"})
        if event.kind == "return":
            return pointer in event.text
        return False

    def _finding(
        self,
        item: AstAnalysis,
        event: SemanticEvent,
        pointer: str,
        free_line: int,
        cwe: str,
        vulnerability_type: str,
        sink: str,
    ) -> VulnerabilityFinding:
        return self._build_finding(
            finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{free_line}:{event.line_start}:{cwe}",
            cwe=cwe, vulnerability_type=vulnerability_type, file=item.file,
            function=event.function, line_start=free_line, line_end=event.line_end,
            source=pointer, sink=sink,
            evidence=f"Pointer '{pointer}' is freed at line {free_line} and used by '{event.text.strip()}' at line {event.line_start}.",
            confidence=0.92,
        )

    def _event_order(self, event: SemanticEvent) -> tuple[int, int, int]:
        priority = 0 if event.kind in {"assignment", "declaration"} else 1
        return event.line_start, event.line_end, priority
