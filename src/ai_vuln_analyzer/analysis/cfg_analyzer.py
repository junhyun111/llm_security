from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.core.schemas import CfgAnalysis, CfgEdge, CfgNode, SemanticEvent


class CfgAnalyzer:
    """Build a function-local CFG with branches, loop back-edges, calls, and returns."""

    def __init__(self, ast_analyzer: AstAnalyzer | None = None) -> None:
        self.ast_analyzer = ast_analyzer or AstAnalyzer()

    def analyze(self, file_path: str | Path) -> CfgAnalysis:
        path = Path(file_path)
        analysis = self.ast_analyzer.analyze(path)
        nodes: list[CfgNode] = []
        edges: list[CfgEdge] = []

        for function in analysis.functions:
            events = sorted(
                (event for event in analysis.events if event.function == function.name),
                key=self._event_order,
            )
            entry_id = f"{path.name}:{function.name}:entry"
            exit_id = f"{path.name}:{function.name}:exit"
            nodes.append(CfgNode(
                id=entry_id, label=f"entry {function.name}",
                line_start=function.line_start, line_end=function.line_start,
            ))
            event_nodes: list[tuple[SemanticEvent, str]] = []
            for index, event in enumerate(events):
                node_id = f"{path.name}:{function.name}:{event.line_start}:{index}"
                event_nodes.append((event, node_id))
                nodes.append(CfgNode(
                    id=node_id, label=f"{event.kind}: {event.text.strip()[:100]}",
                    line_start=event.line_start, line_end=event.line_end,
                ))
                if event.kind == "call" and event.callee:
                    edges.append(CfgEdge(source=node_id, target=f"call:{event.callee}", kind="call"))

            nodes.append(CfgNode(
                id=exit_id, label=f"exit {function.name}",
                line_start=function.line_end, line_end=function.line_end,
            ))
            if not event_nodes:
                edges.append(CfgEdge(source=entry_id, target=exit_id, kind="flow"))
                continue

            edges.append(CfgEdge(source=entry_id, target=event_nodes[0][1], kind="flow"))
            for index, (event, node_id) in enumerate(event_nodes):
                next_id = event_nodes[index + 1][1] if index + 1 < len(event_nodes) else exit_id
                if event.kind == "return":
                    edges.append(CfgEdge(source=node_id, target=exit_id, kind="return"))
                    continue
                if event.kind == "condition":
                    edges.append(CfgEdge(source=node_id, target=next_id, kind="branch"))
                    false_target = self._first_after_scope(event_nodes, index, event.scope_end_line) or exit_id
                    if false_target != next_id:
                        edges.append(CfgEdge(source=node_id, target=false_target, kind="branch"))
                    if event.control_kind in {"for", "while", "do"}:
                        loop_tail = self._last_in_scope(event_nodes, index, event.scope_end_line)
                        if loop_tail and loop_tail != node_id:
                            edges.append(CfgEdge(source=loop_tail, target=node_id, kind="loop"))
                    continue
                if index + 1 < len(event_nodes) and events[index + 1].kind == "condition":
                    edges.append(CfgEdge(source=node_id, target=next_id, kind="flow"))
                elif index + 1 < len(event_nodes) or next_id == exit_id:
                    edges.append(CfgEdge(source=node_id, target=next_id, kind="flow"))

        return CfgAnalysis(file=str(path), nodes=nodes, edges=self._deduplicate(edges))

    def _first_after_scope(
        self,
        event_nodes: list[tuple[SemanticEvent, str]],
        condition_index: int,
        scope_end_line: int | None,
    ) -> str | None:
        if scope_end_line is None:
            return None
        for event, node_id in event_nodes[condition_index + 1:]:
            if event.line_start > scope_end_line:
                return node_id
        return None

    def _last_in_scope(
        self,
        event_nodes: list[tuple[SemanticEvent, str]],
        condition_index: int,
        scope_end_line: int | None,
    ) -> str | None:
        if scope_end_line is None:
            return None
        result = None
        for event, node_id in event_nodes[condition_index + 1:]:
            if event.line_start > scope_end_line:
                break
            result = node_id
        return result

    def _event_order(self, event: SemanticEvent) -> tuple[int, int, int]:
        priority = 0 if event.kind == "condition" else 1
        return event.line_start, priority, event.line_end

    def _deduplicate(self, edges: list[CfgEdge]) -> list[CfgEdge]:
        unique = {}
        for edge in edges:
            unique[(edge.source, edge.target, edge.kind)] = edge
        return list(unique.values())
