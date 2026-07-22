from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.core.schemas import CfgAnalysis, CfgEdge, CfgNode


class CfgAnalyzer:
    """Build a lightweight, function-local CFG from parsed semantic events."""

    def __init__(self, ast_analyzer: AstAnalyzer | None = None) -> None:
        self.ast_analyzer = ast_analyzer or AstAnalyzer()

    def analyze(self, file_path: str | Path) -> CfgAnalysis:
        path = Path(file_path)
        analysis = self.ast_analyzer.analyze(path)
        nodes: list[CfgNode] = []
        edges: list[CfgEdge] = []

        functions = {function.name: function for function in analysis.functions}
        for function_name, function in functions.items():
            function_events = sorted(
                (event for event in analysis.events if event.function == function_name),
                key=lambda event: (event.line_start, event.line_end, event.kind),
            )
            entry_id = f"{path.name}:{function_name}:entry"
            nodes.append(CfgNode(
                id=entry_id,
                label=f"entry {function_name}",
                line_start=function.line_start,
                line_end=function.line_start,
            ))
            previous_id = entry_id
            for index, event in enumerate(function_events):
                node_id = f"{path.name}:{function_name}:{event.line_start}:{index}"
                nodes.append(CfgNode(
                    id=node_id,
                    label=f"{event.kind}: {event.text.strip()[:100]}",
                    line_start=event.line_start,
                    line_end=event.line_end,
                ))
                edges.append(CfgEdge(
                    source=previous_id,
                    target=node_id,
                    kind="branch" if event.kind == "condition" else "flow",
                ))
                if event.kind == "call" and event.callee:
                    edges.append(CfgEdge(source=node_id, target=f"call:{event.callee}", kind="call"))
                previous_id = node_id

            exit_id = f"{path.name}:{function_name}:exit"
            nodes.append(CfgNode(
                id=exit_id,
                label=f"exit {function_name}",
                line_start=function.line_end,
                line_end=function.line_end,
            ))
            edges.append(CfgEdge(source=previous_id, target=exit_id, kind="flow"))
        return CfgAnalysis(file=str(path), nodes=nodes, edges=edges)
