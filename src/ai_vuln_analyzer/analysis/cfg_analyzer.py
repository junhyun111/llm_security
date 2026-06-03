from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.core.schemas import CfgAnalysis, CfgEdge, CfgNode


class CfgAnalyzer:
    def analyze(self, file_path: str | Path) -> CfgAnalysis:
        path = Path(file_path)
        lines = path.read_text(encoding="utf-8").splitlines()
        nodes: list[CfgNode] = []
        edges: list[CfgEdge] = []
        last_id: str | None = None
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            node_id = f"{path.name}:{lineno}"
            label = stripped[:80]
            nodes.append(CfgNode(id=node_id, label=label, line_start=lineno, line_end=lineno))
            if last_id:
                edge_kind = "branch" if stripped.startswith(("if", "for", "while", "switch")) else "flow"
                edges.append(CfgEdge(source=last_id, target=node_id, kind=edge_kind))
            last_id = node_id
        return CfgAnalysis(file=str(path), nodes=nodes, edges=edges)
