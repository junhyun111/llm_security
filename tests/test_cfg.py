from __future__ import annotations

from ai_vuln_analyzer.analysis.cfg_analyzer import CfgAnalyzer


def test_cfg_contains_branch_loop_and_return_edges(tmp_path):
    source = tmp_path / "flow.c"
    source.write_text(r'''
        int calculate(int limit) {
            int total = 0;
            for (int i = 0; i < limit; ++i) {
                if (i == 3) return total;
                total += i;
            }
            return total;
        }
    ''', encoding="utf-8")

    cfg = CfgAnalyzer().analyze(source)
    kinds = {edge.kind for edge in cfg.edges}

    assert {"branch", "loop", "return"} <= kinds
