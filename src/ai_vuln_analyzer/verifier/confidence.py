from __future__ import annotations


def calculate_confidence(
    *,
    agent_rerun_score: float,
    ast_patch_score: float,
    rule_based_score: float,
    llm_confidence: float,
) -> float:
    score = (
        0.35 * agent_rerun_score
        + 0.25 * ast_patch_score
        + 0.20 * rule_based_score
        + 0.20 * llm_confidence
    )
    return round(max(0.0, min(1.0, score)), 4)
