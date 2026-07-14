from __future__ import annotations

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.core.schemas import PlannerDecision


class Manager:
    def __init__(self, agents: list[BaseAgent]) -> None:
        self.agents = agents

    def select_agents(self, decision: PlannerDecision) -> list[BaseAgent]:
        selected = []
        remaining = []
        candidate_cwes = set(decision.candidate_cwes)
        for agent in self.agents:
            if candidate_cwes.intersection(agent.covered_cwes):
                selected.append(agent)
            else:
                remaining.append(agent)
        # Planner output prioritizes cheap deterministic agents; it does not gate recall.
        return selected + remaining
