from __future__ import annotations


class LoopController:
    def __init__(self, max_rounds: int) -> None:
        self.max_rounds = max_rounds

    def should_stop(self, history: list[float], current_round: int) -> bool:
        if current_round >= self.max_rounds:
            return True
        if len(history) >= 2 and history[-1] == history[-2]:
            return True
        if len(history) >= 3 and max(history[-3:]) - min(history[-3:]) < 0.01:
            return True
        return False
