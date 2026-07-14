from __future__ import annotations

from ai_vuln_analyzer.core.schemas import AstAnalysis, PlannerDecision
from ai_vuln_analyzer.llm.base import LLMClient
from ai_vuln_analyzer.llm.prompts import planner_prompt


class Planner:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def plan(self, ast_results: list[AstAnalysis]) -> PlannerDecision:
        summary = []
        cwes: set[str] = set()
        for item in ast_results:
            summary.append(f"{item.file}: {len(item.functions)} functions, {len(item.dangerous_calls)} dangerous calls")
            for call in item.dangerous_calls:
                cwes.update(call["cwes"])
        system_prompt, user_prompt = planner_prompt("\n".join(summary))
        raw = self.llm.complete(system_prompt, user_prompt)
        parsed = {"candidate_cwes": sorted(cwes), "rationale": "Static pre-scan selected candidate CWE families."}
        if raw:
            from json import loads, JSONDecodeError

            try:
                llm_data = loads(raw)
                llm_cwes = llm_data.pop("candidate_cwes", [])
                parsed.update({k: v for k, v in llm_data.items() if k in parsed})
                parsed["candidate_cwes"] = sorted(cwes | set(llm_cwes))
            except JSONDecodeError:
                pass
        return PlannerDecision(
            candidate_cwes=sorted(set(parsed["candidate_cwes"])),
            rationale=parsed["rationale"],
            related_files=[item.file for item in ast_results],
        )
