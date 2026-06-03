from __future__ import annotations

import json

from ai_vuln_analyzer.core.schemas import VulnerabilityFinding
from ai_vuln_analyzer.llm.base import LLMClient
from ai_vuln_analyzer.llm.prompts import teacher_prompt


class Teacher:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def annotate(self, findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        enriched: list[VulnerabilityFinding] = []
        for finding in findings:
            system_prompt, user_prompt = teacher_prompt(finding.model_dump_json())
            raw = self.llm.complete(system_prompt, user_prompt)
            root_cause = None
            try:
                root_cause = json.loads(raw).get("root_cause")
            except json.JSONDecodeError:
                root_cause = raw.strip() or None
            enriched.append(finding.model_copy(update={"root_cause": root_cause}))
        return enriched
