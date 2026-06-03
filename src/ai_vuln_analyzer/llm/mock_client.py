from __future__ import annotations

import json

from ai_vuln_analyzer.llm.base import LLMClient


class MockLLMClient(LLMClient):
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        lower = f"{system_prompt}\n{user_prompt}".lower()
        if "planner" in lower or "prioritizes" in lower:
            return json.dumps(
                {
                    "candidate_cwes": [
                        "CWE-121",
                        "CWE-787",
                        "CWE-416",
                        "CWE-415",
                        "CWE-190",
                        "CWE-191",
                        "CWE-476",
                        "CWE-457",
                    ],
                    "rationale": "Dangerous memory APIs, allocation patterns, and pointer usage were detected.",
                }
            )
        if "root cause" in lower:
            return json.dumps(
                {
                    "root_cause": "The code uses unsafe memory or pointer operations without validating size, lifetime, or nullability assumptions."
                }
            )
        if "safer c/c++ patch" in lower:
            return json.dumps(
                {
                    "explanation": "Introduce bounds or null checks and replace unsafe operations with guarded variants.",
                    "confidence": 0.81,
                }
            )
        return json.dumps({"confidence": 0.75})
