from __future__ import annotations

from ai_vuln_analyzer.core.schemas import VulnerabilityFinding
from ai_vuln_analyzer.llm.base import LLMClient


class Teacher:
    """Produces stable root-cause text from verified static-analysis evidence."""

    ROOT_CAUSES = {
        "CWE-22": "An externally influenced path reaches a file-system operation without canonicalization and an allowed-base check.",
        "CWE-78": "Externally influenced text reaches a command execution API without strict allow-list validation or shell separation.",
        "CWE-120": "Input is copied into a destination without a proven bound derived from the destination capacity.",
        "CWE-121": "Input is copied into a fixed-size stack object without a proven destination bound.",
        "CWE-134": "A non-literal, externally influenced value is interpreted as a format string.",
        "CWE-190": "Unchecked integer arithmetic is used to calculate an allocation or copy size.",
        "CWE-193": "An inclusive boundary can allow an index equal to the valid element count.",
        "CWE-242": "The code uses an input API that cannot enforce the destination buffer capacity.",
        "CWE-338": "A predictable pseudo-random generator is used where unpredictable values may be required.",
        "CWE-416": "A pointer remains reachable and is dereferenced after its allocation has been released.",
        "CWE-476": "An allocation result is dereferenced before a successful allocation is established.",
        "CWE-787": "A memory write uses a source or length whose relationship to destination capacity is not proven.",
    }

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def annotate(self, findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        return [
            finding.model_copy(update={"root_cause": self._root_cause(finding)})
            for finding in findings
        ]

    def _root_cause(self, finding: VulnerabilityFinding) -> str:
        root = self.ROOT_CAUSES.get(
            finding.cwe,
            "The reported source can reach the sink without the required validation or state invariant.",
        )
        if finding.source and finding.sink:
            return f"{root} Flow: {finding.source} -> {finding.sink}."
        return root
