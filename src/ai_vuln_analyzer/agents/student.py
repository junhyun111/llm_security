from __future__ import annotations

import difflib
import re
from pathlib import Path

from ai_vuln_analyzer.core.schemas import PatchSuggestion, VulnerabilityFinding
from ai_vuln_analyzer.llm.base import LLMClient


class Student:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def generate_patches(self, findings: list[VulnerabilityFinding]) -> list[PatchSuggestion]:
        return [self._generate_patch(finding) for finding in findings]

    def _generate_patch(self, finding: VulnerabilityFinding) -> PatchSuggestion:
        path = Path(finding.location.file)
        lines = path.read_text(encoding="utf-8").splitlines()
        start = max((finding.location.line_start or 1) - 1, 0)
        end = finding.location.line_end or start + 1
        original = "\n".join(lines[start:end])
        patched = self._patch_text(original, finding)
        requires_review = patched.startswith("/* review required */")
        patch_confidence = 0.35 if requires_review else 0.82
        explanation = (
            "No context-safe automatic rewrite is available; manual review is required."
            if requires_review
            else "The rewrite preserves identifiers from the original statement and adds a vulnerability-specific guard."
        )
        diff = "\n".join(
            difflib.unified_diff(
                original.splitlines(),
                patched.splitlines(),
                fromfile="original",
                tofile="patched",
                lineterm="",
            )
        )
        return PatchSuggestion(
            finding_id=finding.id,
            explanation=explanation,
            original_code=original,
            patched_code=patched,
            diff=diff,
            confidence=patch_confidence,
        )

    def _patch_text(self, original: str, finding: VulnerabilityFinding) -> str:
        sink = finding.sink or ""
        if sink == "strcpy":
            args = self._call_arguments(original, "strcpy")
            if len(args) == 2:
                target, source = args
                indent = re.match(r"\s*", original).group(0)
                return f'{indent}snprintf({target}, sizeof({target}), "%s", {source});'
        if sink == "memcpy":
            args = self._call_arguments(original, "memcpy")
            if len(args) == 3:
                target, source, length = args
                return f"if ({length} <= sizeof({target})) {{\n    memcpy({target}, {source}, {length});\n}}"
        if finding.cwe == "CWE-476":
            variable = finding.source or ""
            if re.fullmatch(r"[A-Za-z_]\w*", variable):
                lines = original.splitlines()
                return "\n".join([lines[0], f"if ({variable} == NULL) {{ return; }}", *lines[1:]])
        if finding.cwe == "CWE-416":
            variable = finding.source or ""
            if re.fullmatch(r"[A-Za-z_]\w*", variable):
                kept = [line for line in original.splitlines() if "free(" in line or variable not in line]
                free_index = next((index for index, line in enumerate(kept) if "free(" in line), None)
                if free_index is not None:
                    kept.insert(free_index + 1, f"{variable} = NULL;")
                    return "\n".join(kept)
        if finding.cwe == "CWE-134" and sink:
            args = self._call_arguments(original, sink)
            format_index = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1}.get(sink)
            if format_index is not None and format_index < len(args):
                value = args[format_index]
                args[format_index:format_index + 1] = ['"%s"', value]
                return re.sub(rf"\b{re.escape(sink)}\s*\(.*?\)", f"{sink}({', '.join(args)})", original)
        return f"/* review required */\n{original}"

    def _call_arguments(self, text: str, callee: str) -> list[str]:
        match = re.search(rf"\b{re.escape(callee)}\s*\((.*?)\)\s*;?", text, re.DOTALL)
        if not match:
            return []
        return [part.strip() for part in match.group(1).split(",")]
