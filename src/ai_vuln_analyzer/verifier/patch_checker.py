from __future__ import annotations

from ai_vuln_analyzer.core.schemas import PatchSuggestion, VulnerabilityFinding


class PatchChecker:
    def ast_patch_score(self, finding: VulnerabilityFinding, patch: PatchSuggestion) -> float:
        patched = patch.patched_code
        if finding.cwe in {"CWE-121", "CWE-122", "CWE-787"} and any(token in patched for token in {"strncpy", "snprintf", "sizeof", "if ("}):
            return 0.9
        if finding.cwe in {"CWE-416", "CWE-415"} and any(token in patched for token in {"NULL", "removed unsafe use", "return"}):
            return 0.85
        if finding.cwe in {"CWE-190", "CWE-191"} and any(token in patched for token in {"SIZE_MAX", "if ("}):
            return 0.88
        if finding.cwe in {"CWE-476", "CWE-457"} and "== NULL" in patched:
            return 0.9
        return 0.45

    def rule_based_score(self, finding: VulnerabilityFinding, patch: PatchSuggestion) -> float:
        patched = patch.patched_code
        if finding.sink == "strcpy" and "strncpy" in patched:
            return 0.92
        if finding.sink == "memcpy" and "SIZE_MAX" in patched:
            return 0.9
        if finding.cwe == "CWE-476" and "return;" in patched:
            return 0.86
        if finding.cwe == "CWE-416" and "unsafe use" in patched:
            return 0.8
        if finding.cwe == "CWE-416" and "p = NULL" in patched and "if (p != NULL)" in patched:
            return 0.86
        return 0.4
