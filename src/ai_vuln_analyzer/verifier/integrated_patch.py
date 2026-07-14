from __future__ import annotations

import os
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.analysis.cfg_analyzer import CfgAnalyzer
from ai_vuln_analyzer.analysis.program_flow import link_program_taint
from ai_vuln_analyzer.core.schemas import (
    IntegratedPatchVerification,
    PatchConflict,
    PatchSuggestion,
    VulnerabilityFinding,
)
from ai_vuln_analyzer.verifier.real_patch import RealPatchValidator


@dataclass(frozen=True)
class PatchEdit:
    finding_id: str
    file: Path
    line_start: int
    line_end: int
    replacement: str


class IntegratedPatchValidator:
    def __init__(
        self,
        ast_analyzer: AstAnalyzer,
        cfg_analyzer: CfgAnalyzer,
        real_validator: RealPatchValidator,
    ) -> None:
        self.ast_analyzer = ast_analyzer
        self.cfg_analyzer = cfg_analyzer
        self.real_validator = real_validator

    def validate(
        self,
        findings: list[VulnerabilityFinding],
        patches: list[PatchSuggestion],
        project_files: list[str | Path],
        agents: list[BaseAgent],
    ) -> IntegratedPatchVerification:
        finding_map = {finding.id: finding for finding in findings}
        edits, initially_skipped = self._edits(finding_map, patches)
        conflicts, conflicted_ids = self._conflicts(edits)
        applicable = [edit for edit in edits if edit.finding_id not in conflicted_ids]
        skipped = sorted(set(initially_skipped) | conflicted_ids)
        if not applicable:
            return IntegratedPatchVerification(
                skipped_finding_ids=skipped,
                conflicts=conflicts,
                parse_succeeded=True,
                verified=False,
                reason="No non-conflicting automatic patches were available for integrated validation.",
            )

        files = [Path(path) for path in project_files]
        with tempfile.TemporaryDirectory(prefix="ai-vuln-integrated-") as directory:
            temp_root = Path(directory)
            copied = self._copy_project(files, temp_root)
            edits_by_file: dict[Path, list[PatchEdit]] = defaultdict(list)
            for edit in applicable:
                edits_by_file[edit.file.resolve()].append(edit)
            for original, file_edits in edits_by_file.items():
                self._apply_edits(copied[original], file_edits)

            temp_files = list(copied.values())
            analyses = link_program_taint([self.ast_analyzer.analyze(path) for path in temp_files])
            cfg = [self.cfg_analyzer.analyze(path) for path in temp_files]
            parse_succeeded = all(item.parser == "tree-sitter" and item.parse_errors == 0 for item in analyses)
            rerun_findings = [candidate for agent in agents for candidate in agent.run(analyses, cfg)]
            re_detected = self._redetected(applicable, finding_map, copied, rerun_findings)
            compile_succeeded, compiler_output = self._compile_changed(edits_by_file, copied)

        verified = parse_succeeded and compile_succeeded is True and not re_detected and not conflicts
        reason = self._reason(parse_succeeded, compile_succeeded, re_detected, conflicts)
        return IntegratedPatchVerification(
            applied_finding_ids=sorted(edit.finding_id for edit in applicable),
            skipped_finding_ids=skipped,
            conflicts=conflicts,
            parse_succeeded=parse_succeeded,
            compile_succeeded=compile_succeeded,
            re_detected_finding_ids=sorted(re_detected),
            verified=verified,
            reason=reason,
            compiler_output=compiler_output,
        )

    def _edits(
        self,
        findings: dict[str, VulnerabilityFinding],
        patches: list[PatchSuggestion],
    ) -> tuple[list[PatchEdit], list[str]]:
        edits = []
        skipped = []
        for patch in patches:
            finding = findings.get(patch.finding_id)
            if not finding or patch.patched_code.startswith("/* review required */"):
                skipped.append(patch.finding_id)
                continue
            start = finding.location.line_start
            end = finding.location.line_end
            if start is None or end is None:
                skipped.append(patch.finding_id)
                continue
            edits.append(PatchEdit(
                finding_id=patch.finding_id,
                file=Path(finding.location.file).resolve(),
                line_start=start,
                line_end=end,
                replacement=patch.patched_code,
            ))
        return edits, skipped

    def _conflicts(self, edits: list[PatchEdit]) -> tuple[list[PatchConflict], set[str]]:
        conflicts = []
        conflicted_ids: set[str] = set()
        by_file: dict[Path, list[PatchEdit]] = defaultdict(list)
        for edit in edits:
            by_file[edit.file].append(edit)
        for file, file_edits in by_file.items():
            ordered = sorted(file_edits, key=lambda edit: (edit.line_start, edit.line_end))
            for index, left in enumerate(ordered):
                for right in ordered[index + 1:]:
                    if right.line_start > left.line_end:
                        break
                    if (
                        left.line_start == right.line_start
                        and left.line_end == right.line_end
                        and left.replacement == right.replacement
                    ):
                        continue
                    ids = sorted({left.finding_id, right.finding_id})
                    conflicted_ids.update(ids)
                    conflicts.append(PatchConflict(
                        file=str(file),
                        line_start=max(left.line_start, right.line_start),
                        line_end=min(left.line_end, right.line_end),
                        finding_ids=ids,
                        reason="Patch ranges overlap and propose different replacements.",
                    ))
        return conflicts, conflicted_ids

    def _copy_project(self, files: list[Path], temp_root: Path) -> dict[Path, Path]:
        resolved = [path.resolve() for path in files]
        common = Path(os.path.commonpath([str(path.parent) for path in resolved]))
        copied = {}
        for index, source in enumerate(resolved):
            try:
                relative = source.relative_to(common)
            except ValueError:
                relative = Path(f"external-{index}") / source.name
            destination = temp_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            copied[source] = destination
        return copied

    def _apply_edits(self, destination: Path, edits: list[PatchEdit]) -> None:
        code = destination.read_text(encoding="utf-8")
        lines = code.splitlines()
        unique = {
            (edit.line_start, edit.line_end, edit.replacement): edit
            for edit in edits
        }
        for edit in sorted(unique.values(), key=lambda item: item.line_start, reverse=True):
            lines[edit.line_start - 1:edit.line_end] = edit.replacement.splitlines()
        trailing = "\n" if code.endswith(("\n", "\r")) else ""
        destination.write_text("\n".join(lines) + trailing, encoding="utf-8")

    def _redetected(self, edits, findings, copied, candidates) -> set[str]:
        result = set()
        for edit in edits:
            original = findings[edit.finding_id]
            patched_file = copied[edit.file]
            if any(
                candidate.cwe == original.cwe
                and Path(candidate.location.file) == patched_file
                and (
                    not original.location.function
                    or candidate.location.function == original.location.function
                )
                for candidate in candidates
            ):
                result.add(edit.finding_id)
        return result

    def _compile_changed(self, edits_by_file, copied) -> tuple[bool | None, str | None]:
        results = []
        outputs = []
        for original in edits_by_file:
            result, output = self.real_validator._compile_pair(
                original, original.read_text(encoding="utf-8"), copied[original]
            )
            results.append(result)
            if output:
                outputs.append(f"{original.name}: {output}")
        if any(result is False for result in results):
            combined = False
        elif results and all(result is True for result in results):
            combined = True
        else:
            combined = None
        return combined, "\n".join(outputs) or None

    def _reason(self, parse_ok, compile_ok, redetected, conflicts) -> str:
        problems = []
        if conflicts:
            problems.append("one or more patches conflict")
        if not parse_ok:
            problems.append("the merged project has parse errors")
        if compile_ok is False:
            problems.append("the merged patch fails syntax compilation")
        elif compile_ok is None:
            problems.append("compilation is unavailable or inconclusive")
        if redetected:
            problems.append("one or more vulnerabilities are re-detected")
        if problems:
            return "Integrated patch is not verified because " + "; ".join(problems) + "."
        return "All merged patches parse, compile, and pass full agent re-analysis."
