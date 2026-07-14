from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.analysis.cfg_analyzer import CfgAnalyzer
from ai_vuln_analyzer.analysis.program_flow import link_program_taint
from ai_vuln_analyzer.analysis.semantic_flow import identifiers
from ai_vuln_analyzer.core.schemas import PatchSuggestion, VulnerabilityFinding


@dataclass(frozen=True)
class RealPatchResult:
    parse_succeeded: bool
    compile_succeeded: bool | None
    vulnerability_re_detected: bool
    compiler_output: str | None
    introduced_identifiers: tuple[str, ...] = ()


class RealPatchValidator:
    def __init__(self, ast_analyzer: AstAnalyzer, cfg_analyzer: CfgAnalyzer) -> None:
        self.ast_analyzer = ast_analyzer
        self.cfg_analyzer = cfg_analyzer

    def validate(
        self,
        finding: VulnerabilityFinding,
        patch: PatchSuggestion,
        agents: list[BaseAgent],
        project_files: list[str | Path] | None = None,
    ) -> RealPatchResult:
        original_path = Path(finding.location.file)
        original_code = original_path.read_text(encoding="utf-8")
        patched_code = self._apply_patch(original_code, finding, patch)
        introduced_identifiers = self._introduced_identifiers(original_code, patch.patched_code)

        with tempfile.TemporaryDirectory(prefix="ai-vuln-patch-") as directory:
            patched_path = Path(directory) / original_path.name
            patched_path.write_text(patched_code, encoding="utf-8")
            other_files = [
                Path(path)
                for path in (project_files or [])
                if Path(path).resolve() != original_path.resolve()
            ]
            analysis = link_program_taint([
                *(self.ast_analyzer.analyze(path) for path in other_files),
                self.ast_analyzer.analyze(patched_path),
            ])
            cfg = [
                *(self.cfg_analyzer.analyze(path) for path in other_files),
                self.cfg_analyzer.analyze(patched_path),
            ]
            patched_analysis = next(item for item in analysis if Path(item.file) == patched_path)
            parse_succeeded = patched_analysis.parser == "tree-sitter" and patched_analysis.parse_errors == 0
            relevant_agents = [agent for agent in agents if finding.cwe in agent.covered_cwes]
            rerun_findings = [
                candidate
                for agent in relevant_agents
                for candidate in agent.run(analysis, cfg)
            ]
            vulnerability_re_detected = any(
                candidate.cwe == finding.cwe
                and (
                    not finding.location.function
                    or candidate.location.function == finding.location.function
                )
                for candidate in rerun_findings
            )
            compile_succeeded, compiler_output = self._compile_pair(
                original_path, original_code, patched_path
            )
        return RealPatchResult(
            parse_succeeded=parse_succeeded,
            compile_succeeded=compile_succeeded,
            vulnerability_re_detected=vulnerability_re_detected,
            compiler_output=compiler_output,
            introduced_identifiers=tuple(introduced_identifiers),
        )

    def _introduced_identifiers(self, original_code: str, patched_snippet: str) -> list[str]:
        allowed_new = {
            "NULL", "SIZE_MAX", "snprintf", "strncat", "strncpy", "memcpy", "memmove",
        }
        original_names = identifiers(original_code)
        patch_names = identifiers(patched_snippet)
        return sorted(patch_names - original_names - allowed_new)

    def _apply_patch(
        self,
        original_code: str,
        finding: VulnerabilityFinding,
        patch: PatchSuggestion,
    ) -> str:
        lines = original_code.splitlines()
        start = max((finding.location.line_start or 1) - 1, 0)
        end = finding.location.line_end or start + 1
        if start >= len(lines) or end > len(lines):
            raise ValueError(f"Patch location {start + 1}-{end} is outside {finding.location.file}")
        patched_lines = patch.patched_code.splitlines()
        result = [*lines[:start], *patched_lines, *lines[end:]]
        trailing_newline = "\n" if original_code.endswith(("\n", "\r")) else ""
        return "\n".join(result) + trailing_newline

    def _compile_pair(
        self,
        original_path: Path,
        original_code: str,
        patched_path: Path,
    ) -> tuple[bool | None, str | None]:
        compiler = self._find_compiler(original_path.suffix.lower())
        if compiler is None:
            return None, "No supported C/C++ compiler was found (clang, gcc, or cl)."

        baseline_path = patched_path.with_name(f"baseline{original_path.suffix}")
        baseline_path.write_text(original_code, encoding="utf-8")
        baseline_ok, baseline_output = self._compile(compiler, baseline_path, original_path.parent)
        patched_ok, patched_output = self._compile(compiler, patched_path, original_path.parent)
        if baseline_ok:
            return patched_ok, patched_output or None
        if patched_ok:
            return True, None
        output = (
            "Baseline source also fails syntax compilation; patch compilation is inconclusive.\n"
            f"Baseline: {baseline_output[-1200:]}\nPatched: {patched_output[-1200:]}"
        )
        return None, output

    def _find_compiler(self, suffix: str) -> str | None:
        candidates = ["clang", "gcc", "cl"] if suffix == ".c" else ["clang++", "g++", "cl"]
        return next((path for candidate in candidates if (path := shutil.which(candidate))), None)

    def _compile(self, compiler: str, source: Path, include_directory: Path) -> tuple[bool, str]:
        if Path(compiler).name.lower() in {"cl", "cl.exe"}:
            command = [compiler, "/nologo", "/Zs", f"/I{include_directory}", str(source)]
        else:
            command = [compiler, "-fsyntax-only", "-I", str(include_directory), str(source)]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)
        output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
        return result.returncode == 0, output
