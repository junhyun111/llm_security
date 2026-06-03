from __future__ import annotations

import re
from pathlib import Path

from ai_vuln_analyzer.analysis.dangerous_api import DANGEROUS_APIS
from ai_vuln_analyzer.core.schemas import AstAnalysis, FunctionSummary

FUNCTION_PATTERN = re.compile(
    r"^\s*([A-Za-z_][\w:\s\*<>]*?)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE,
)


class AstAnalyzer:
    def analyze(self, file_path: str | Path) -> AstAnalysis:
        path = Path(file_path)
        code = path.read_text(encoding="utf-8")
        functions = self._extract_functions(code, str(path))
        dangerous_calls = self._find_dangerous_calls(code)
        return AstAnalysis(
            file=str(path),
            language="c_cpp",
            parser="regex-fallback",
            functions=functions,
            dangerous_calls=dangerous_calls,
        )

    def _extract_functions(self, code: str, file_path: str) -> list[FunctionSummary]:
        functions: list[FunctionSummary] = []
        lines = code.splitlines()
        for match in FUNCTION_PATTERN.finditer(code):
            name = match.group(2)
            start_line = code[: match.start()].count("\n") + 1
            end_line = self._find_block_end(lines, start_line)
            snippet = "\n".join(lines[start_line - 1 : end_line])
            calls = [api for api in DANGEROUS_APIS if f"{api}(" in snippet]
            locals_found = re.findall(r"\b(?:char|int|size_t|long|void)\s+\*?([A-Za-z_]\w*)", snippet)
            notes = []
            if "[" in snippet and any(api in calls for api in {"strcpy", "memcpy", "sprintf"}):
                notes.append("stack buffer with copy API")
            if "malloc(" in snippet and "if (" not in snippet:
                notes.append("allocation without visible null-check")
            functions.append(
                FunctionSummary(
                    file=file_path,
                    name=name,
                    line_start=start_line,
                    line_end=end_line,
                    calls=sorted(set(calls)),
                    locals=sorted(set(locals_found)),
                    notes=notes,
                )
            )
        return functions

    def _find_block_end(self, lines: list[str], start_line: int) -> int:
        depth = 0
        started = False
        for index in range(start_line - 1, len(lines)):
            depth += lines[index].count("{")
            if "{" in lines[index]:
                started = True
            depth -= lines[index].count("}")
            if started and depth == 0:
                return index + 1
        return len(lines)

    def _find_dangerous_calls(self, code: str) -> list[dict]:
        findings: list[dict] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            for api, meta in DANGEROUS_APIS.items():
                if f"{api}(" in line:
                    findings.append(
                        {
                            "api": api,
                            "line": lineno,
                            "content": line.strip(),
                            "cwes": meta["cwes"],
                        }
                    )
        return findings
