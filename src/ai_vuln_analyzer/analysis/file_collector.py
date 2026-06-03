from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.analysis.dangerous_api import CPP_EXTENSIONS


def collect_cpp_files(root: str | Path) -> list[Path]:
    root_path = Path(root)
    if root_path.is_file() and root_path.suffix.lower() in CPP_EXTENSIONS:
        return [root_path]
    files = sorted(
        path
        for path in root_path.rglob("*")
        if path.is_file() and path.suffix.lower() in CPP_EXTENSIONS
    )
    return files
