from __future__ import annotations

import json
from pathlib import Path

from ai_vuln_analyzer.core.schemas import FinalReport


def write_json_report(path: str | Path, report: FinalReport) -> None:
    Path(path).write_text(
        json.dumps(report.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
