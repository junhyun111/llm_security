from __future__ import annotations

from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.pipeline import VulnerabilityPipeline


def test_parse_errors_are_reported_without_stopping_other_files(tmp_path):
    (tmp_path / "broken.c").write_text("void broken( {", encoding="utf-8")
    (tmp_path / "valid.c").write_text(r'''
        #include <stdio.h>
        void show(char *value) { printf(value); }
    ''', encoding="utf-8")

    report = VulnerabilityPipeline(Settings(provider="mock")).run(tmp_path)

    assert any(failure.file.endswith("broken.c") for failure in report.artifacts.analysis_failures)
    assert any(finding.cwe == "CWE-134" for finding in report.artifacts.findings)
