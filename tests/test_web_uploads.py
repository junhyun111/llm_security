from __future__ import annotations

import asyncio
from io import BytesIO

import pytest
from fastapi import UploadFile
from fastapi.testclient import TestClient

from ai_vuln_analyzer.web.app import UploadValidationError, app, safe_upload_name, save_upload_limited
from ai_vuln_analyzer.web.app import _run_pipeline_process
from ai_vuln_analyzer.config import Settings


def test_upload_name_rejects_paths_and_non_source_files():
    assert safe_upload_name("source.c") == "source.c"
    with pytest.raises(UploadValidationError):
        safe_upload_name("../source.c")
    with pytest.raises(UploadValidationError):
        safe_upload_name("archive.zip")


def test_home_page_renders_valid_korean_interface():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "취약점 분석 시작" in response.text
    assert '<label for="files">' in response.text


def test_streamed_upload_enforces_file_limit(tmp_path):
    upload = UploadFile(filename="large.c", file=BytesIO(b"a" * 32))

    with pytest.raises(UploadValidationError):
        asyncio.run(save_upload_limited(upload, tmp_path / "large.c", 16, 64))


def test_web_analysis_runs_in_isolated_process(tmp_path):
    (tmp_path / "sample.c").write_text(
        '#include <stdio.h>\nvoid show(char *value) { printf(value); }\n',
        encoding="utf-8",
    )

    report = _run_pipeline_process(
        Settings(provider="mock").model_dump(mode="json"), str(tmp_path)
    )

    assert any(finding.cwe == "CWE-134" for finding in report.artifacts.findings)
