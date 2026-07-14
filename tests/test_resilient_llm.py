from __future__ import annotations

from ai_vuln_analyzer.llm.base import LLMClient
from ai_vuln_analyzer.llm.resilient_client import ResilientLLMClient
from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.pipeline import VulnerabilityPipeline


class RateLimitError(Exception):
    status_code = 429


class FailingClient(LLMClient):
    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.calls = 0

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.calls += 1
        if self.calls <= self.failures:
            raise RateLimitError("temporarily rate limited")
        return '{"ok": true}'


def test_transient_llm_failure_retries_then_succeeds():
    client = FailingClient(failures=1)
    delays = []
    resilient = ResilientLLMClient(client, max_retries=2, sleep=delays.append)

    assert resilient.complete("system", "user") == '{"ok": true}'
    assert client.calls == 2
    assert delays == [1.0]


def test_llm_outage_returns_empty_response_for_static_fallback():
    client = FailingClient(failures=10)
    resilient = ResilientLLMClient(client, max_retries=1, sleep=lambda delay: None)

    assert resilient.complete("system", "user") == ""
    assert resilient.last_error == "temporarily rate limited"


def test_pipeline_reports_llm_warning_but_keeps_static_findings(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text(
        '#include <stdio.h>\nvoid show(char *value) { printf(value); }\n', encoding="utf-8"
    )
    resilient = ResilientLLMClient(
        FailingClient(failures=10), max_retries=0, sleep=lambda delay: None
    )
    pipeline = VulnerabilityPipeline(Settings(provider="mock"))
    pipeline.llm = resilient
    pipeline.planner.llm = resilient

    report = pipeline.run(source)

    assert report.artifacts.llm_warning
    assert any(finding.cwe == "CWE-134" for finding in report.artifacts.findings)
