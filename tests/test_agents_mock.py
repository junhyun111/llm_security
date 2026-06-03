from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.pipeline import VulnerabilityPipeline


def test_pipeline_mock_generates_findings():
    pipeline = VulnerabilityPipeline(Settings(provider="mock"))
    report = pipeline.run("examples/vulnerable")
    assert report.summary["total_findings"] >= 4
    assert any(finding.root_cause for finding in report.artifacts.findings)
    assert report.artifacts.patches
