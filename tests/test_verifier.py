from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.pipeline import VulnerabilityPipeline


def test_verifier_returns_confidence_scores():
    pipeline = VulnerabilityPipeline(Settings(provider="mock", confidence_threshold=0.8))
    report = pipeline.run("examples/vulnerable")
    assert report.artifacts.verifications
    assert all(0.0 <= item.confidence <= 1.0 for item in report.artifacts.verifications)
