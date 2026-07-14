from __future__ import annotations

from ai_vuln_analyzer.core.schemas import (
    CodeLocation,
    FinalReport,
    PipelineArtifacts,
    PlannerDecision,
    VerificationResult,
    VulnerabilityFinding,
)
from ai_vuln_analyzer.evaluation.evaluator import GroundTruthFinding, evaluate_report


def _prediction(finding_id: str, cwe: str, line: int) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id=finding_id, cwe=cwe, vulnerability_type="test",
        location=CodeLocation(file="sample.c", function="run", line_start=line, line_end=line),
        evidence="test", agent_name="test", confidence=0.8,
    )


def test_evaluator_reports_detection_cwe_and_patch_metrics():
    findings = [
        _prediction("correct", "CWE-78", 10),
        _prediction("wrong-cwe", "CWE-121", 20),
        _prediction("false-positive", "CWE-22", 50),
    ]
    report = FinalReport(
        summary={},
        artifacts=PipelineArtifacts(
            planner_decision=PlannerDecision(), findings=findings,
            verifications=[
                VerificationResult(
                    finding_id="correct", verified=True, confidence=0.9, reason="ok",
                    parse_succeeded=True, vulnerability_re_detected=False,
                ),
                VerificationResult(
                    finding_id="wrong-cwe", verified=False, confidence=0.2, reason="failed",
                    parse_succeeded=False, vulnerability_re_detected=True,
                ),
            ],
        ),
    )
    truth = [
        GroundTruthFinding(file="sample.c", function="run", line=10, cwe="CWE-78"),
        GroundTruthFinding(file="sample.c", function="run", line=20, cwe="CWE-134"),
    ]

    metrics = evaluate_report(report, truth, line_tolerance=0)

    assert metrics.true_positives == 1
    assert metrics.false_positives == 2
    assert metrics.false_negatives == 1
    assert metrics.precision == 0.3333
    assert metrics.recall == 0.5
    assert metrics.cwe_classification_accuracy == 0.5
    assert metrics.patch_parse_success_rate == 0.5
    assert metrics.patch_verification_rate == 0.5
    assert metrics.patch_redetection_rate == 0.5
