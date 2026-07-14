from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from ai_vuln_analyzer.core.schemas import FinalReport, VulnerabilityFinding


class GroundTruthFinding(BaseModel):
    file: str
    cwe: str
    line: int
    function: str | None = None


class CweMetrics(BaseModel):
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


class EvaluationMetrics(BaseModel):
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    cwe_classification_accuracy: float
    location_aligned_findings: int
    per_cwe: dict[str, CweMetrics] = Field(default_factory=dict)
    patch_parse_success_rate: float
    patch_verification_rate: float
    patch_redetection_rate: float


def load_report(path: str | Path) -> FinalReport:
    return FinalReport.model_validate_json(Path(path).read_text(encoding="utf-8"))


def load_ground_truth(path: str | Path) -> list[GroundTruthFinding]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = raw.get("findings", []) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("Ground truth must be a list or an object containing a 'findings' list.")
    return [GroundTruthFinding.model_validate(entry) for entry in entries]


def evaluate_report(
    report: FinalReport,
    ground_truth: list[GroundTruthFinding],
    line_tolerance: int = 1,
) -> EvaluationMetrics:
    predictions = report.artifacts.findings
    exact_pairs = _greedy_pairs(predictions, ground_truth, line_tolerance, require_cwe=True)
    location_pairs = _greedy_pairs(predictions, ground_truth, line_tolerance, require_cwe=False)
    true_positives = len(exact_pairs)
    false_positives = len(predictions) - true_positives
    false_negatives = len(ground_truth) - true_positives
    precision, recall, f1 = _rates(true_positives, false_positives, false_negatives)

    correctly_classified = sum(
        predictions[prediction_index].cwe == ground_truth[truth_index].cwe
        for prediction_index, truth_index in location_pairs
    )
    classification_accuracy = _safe_divide(correctly_classified, len(location_pairs))
    per_cwe = _per_cwe(predictions, ground_truth, exact_pairs)

    verifications = report.artifacts.verifications
    parse_known = [item for item in verifications if item.parse_succeeded is not None]
    redetection_known = [item for item in verifications if item.vulnerability_re_detected is not None]
    return EvaluationMetrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
        cwe_classification_accuracy=classification_accuracy,
        location_aligned_findings=len(location_pairs),
        per_cwe=per_cwe,
        patch_parse_success_rate=_safe_divide(
            sum(item.parse_succeeded is True for item in parse_known), len(parse_known)
        ),
        patch_verification_rate=_safe_divide(
            sum(item.verified for item in verifications), len(verifications)
        ),
        patch_redetection_rate=_safe_divide(
            sum(item.vulnerability_re_detected is True for item in redetection_known),
            len(redetection_known),
        ),
    )


def _greedy_pairs(predictions, ground_truth, tolerance, require_cwe):
    pairs = []
    used_truth = set()
    for prediction_index, prediction in enumerate(predictions):
        candidates = [
            (abs((prediction.location.line_start or 0) - truth.line), truth_index)
            for truth_index, truth in enumerate(ground_truth)
            if truth_index not in used_truth
            and _same_location(prediction, truth, tolerance)
            and (not require_cwe or prediction.cwe == truth.cwe)
        ]
        if not candidates:
            continue
        _, truth_index = min(candidates)
        used_truth.add(truth_index)
        pairs.append((prediction_index, truth_index))
    return pairs


def _same_location(
    prediction: VulnerabilityFinding,
    truth: GroundTruthFinding,
    tolerance: int,
) -> bool:
    prediction_file = Path(prediction.location.file)
    truth_file = Path(truth.file)
    same_file = (
        prediction_file.as_posix().lower() == truth_file.as_posix().lower()
        or prediction_file.name.lower() == truth_file.name.lower()
    )
    same_function = not truth.function or prediction.location.function == truth.function
    prediction_line = prediction.location.line_start
    return bool(
        same_file and same_function and prediction_line is not None
        and abs(prediction_line - truth.line) <= tolerance
    )


def _per_cwe(predictions, ground_truth, exact_pairs) -> dict[str, CweMetrics]:
    matched_predictions = {prediction for prediction, _ in exact_pairs}
    matched_truth = {truth for _, truth in exact_pairs}
    cwes = {prediction.cwe for prediction in predictions} | {truth.cwe for truth in ground_truth}
    result = {}
    for cwe in sorted(cwes):
        tp = sum(predictions[index].cwe == cwe for index in matched_predictions)
        fp = sum(
            prediction.cwe == cwe and index not in matched_predictions
            for index, prediction in enumerate(predictions)
        )
        fn = sum(
            truth.cwe == cwe and index not in matched_truth
            for index, truth in enumerate(ground_truth)
        )
        precision, recall, f1 = _rates(tp, fp, fn)
        result[cwe] = CweMetrics(
            true_positives=tp, false_positives=fp, false_negatives=fn,
            precision=precision, recall=recall, f1=f1,
        )
    return result


def _rates(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1 = _safe_divide(2 * precision * recall, precision + recall)
    return precision, recall, f1


def _safe_divide(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0
