from __future__ import annotations

from pathlib import Path

from ai_vuln_analyzer.core.schemas import FinalReport


def write_markdown_report(path: str | Path, report: FinalReport) -> None:
    lines = [
        "# C/C++ Vulnerability Analysis Report",
        "",
        "## Summary",
        "",
        f"- Total findings: {report.summary['total_findings']}",
        f"- Verified findings: {report.summary['verified_findings']}",
        f"- Rejected findings: {report.summary['rejected_findings']}",
        f"- Unresolved findings: {report.summary['unresolved_findings']}",
        "",
    ]
    patch_map = {patch.finding_id: patch for patch in report.artifacts.patches}
    verification_map = {item.finding_id: item for item in report.artifacts.verifications}
    if report.artifacts.llm_warning:
        lines.extend(["## LLM Warning", "", report.artifacts.llm_warning, ""])
    if report.artifacts.analysis_failures:
        lines.extend(["## Analysis Failures", ""])
        for failure in report.artifacts.analysis_failures:
            lines.append(f"- {failure.file} ({failure.stage}): {failure.error}")
        lines.append("")
    integrated = report.artifacts.integrated_verification
    if integrated:
        lines.extend([
            "## Integrated Patch Verification", "",
            f"- Verified: {integrated.verified}",
            f"- Parse succeeded: {integrated.parse_succeeded}",
            f"- Compile succeeded: {integrated.compile_succeeded}",
            f"- Applied findings: {', '.join(integrated.applied_finding_ids)}",
            f"- Skipped findings: {', '.join(integrated.skipped_finding_ids)}",
            f"- Re-detected findings: {', '.join(integrated.re_detected_finding_ids)}",
            f"- Conflicts: {len(integrated.conflicts)}",
            f"- Reason: {integrated.reason}", "",
        ])
    for index, finding in enumerate(report.artifacts.findings, start=1):
        patch = patch_map.get(finding.id)
        verification = verification_map.get(finding.id)
        lines.extend(
            [
                f"## Finding {index}",
                "",
                f"- CWE: {finding.cwe}",
                f"- Type: {finding.vulnerability_type}",
                f"- File: {finding.location.file}",
                f"- Function: {finding.location.function or '-'}",
                f"- Lines: {finding.location.line_start}-{finding.location.line_end}",
                f"- Confidence: {finding.confidence}",
                f"- Status: {finding.status}",
                f"- Role: {finding.finding_role}",
                f"- Related finding: {finding.related_finding_id or '-'}",
                "",
                "### Evidence",
                "",
                finding.evidence,
                "",
                "### Root Cause",
                "",
                finding.root_cause or "N/A",
                "",
                "### Patch",
                "",
                "```diff",
                patch.diff if patch and patch.diff else "",
                "```",
                "",
                "### Verification Result",
                "",
                f"Verified: {verification.verified if verification else False}",
                f"Confidence: {verification.confidence if verification else 0.0}",
                f"Rerun Agents: {', '.join(verification.rerun_agents) if verification else ''}",
                f"Reason: {verification.reason if verification else 'N/A'}",
                f"Parse succeeded: {verification.parse_succeeded if verification else 'N/A'}",
                f"Compile succeeded: {verification.compile_succeeded if verification else 'N/A'}",
                f"Vulnerability re-detected: {verification.vulnerability_re_detected if verification else 'N/A'}",
                f"Remaining Risks: {', '.join(verification.remaining_risks) if verification else ''}",
                "",
            ]
        )
    Path(path).write_text("\n".join(lines), encoding="utf-8")
