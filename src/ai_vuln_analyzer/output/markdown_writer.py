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
                f"Remaining Risks: {', '.join(verification.remaining_risks) if verification else ''}",
                "",
            ]
        )
    Path(path).write_text("\n".join(lines), encoding="utf-8")
