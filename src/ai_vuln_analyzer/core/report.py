from __future__ import annotations

from ai_vuln_analyzer.core.schemas import FinalReport


def build_summary(report: FinalReport) -> dict:
    findings = report.artifacts.findings
    return {
        "total_findings": len(findings),
        "verified_findings": sum(1 for item in findings if item.status == "verified"),
        "rejected_findings": sum(1 for item in findings if item.status == "rejected"),
        "unresolved_findings": sum(1 for item in findings if item.status == "unresolved"),
    }
