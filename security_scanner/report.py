"""Renders a ScanResult as plain text for the terminal."""

from __future__ import annotations

from security_scanner.models import RiskLevel, ScanResult

_RISK_ORDER = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2}


def render_text(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("CyberLab Security Scanner - Report")
    lines.append("=" * 70)
    lines.append(f"Target:   {result.target_url}")
    failed = result.failed_request_count
    req_line = f"Requests: {result.total_requests}"
    if failed:
        req_line += f"  ({failed} failed to connect)"
    lines.append(req_line)
    lines.append(f"Notice:   {result.disclaimer}")
    lines.append("")

    counts = result.risk_counts()
    lines.append(
        f"Findings: {len(result.findings)}  "
        f"(High={counts['High']}, Medium={counts['Medium']}, Low={counts['Low']})"
    )
    lines.append("")

    ordered = sorted(result.findings, key=lambda f: _RISK_ORDER[f.risk])
    if not ordered:
        lines.append("No findings from the automated checks. This does not mean the")
        lines.append("target is secure — manual review is still recommended.")
    for i, finding in enumerate(ordered, start=1):
        lines.append(f"[{i}] {finding.risk.value.upper()} - {finding.title}  ({finding.module})")
        lines.append(f"    URL:         {finding.request_url}")
        lines.append(f"    Description: {finding.description}")
        lines.append(f"    Evidence:    {finding.evidence}")
        lines.append(f"    Remediation: {finding.remediation}")
        lines.append("")

    if result.errors:
        lines.append("-" * 70)
        lines.append("Module errors (scan continued past these):")
        for err in result.errors:
            lines.append(f"  - {err}")
        lines.append("")

    return "\n".join(lines)
