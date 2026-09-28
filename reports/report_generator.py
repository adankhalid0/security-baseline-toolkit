"""Render audit findings as a Markdown risk report."""

from __future__ import annotations

from datetime import datetime, timezone

from baseline.risk import RiskLevel

_LEVEL_ORDER = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3}


def _summary_counts(findings: list[dict]) -> dict:
    counts = {level.value: 0 for level in RiskLevel}
    for f in findings:
        counts[f["risk_level"].value] += 1
    return counts


def generate_markdown_report(findings: list[dict], passed: list[dict], title: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    findings_sorted = sorted(findings, key=lambda f: _LEVEL_ORDER[f["risk_level"]])
    counts = _summary_counts(findings)

    lines = [
        f"# {title}",
        "",
        f"Generated: {now}",
        "",
        "## Summary",
        "",
        f"- Assets evaluated: **{len({f['asset_id'] for f in findings} | {p['asset_id'] for p in passed})}**",
        f"- Controls passed: **{len(passed)}**",
        f"- Findings (failed controls): **{len(findings)}**",
        f"  - Critical: {counts['Critical']}  ·  High: {counts['High']}  ·  "
        f"Medium: {counts['Medium']}  ·  Low: {counts['Low']}",
        "",
        "## Findings",
        "",
    ]

    if not findings_sorted:
        lines.append("No findings — all applicable controls passed for the evaluated assets.")
    else:
        lines.append(
            "| Risk | Control | Asset | Framework mapping | Evidence | Compensating control |"
        )
        lines.append("|---|---|---|---|---|---|")
        for f in findings_sorted:
            c = f["control"]
            lines.append(
                f"| **{f['risk_level'].value}** ({f['risk_score']}) "
                f"| {c.control_id} — {c.title} "
                f"| {f['asset_id']} "
                f"| NIST {c.nist_csf} / ISO {c.iso27001} "
                f"| {f['evidence']} "
                f"| {c.compensating_control} |"
            )

    lines += ["", "## Controls passed", ""]
    if not passed:
        lines.append("None.")
    else:
        lines.append("| Control | Asset | Framework mapping | Evidence |")
        lines.append("|---|---|---|---|")
        for p in passed:
            c = p["control"]
            lines.append(
                f"| {c.control_id} — {c.title} | {p['asset_id']} "
                f"| NIST {c.nist_csf} / ISO {c.iso27001} | {p['evidence']} |"
            )

    lines += [
        "",
        "## Method",
        "",
        "Each control is checked automatically against the asset inventory. A failed "
        "control becomes a finding, rated with a likelihood x impact score "
        "(1-5 x 1-5, ISO 31000-style) based on the asset's network exposure and the "
        "control's default impact. Findings are sorted by risk level, highest first, "
        "so remediation effort goes where it matters most instead of being applied "
        "evenly across every gap.",
        "",
    ]

    return "\n".join(lines)
