#!/usr/bin/env python3
"""
Security Baseline & Risk Assessment Toolkit
=============================================

CLI entrypoint. Runs the baseline control set (baseline/controls.py) against
an asset inventory (examples/sample_inventory.yaml by default), scores every
failed control as a risk (baseline/risk.py), and writes a Markdown report.

Usage:
    python audit.py
    python audit.py --inventory examples/sample_inventory.yaml --out report.md
    python audit.py --json                # also print raw findings as JSON
"""

from __future__ import annotations

import argparse
import json
import sys

from baseline.controls import BASELINE
from baseline.risk import rate_finding
from reports.report_generator import generate_markdown_report
from scanner.checks import CHECK_REGISTRY
from scanner.inventory import load_inventory


def run_audit(inventory_path: str) -> tuple[list[dict], list[dict]]:
    assets = load_inventory(inventory_path)
    findings: list[dict] = []
    passed: list[dict] = []

    for asset in assets:
        for control in BASELINE:
            check_fn = CHECK_REGISTRY[control.check_name]
            result = check_fn(asset)

            if not result["applicable"]:
                continue

            record = {
                "asset_id": asset.get("id", "unknown"),
                "control": control,
                "evidence": result["evidence"],
            }

            if result["passed"]:
                passed.append(record)
                continue

            rating = rate_finding(control, result)
            record["risk_score"] = rating.score
            record["risk_level"] = rating.level
            findings.append(record)

    return findings, passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inventory", default="examples/sample_inventory.yaml",
        help="Path to the asset inventory YAML file.",
    )
    parser.add_argument(
        "--out", default="report.md",
        help="Path to write the Markdown report to.",
    )
    parser.add_argument(
        "--title", default="Security Baseline Audit Report",
        help="Report title.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Also print raw findings as JSON to stdout.",
    )
    args = parser.parse_args()

    findings, passed = run_audit(args.inventory)

    report = generate_markdown_report(findings, passed, args.title)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Evaluated inventory: {args.inventory}")
    print(f"Controls passed: {len(passed)}")
    print(f"Findings: {len(findings)}")
    print(f"Report written to: {args.out}")

    if args.json:
        json_findings = [
            {
                "asset_id": f["asset_id"],
                "control_id": f["control"].control_id,
                "title": f["control"].title,
                "nist_csf": f["control"].nist_csf,
                "iso27001": f["control"].iso27001,
                "evidence": f["evidence"],
                "risk_score": f["risk_score"],
                "risk_level": f["risk_level"].value,
            }
            for f in findings
        ]
        print(json.dumps(json_findings, indent=2))

    # Non-zero exit if any Critical/High findings, useful for CI pipelines.
    severe = [f for f in findings if f["risk_level"].value in {"Critical", "High"}]
    return 1 if severe else 0


if __name__ == "__main__":
    sys.exit(main())
