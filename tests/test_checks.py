"""
Unit tests for the risk engine and a few representative checks.

Run with:  pytest -q
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from baseline.controls import get_control
from baseline.risk import RiskLevel, rate_finding
from scanner import checks
from scanner.network_scanner import parse_nftables_default_policy


def test_risk_level_thresholds():
    control = get_control("AC-01")
    assert rate_finding(control, {"exposure": "internet"}).level == RiskLevel.CRITICAL
    assert rate_finding(control, {"exposure": "internal_trusted"}).level in {
        RiskLevel.MEDIUM, RiskLevel.HIGH,
    }


def test_check_mfa_enabled_pass_and_fail():
    ok = checks.check_mfa_enabled({"type": "host", "mfa_enabled": True, "exposure": "internal_trusted"})
    assert ok["applicable"] and ok["passed"]

    fail = checks.check_mfa_enabled({"type": "host", "mfa_enabled": False, "exposure": "internet"})
    assert fail["applicable"] and not fail["passed"]


def test_check_exposed_ports_flags_sensitive_ports():
    result = checks.check_exposed_ports({
        "type": "host", "open_ports": [22, 3389], "exposure": "internal_untrusted",
    })
    assert result["applicable"]
    assert not result["passed"]
    assert "3389" in result["evidence"]


def test_check_exposed_ports_clean_host_passes():
    result = checks.check_exposed_ports({
        "type": "host", "open_ports": [22, 443], "exposure": "internal_trusted",
    })
    assert result["applicable"] and result["passed"]


def test_check_iam_least_privilege_flags_wildcards():
    result = checks.check_iam_least_privilege({
        "type": "iam_policy", "policy_actions": ["*"], "policy_resources": ["*"],
    })
    assert result["applicable"] and not result["passed"]


def test_check_patch_currency_respects_sla():
    within_sla = checks.check_patch_currency({
        "type": "host",
        "patch_status": {"days_since_patch_available": 10, "sla_days": 30,
                          "current_version": "1.0", "latest_version": "1.0"},
    })
    assert within_sla["passed"]

    breached_sla = checks.check_patch_currency({
        "type": "host",
        "patch_status": {"days_since_patch_available": 45, "sla_days": 30,
                          "current_version": "1.0", "latest_version": "1.2"},
    })
    assert not breached_sla["passed"]


def test_parse_nftables_default_policy():
    ruleset = """
    table inet filter {
        chain input {
            type filter hook input priority 0; policy drop;
            ct state established,related accept
        }
    }
    """
    assert parse_nftables_default_policy(ruleset, "input") == "drop"
    assert parse_nftables_default_policy(ruleset, "output") is None
