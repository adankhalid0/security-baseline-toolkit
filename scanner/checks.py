"""
Check functions referenced by baseline.controls.Control.check_name.

Each check takes a single "asset" dict (one entry from the inventory file)
and returns a result dict:

    {
        "applicable": bool,       # False if this control doesn't apply to this asset type
        "passed": bool,           # only meaningful if applicable is True
        "evidence": str,          # short human-readable explanation
        "exposure": str,          # "internet" | "internal_untrusted" | "internal_trusted"
        "impact_override": int,   # optional, overrides the control's default impact
    }

Keeping every check to this same shape is what lets audit.py iterate over
the whole baseline generically instead of special-casing each control.
"""

from __future__ import annotations

from . import network_scanner

SENSITIVE_PORTS = {
    21: "FTP (plaintext)",
    23: "Telnet (plaintext)",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
}

PLAINTEXT_REMOTE_PROTOCOLS = {"telnet", "ftp", "rdp", "vnc", "http"}
ENCRYPTED_REMOTE_PROTOCOLS = {"ssh", "vpn", "wireguard", "ipsec", "tls", "https"}


def _base(applicable: bool, passed: bool, evidence: str, exposure: str = "internal_trusted",
          impact_override: int | None = None) -> dict:
    result = {
        "applicable": applicable,
        "passed": passed,
        "evidence": evidence,
        "exposure": exposure,
    }
    if impact_override is not None:
        result["impact_override"] = impact_override
    return result


def check_mfa_enabled(asset: dict) -> dict:
    if asset.get("type") not in {"host", "identity", "firewall_gateway"}:
        return _base(False, False, "Not applicable to this asset type.")
    mfa = asset.get("mfa_enabled")
    if mfa is None:
        return _base(False, False, "No MFA data reported for this asset.")
    exposure = asset.get("exposure", "internal_trusted")
    return _base(True, bool(mfa),
                 f"mfa_enabled={mfa}", exposure=exposure)


def check_firewall_default_deny(asset: dict) -> dict:
    if asset.get("type") != "firewall_gateway":
        return _base(False, False, "Not applicable to this asset type.")
    ruleset_path = asset.get("nftables_ruleset")
    if not ruleset_path:
        return _base(False, False, "No nftables ruleset provided for this gateway.")
    ruleset_text = network_scanner.load_ruleset(ruleset_path)
    policy = network_scanner.parse_nftables_default_policy(ruleset_text, "input")
    passed = policy == "drop"
    evidence = f"input chain default policy = '{policy}'" if policy else \
        "no explicit policy found on input chain"
    return _base(True, passed, evidence, exposure=asset.get("exposure", "internet"))


def check_segmentation(asset: dict) -> dict:
    if asset.get("type") != "network":
        return _base(False, False, "Not applicable to this asset type.")
    zones = asset.get("zones", [])
    inter_zone_rules = asset.get("inter_zone_rules", [])
    passed = len(zones) >= 2 and len(inter_zone_rules) > 0
    evidence = f"{len(zones)} zone(s) defined, {len(inter_zone_rules)} documented inter-zone rule(s)"
    return _base(True, passed, evidence, exposure="internal_untrusted")


def check_exposed_ports(asset: dict) -> dict:
    if asset.get("type") != "host":
        return _base(False, False, "Not applicable to this asset type.")

    if asset.get("scan_live") and asset.get("ip"):
        candidate_ports = sorted(set(list(SENSITIVE_PORTS) + asset.get("open_ports", [])))
        result = network_scanner.scan_ports(asset["ip"], candidate_ports)
        open_ports = result.open_ports
    else:
        open_ports = asset.get("open_ports", [])

    exposed_sensitive = [p for p in open_ports if p in SENSITIVE_PORTS]
    passed = len(exposed_sensitive) == 0
    if exposed_sensitive:
        names = ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in exposed_sensitive)
        evidence = f"Sensitive port(s) reachable: {names}"
    else:
        evidence = f"No sensitive ports open (checked {sorted(open_ports)})"
    return _base(True, passed, evidence, exposure=asset.get("exposure", "internal_trusted"))


def check_encrypted_remote_access(asset: dict) -> dict:
    if asset.get("type") != "host":
        return _base(False, False, "Not applicable to this asset type.")
    protocol = (asset.get("remote_access_protocol") or "").lower()
    if not protocol:
        return _base(False, False, "No remote access protocol reported.")
    passed = protocol in ENCRYPTED_REMOTE_PROTOCOLS
    evidence = f"remote_access_protocol='{protocol}'"
    return _base(True, passed, evidence, exposure=asset.get("exposure", "internal_trusted"))


def check_logging_enabled(asset: dict) -> dict:
    if "logging_forwarded" not in asset:
        return _base(False, False, "No logging data reported for this asset.")
    passed = bool(asset["logging_forwarded"])
    return _base(True, passed, f"logging_forwarded={asset['logging_forwarded']}",
                 exposure=asset.get("exposure", "internal_trusted"), impact_override=3)


def check_iam_least_privilege(asset: dict) -> dict:
    if asset.get("type") != "iam_policy":
        return _base(False, False, "Not applicable to this asset type.")
    actions = asset.get("policy_actions", [])
    resources = asset.get("policy_resources", [])
    wildcard = "*" in actions or "*" in resources
    passed = not wildcard
    evidence = f"actions={actions}, resources={resources}"
    return _base(True, passed, evidence, exposure="internal_trusted")


def check_patch_currency(asset: dict) -> dict:
    if asset.get("type") != "host":
        return _base(False, False, "Not applicable to this asset type.")
    patch = asset.get("patch_status")
    if not patch:
        return _base(False, False, "No patch status reported.")
    sla_days = patch.get("sla_days", 30)
    days_outstanding = patch.get("days_since_patch_available", 0)
    passed = days_outstanding <= sla_days
    evidence = (f"{days_outstanding} day(s) since patch available "
                f"(SLA {sla_days} days): {patch.get('current_version')} -> "
                f"{patch.get('latest_version')}")
    return _base(True, passed, evidence, exposure=asset.get("exposure", "internal_trusted"))


CHECK_REGISTRY = {
    "check_mfa_enabled": check_mfa_enabled,
    "check_firewall_default_deny": check_firewall_default_deny,
    "check_segmentation": check_segmentation,
    "check_exposed_ports": check_exposed_ports,
    "check_encrypted_remote_access": check_encrypted_remote_access,
    "check_logging_enabled": check_logging_enabled,
    "check_iam_least_privilege": check_iam_least_privilege,
    "check_patch_currency": check_patch_currency,
}
