"""
Baseline security controls.

Each control represents a single, checkable security requirement, mapped to:
  - NIST Cybersecurity Framework (CSF v1.1) subcategory
  - ISO/IEC 27001:2022 Annex A control
  - A default impact rating (1-5) used by the risk engine if the control fails

The control set here is deliberately small and readable -- it is meant to
demonstrate the *method* (centralized baseline -> automated check -> risk
scoring -> compensating control), not to be an exhaustive compliance catalog.
"""

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Control:
    control_id: str
    title: str
    description: str
    nist_csf: str          # e.g. "PR.AC-1"
    iso27001: str          # e.g. "A.9.2.1"
    category: str          # human-readable grouping (Access Control, Network, ...)
    default_impact: int    # 1 (negligible) - 5 (severe), used if control fails
    check_name: str        # name of the check function in scanner.checks
    compensating_control: str  # suggested mitigation if the check fails


BASELINE: list[Control] = [
    Control(
        control_id="AC-01",
        title="Multi-factor authentication enforced",
        description="All administrative and remote-access accounts must require MFA.",
        nist_csf="PR.AC-7",
        iso27001="A.5.17 / A.8.5",
        category="Access Control",
        default_impact=5,
        check_name="check_mfa_enabled",
        compensating_control="Enforce MFA via IdP conditional access policy; restrict "
                              "non-MFA accounts to break-glass use only, with logging.",
    ),
    Control(
        control_id="AC-02",
        title="Least-privilege firewall ingress",
        description="Only explicitly required ports/services are reachable from outside "
                    "the trust zone; default policy is deny.",
        nist_csf="PR.AC-5",
        iso27001="A.8.20 / A.8.22",
        category="Network Security",
        default_impact=4,
        check_name="check_firewall_default_deny",
        compensating_control="Set default INPUT/FORWARD policy to DROP and add explicit "
                              "allow rules per required service only.",
    ),
    Control(
        control_id="NS-01",
        title="Network segmentation between trust zones",
        description="Production, management, and guest/user networks are placed in "
                    "separate segments with controlled inter-zone routing.",
        nist_csf="PR.AC-5 / PR.PT-4",
        iso27001="A.8.22",
        category="Network Security",
        default_impact=4,
        check_name="check_segmentation",
        compensating_control="Introduce VLANs or equivalent segmentation and restrict "
                              "inter-zone traffic to a documented allow-list.",
    ),
    Control(
        control_id="NS-02",
        title="No unnecessary exposed services",
        description="Hosts do not expose management or debug ports (e.g. Telnet, RDP, "
                    "unauthenticated admin panels) to untrusted networks.",
        nist_csf="PR.PT-3 / DE.CM-8",
        iso27001="A.8.9",
        category="Network Security",
        default_impact=4,
        check_name="check_exposed_ports",
        compensating_control="Close or firewall off non-essential ports; place any "
                              "required management interface behind a VPN or bastion host.",
    ),
    Control(
        control_id="DP-01",
        title="Encryption in transit for remote access",
        description="Remote access to internal systems uses an encrypted, authenticated "
                    "tunnel (e.g. VPN, IPsec, TLS) rather than a plaintext protocol.",
        nist_csf="PR.DS-2",
        iso27001="A.8.24",
        category="Data Protection",
        default_impact=5,
        check_name="check_encrypted_remote_access",
        compensating_control="Require IPsec/WireGuard VPN or TLS for all remote "
                              "administrative access; disable plaintext protocols (Telnet, FTP).",
    ),
    Control(
        control_id="LOG-01",
        title="Centralized logging enabled",
        description="Security-relevant events (auth attempts, firewall denies, config "
                    "changes) are forwarded to a central, tamper-resistant log store.",
        nist_csf="DE.CM-1 / DE.AE-3",
        iso27001="A.8.15",
        category="Monitoring",
        default_impact=3,
        check_name="check_logging_enabled",
        compensating_control="Forward logs to a central SIEM/log store with retention "
                              "aligned to policy; alert on repeated auth failures.",
    ),
    Control(
        control_id="IAM-01",
        title="Least-privilege IAM policies",
        description="Cloud/service accounts are scoped to the minimum permissions "
                    "required for their function (no wildcard '*' actions/resources).",
        nist_csf="PR.AC-4",
        iso27001="A.8.2 / A.8.3",
        category="Identity & Access Management",
        default_impact=5,
        check_name="check_iam_least_privilege",
        compensating_control="Replace wildcard IAM policies with scoped permissions per "
                              "role; review quarterly against actual usage (IAM Access Analyzer).",
    ),
    Control(
        control_id="PATCH-01",
        title="Patch currency",
        description="Systems are on a supported, patched version within the "
                    "organization's patch SLA.",
        nist_csf="ID.RA-1 / PR.IP-12",
        iso27001="A.8.8",
        category="Vulnerability Management",
        default_impact=4,
        check_name="check_patch_currency",
        compensating_control="Apply outstanding patches within SLA, or document a "
                              "time-boxed risk acceptance with compensating monitoring.",
    ),
]


def get_control(control_id: str) -> Optional[Control]:
    return next((c for c in BASELINE if c.control_id == control_id), None)
