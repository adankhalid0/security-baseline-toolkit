# Security Baseline Audit Report

Generated: 2026-09-28 13:58 UTC

## Summary

- Assets evaluated: **6**
- Controls passed: **10**
- Findings (failed controls): **6**
  - Critical: 2  ·  High: 4  ·  Medium: 0  ·  Low: 0

## Findings

| Risk | Control | Asset | Framework mapping | Evidence | Compensating control |
|---|---|---|---|---|---|
| **Critical** (20) | AC-01 — Multi-factor authentication enforced | legacy-host-02 | NIST PR.AC-7 / ISO A.5.17 / A.8.5 | mfa_enabled=False | Enforce MFA via IdP conditional access policy; restrict non-MFA accounts to break-glass use only, with logging. |
| **Critical** (20) | DP-01 — Encryption in transit for remote access | legacy-host-02 | NIST PR.DS-2 / ISO A.8.24 | remote_access_protocol='rdp' | Require IPsec/WireGuard VPN or TLS for all remote administrative access; disable plaintext protocols (Telnet, FTP). |
| **High** (16) | NS-02 — No unnecessary exposed services | legacy-host-02 | NIST PR.PT-3 / DE.CM-8 / ISO A.8.9 | Sensitive port(s) reachable: 23/Telnet (plaintext), 3389/RDP, 445/SMB | Close or firewall off non-essential ports; place any required management interface behind a VPN or bastion host. |
| **High** (12) | LOG-01 — Centralized logging enabled | legacy-host-02 | NIST DE.CM-1 / DE.AE-3 / ISO A.8.15 | logging_forwarded=False | Forward logs to a central SIEM/log store with retention aligned to policy; alert on repeated auth failures. |
| **High** (16) | PATCH-01 — Patch currency | legacy-host-02 | NIST ID.RA-1 / PR.IP-12 / ISO A.8.8 | 92 day(s) since patch available (SLA 30 days): 2.1.0 -> 2.6.0 | Apply outstanding patches within SLA, or document a time-boxed risk acceptance with compensating monitoring. |
| **High** (10) | IAM-01 — Least-privilege IAM policies | iam-role-deploy | NIST PR.AC-4 / ISO A.8.2 / A.8.3 | actions=['*'], resources=['*'] | Replace wildcard IAM policies with scoped permissions per role; review quarterly against actual usage (IAM Access Analyzer). |

## Controls passed

| Control | Asset | Framework mapping | Evidence |
|---|---|---|---|
| AC-01 — Multi-factor authentication enforced | fw-gw-01 | NIST PR.AC-7 / ISO A.5.17 / A.8.5 | mfa_enabled=True |
| AC-02 — Least-privilege firewall ingress | fw-gw-01 | NIST PR.AC-5 / ISO A.8.20 / A.8.22 | input chain default policy = 'drop' |
| LOG-01 — Centralized logging enabled | fw-gw-01 | NIST DE.CM-1 / DE.AE-3 / ISO A.8.15 | logging_forwarded=True |
| NS-01 — Network segmentation between trust zones | corp-network | NIST PR.AC-5 / PR.PT-4 / ISO A.8.22 | 3 zone(s) defined, 2 documented inter-zone rule(s) |
| AC-01 — Multi-factor authentication enforced | app-server-01 | NIST PR.AC-7 / ISO A.5.17 / A.8.5 | mfa_enabled=True |
| NS-02 — No unnecessary exposed services | app-server-01 | NIST PR.PT-3 / DE.CM-8 / ISO A.8.9 | No sensitive ports open (checked [22, 443]) |
| DP-01 — Encryption in transit for remote access | app-server-01 | NIST PR.DS-2 / ISO A.8.24 | remote_access_protocol='ssh' |
| LOG-01 — Centralized logging enabled | app-server-01 | NIST DE.CM-1 / DE.AE-3 / ISO A.8.15 | logging_forwarded=True |
| PATCH-01 — Patch currency | app-server-01 | NIST ID.RA-1 / PR.IP-12 / ISO A.8.8 | 0 day(s) since patch available (SLA 30 days): 3.4.1 -> 3.4.1 |
| IAM-01 — Least-privilege IAM policies | iam-role-readonly | NIST PR.AC-4 / ISO A.8.2 / A.8.3 | actions=['s3:GetObject', 'logs:Describe*'], resources=['arn:aws:s3:::reports-bucket/*'] |

## Method

Each control is checked automatically against the asset inventory. A failed control becomes a finding, rated with a likelihood x impact score (1-5 x 1-5, ISO 31000-style) based on the asset's network exposure and the control's default impact. Findings are sorted by risk level, highest first, so remediation effort goes where it matters most instead of being applied evenly across every gap.
