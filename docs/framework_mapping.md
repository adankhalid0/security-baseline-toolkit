# Framework mapping

Every control in `baseline/controls.py` is mapped to two reference frameworks so
that a single automated check can support reporting against either one:

- **NIST Cybersecurity Framework (CSF) v1.1** — subcategory reference (e.g. `PR.AC-7`)
- **ISO/IEC 27001:2022 Annex A** — control reference (e.g. `A.5.17`)

| Control ID | Title | Category | NIST CSF | ISO 27001 Annex A | Default impact |
|---|---|---|---|---|---|
| AC-01 | Multi-factor authentication enforced | Access Control | PR.AC-7 | A.5.17 / A.8.5 | 5 |
| AC-02 | Least-privilege firewall ingress | Network Security | PR.AC-5 | A.8.20 / A.8.22 | 4 |
| NS-01 | Network segmentation between trust zones | Network Security | PR.AC-5 / PR.PT-4 | A.8.22 | 4 |
| NS-02 | No unnecessary exposed services | Network Security | PR.PT-3 / DE.CM-8 | A.8.9 | 4 |
| DP-01 | Encryption in transit for remote access | Data Protection | PR.DS-2 | A.8.24 | 5 |
| LOG-01 | Centralized logging enabled | Monitoring | DE.CM-1 / DE.AE-3 | A.8.15 | 3 |
| IAM-01 | Least-privilege IAM policies | Identity & Access Management | PR.AC-4 | A.8.2 / A.8.3 | 5 |
| PATCH-01 | Patch currency | Vulnerability Management | ID.RA-1 / PR.IP-12 | A.8.8 | 4 |

## Why map to two frameworks instead of one

Different organizations standardize on different frameworks — some run an ISO
27001 ISMS, others use NIST CSF as their primary reference (often because a
regulator or customer requires it), and many maintain a mapping between the
two anyway. Tagging each control with both means the same automated check
produces evidence that's directly usable in either an ISO surveillance audit
or a NIST-CSF-structured risk report, without maintaining two separate
control sets.

## Risk scoring model (ISO 31000-style)

Every **failed** control becomes a finding. Its risk score is:

```
risk_score = likelihood (1-5) x impact (1-5)
```

- **Impact** comes from the control's `default_impact` (how bad it is if this
  specific control is missing — e.g. missing MFA is impact 5, missing
  centralized logging alone is impact 3).
- **Likelihood** comes from the asset's network exposure at the time of the
  finding — internet-facing is likelihood 5, an internal-but-untrusted
  segment is 4, an internal-trusted segment is 2.

| Score range | Risk level |
|---|---|
| 1 – 4 | Low |
| 5 – 9 | Medium |
| 10 – 16 | High |
| 17 – 25 | Critical |

This keeps the model simple enough to defend in a review ("why is this
Critical and that one only Medium?") while still differentiating a
misconfiguration on an internet-facing gateway from the same gap on an
isolated internal host.
