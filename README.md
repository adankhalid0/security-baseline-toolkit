# Security Baseline & Risk Assessment Toolkit

A small, working toolkit that automates the loop most security teams do
manually: **define a baseline → check assets against it → score the gaps as
risk → report, with a suggested compensating control for each finding.**

It checks a sample inventory of network and cloud assets (firewall gateway,
segmented network, hosts, IAM policies) against eight baseline controls
mapped to **NIST CSF** and **ISO/IEC 27001**, scores every failed control
using a likelihood × impact model in the spirit of **ISO 31000**, and
produces a Markdown risk report. A companion **Terraform** module shows the
same baseline enforced as infrastructure-as-code instead of checked after
the fact.

I built this to tie together the parts of security I find most interesting:
network segmentation and firewalling, cloud IAM, and structured risk
assessment against recognized frameworks — rather than treating each as a
separate, disconnected exercise.

## Why this design

A lot of "baseline compliance" work in practice is either a static
spreadsheet nobody updates, or a fully automated scanner that produces a
wall of findings with no sense of priority. This toolkit is a small
demonstration of a middle path:

- **Centralized baseline.** Controls live in one place (`baseline/controls.py`),
  each mapped to a framework reference and a default impact — so "what do we
  require" is separate from "how do we check it."
- **Pragmatic checks.** Every check is a plain Python function against a
  structured asset record. No control is checked unless it actually applies
  to that asset type (`applicable: false` is skipped, not scored) — the goal
  is to avoid the "risk-assess everything, even the obvious" trap.
- **Risk, not just pass/fail.** A failed control isn't just "red" — it gets a
  likelihood × impact score based on how exposed the asset actually is, so a
  missing control on an internet-facing gateway is rated very differently
  from the same gap on an isolated internal host.
- **Every finding ships with a next step.** Each control carries a suggested
  compensating control, so the report is something an engineer can act on,
  not just a list of failures.

## Quick start

```bash
git clone <this-repo>
cd security-baseline-toolkit
pip install -r requirements.txt

# Run the audit against the sample inventory
python audit.py

# See it
cat report.md
```

Example run:

```
$ python audit.py
Evaluated inventory: examples/sample_inventory.yaml
Controls passed: 10
Findings: 6
Report written to: report.md
```

A sample of the generated report is committed at
[`examples/sample_report.md`](examples/sample_report.md) — it flags a
deliberately mis-configured legacy host (no MFA, RDP exposed to an untrusted
segment, no logging, patches 92 days overdue) and an over-permissive IAM
policy (`Action: "*", Resource: "*"`) as Critical/High, while a properly
configured host and a scoped IAM policy pass cleanly.

Run the tests:

```bash
pytest -q
```

## Project layout

```
baseline/
  controls.py       Baseline control definitions (NIST CSF + ISO 27001 mapping, default impact)
  risk.py            Likelihood x impact risk scoring (ISO 31000-style)
scanner/
  checks.py          One check function per control
  network_scanner.py Real TCP connect-scan + nftables ruleset parser
  inventory.py        Loads the YAML asset inventory
reports/
  report_generator.py Renders findings as a Markdown report
examples/
  sample_inventory.yaml          Sample assets (firewall, network, hosts, IAM policies)
  sample_nftables_ruleset.conf   Sample firewall ruleset the check parses
  sample_report.md               A committed example of the generated output
terraform/
  main.tf / variables.tf / outputs.tf   Baseline network expressed as IaC
docs/
  framework_mapping.md   Full control-to-framework mapping table and scoring model
tests/
  test_checks.py     Unit tests for the risk engine and the checks
audit.py             CLI entrypoint
```

## What the baseline actually checks

| ID | Control | Framework mapping |
|---|---|---|
| AC-01 | MFA enforced | NIST PR.AC-7 / ISO A.5.17 |
| AC-02 | Least-privilege firewall ingress (default-deny) | NIST PR.AC-5 / ISO A.8.20 |
| NS-01 | Network segmentation between trust zones | NIST PR.PT-4 / ISO A.8.22 |
| NS-02 | No unnecessary exposed services (Telnet/RDP/SMB etc.) | NIST PR.PT-3 / ISO A.8.9 |
| DP-01 | Encrypted remote access (no plaintext protocols) | NIST PR.DS-2 / ISO A.8.24 |
| LOG-01 | Centralized logging | NIST DE.CM-1 / ISO A.8.15 |
| IAM-01 | Least-privilege IAM policies (no wildcards) | NIST PR.AC-4 / ISO A.8.2 |
| PATCH-01 | Patch currency against SLA | NIST ID.RA-1 / ISO A.8.8 |

Full detail, including the risk scoring model, is in
[`docs/framework_mapping.md`](docs/framework_mapping.md).

## The network scanner is real, not mocked

`scanner/network_scanner.py` does an actual TCP connect-scan
(`socket.connect_ex`) and a real regex-based parse of an nftables ruleset —
the same technique used in my
[Network Security Lab](https://github.com/adankhalid0) project, where I set
up a segmented Docker network behind an nftables gateway. By default the
sample inventory uses recorded port data (so the demo is reproducible
without a live target), but `scan_live: true` + an `ip` in the inventory
will make `check_exposed_ports` scan that host for real.

## Terraform: the baseline as infrastructure-as-code

`terraform/` provisions a small AWS network — a VPC with separate production
and management subnets, a management security group scoped to a single admin
CIDR (never `0.0.0.0/0`), and VPC Flow Logs shipped to CloudWatch — so that
AC-02, NS-01, and LOG-01 are enforced by the infrastructure definition itself
rather than caught later by an audit. It hasn't been applied against a live
AWS account (no state file or credentials are part of this repo); run
`terraform init && terraform validate` and review the plan before ever
applying it anywhere.

## Limitations / honest scope

This is a portfolio project, not a production compliance platform:

- The control set (8 controls) is a representative sample, not a full
  NIST CSF or ISO 27001 catalog.
- The risk model is a simple 5x5 matrix, chosen for explainability over
  precision — it does not account for compensating controls already in
  place, threat intelligence, or asset criticality beyond exposure.
- The inventory is static YAML for the demo; a real deployment would pull
  asset state from a CMDB, cloud provider APIs, or a CSPM tool instead of a
  hand-maintained file.

## License

MIT — see [LICENSE](LICENSE).
