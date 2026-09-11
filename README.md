# Azure Storage Security Lab

Recruiter-facing **Cloud Security / Security Engineering** project that evaluates Azure Storage configuration evidence offline, prioritizes weaknesses with transparent contextual risk scoring, produces remediation guidance, and validates closure evidence.

The project is intentionally defensive. It does **not** connect to Azure, enumerate subscriptions, use credentials, alter cloud resources, or claim activity against a production tenant. All included data is fictional.

## Problem statement

Storage services frequently combine data sensitivity, broad network reachability, long-lived authorization mechanisms, weak monitoring, and incomplete recovery controls. A useful cloud-security review must do more than list configuration deviations: it should validate evidence, explain business impact, prioritize remediation, and define what technically constitutes closure.

This lab demonstrates that workflow using a deterministic Python implementation and synthetic Azure Storage configuration data.

## Architecture

```text
Synthetic / approved configuration evidence
                 |
                 v
         fail-closed JSON loader
                 |
                 v
        normalized domain model
                 |
                 v
       control assessment engine
                 |
        +--------+---------+
        |                  |
        v                  v
 contextual risk      MITRE ATT&CK
    scoring             context
        |                  |
        +--------+---------+
                 v
       prioritized findings
                 |
                 v
        Markdown reporting

remediation evidence --> closure validator --> validated / needs_evidence / invalid_closure
```

## Repository structure

```text
.github/workflows/security-quality.yml  Least-privilege CI checks
data/synthetic_storage_accounts.json    Fictional Azure Storage evidence
docs/architecture-and-methodology.md    Architecture, trust boundaries, methodology
reports/example-assessment.md            Recruiter-facing sample output
src/models.py                            Domain models, stable IDs, metrics
src/loader.py                            Strict evidence ingestion
src/assessor.py                          Control checks + contextual scoring
src/remediation.py                       Closure evidence validation
src/reporting.py                         Markdown report generation
src/cli.py                               Offline CLI
tests/test_assessment.py                 Unit tests
```

## Security controls assessed

| Control area | Assessment intent | Example impact |
|---|---|---|
| Blob public access | Detect account-level public blob capability | Unintended data exposure |
| Network exposure | Identify public reachability without a recorded private endpoint | Expanded attack surface |
| Shared Key | Identify long-lived account-key authorization | Credential compromise / excessive privilege |
| Transport security | Require HTTPS and TLS 1.2 lab baseline | Weak transport protection |
| Diagnostic logging | Require investigation/assurance evidence | Reduced detection and forensic visibility |
| Recovery controls | Review versioning and soft-delete baseline | Data loss / destructive-event impact |
| Infrastructure encryption | Add context for sensitive workloads | Defense-in-depth gap |
| Key governance | Review CMK need for critical workloads | Separation-of-duties / regulatory gap |

The controls are deliberately opinionated but transparent. For example, customer-managed keys are **not** treated as universally mandatory; the finding is generated only for critical synthetic workloads and is worded as an evaluation requirement rather than a blanket compliance statement.

## Contextual risk model

Each control has a documented base risk. The engine then applies contextual modifiers for:

- business criticality;
- presence of sensitive data;
- public network exposure without a private endpoint.

The final score is bounded to **0–100** and mapped to:

- **Critical:** 80–100
- **High:** 60–79
- **Medium:** 35–59
- **Low:** 0–34

This provides a repeatable prioritization mechanism without pretending that a configuration setting has the same business impact in every environment.

## MITRE ATT&CK mapping

The project uses ATT&CK strictly as **defensive threat context**. Mappings include:

- **T1530 — Data from Cloud Storage**
- **T1078.004 — Valid Accounts: Cloud Accounts**
- **T1552 — Unsecured Credentials**
- **T1040 — Network Sniffing**
- **T1562.008 — Impair Defenses: Disable or Modify Cloud Logs**
- **T1485 — Data Destruction**
- **T1490 — Inhibit System Recovery**

A mapping means a control weakness is relevant to the technique. It does not mean the technique occurred.

## Usage

Requirements: Python 3.11+; the project uses only the standard library.

Run the synthetic assessment:

```bash
python -m src.cli data/synthetic_storage_accounts.json --output reports/generated-assessment.md
```

Run the unit suite:

```bash
python -m unittest discover -s tests -v
```

The CLI writes a Markdown report containing executive metrics, prioritized findings, risk rationale, remediation guidance, ATT&CK context, and closure expectations.

## Fail-closed evidence handling

`src/loader.py` treats configuration evidence as untrusted input. It rejects:

- missing required fields;
- unsupported extra fields;
- duplicate storage account records;
- string values masquerading as booleans;
- malformed integer controls;
- unsupported business-criticality values;
- negative private-endpoint or retention values;
- unsupported TLS baselines.

This avoids silently converting malformed evidence into apparently valid security conclusions.

## Remediation and validation workflow

The project separates **finding creation** from **closure validation**. A remediation record is only considered validated when it contains:

1. a finding identifier;
2. accountable owner;
3. change reference;
4. before-state evidence;
5. after-state evidence showing an actual state change;
6. validation method;
7. successful validation result;
8. confirmation that monitoring remains operational.

Possible closure states are `validated`, `needs_evidence`, and `invalid_closure`.

This models a practical vulnerability/security-engineering principle: implementation activity is not equivalent to verified risk reduction.

## Example synthetic outcome

The included fictional dataset intentionally mixes secure and weak configurations. The sample report highlights a high-criticality archive workload with public blob access, Shared Key authorization, weak transport settings, missing logging, and weak recovery controls. A second critical synthetic workload is largely hardened but retains Shared Key and lacks a customer-managed-key decision record. The third synthetic workload demonstrates a comparatively stronger baseline.

See [`reports/example-assessment.md`](reports/example-assessment.md) for the recruiter-facing example.

## CI/CD security checks

The GitHub Actions workflow uses only:

```yaml
permissions:
  contents: read
```

It performs:

1. Python compilation checks;
2. unit-test discovery and execution;
3. an offline synthetic assessment smoke test;
4. simple validation that the generated report contains ATT&CK and validation-workflow markers.

No cloud credentials or repository write permissions are required by the workflow.

## Design decisions

**Offline by default.** Portfolio users can inspect and execute the project safely without a cloud subscription.

**Deterministic output.** Finding IDs are SHA-256-derived from the storage account and control identifier; repeated assessment of identical evidence produces stable IDs.

**Context before severity.** Findings are prioritized using data sensitivity and business/network context instead of treating every failed check as equally urgent.

**Explicit limitations.** The project does not attempt to reproduce Defender for Cloud, Azure Policy, or a CSPM platform.

**Evidence-driven closure.** The validator prevents remediation claims from being accepted merely because a configuration ticket exists.

## Skills demonstrated

- Azure Storage security architecture
- cloud attack-surface reduction
- identity-first authorization concepts
- security control design
- configuration evidence validation
- risk-based prioritization
- secure Python engineering
- deterministic finding generation
- automated reporting
- remediation governance
- validation/retest methodology
- MITRE ATT&CK contextual mapping
- unit testing
- least-privilege CI/CD design

## Limitations

This lab evaluates a deliberately constrained evidence model. It does not currently model every Azure Storage firewall rule, SAS token, RBAC assignment, lifecycle-management policy, private DNS dependency, legal hold, object replication rule, cross-tenant configuration, Defender setting, or service-specific diagnostic category.

A production implementation should ingest authoritative configuration through an approved, least-privileged identity and reconcile results against organization-specific Azure Policy, data-classification, regulatory, and exception-management requirements.

## Roadmap

- Add RBAC and SAS-token governance models.
- Model storage firewall rules and approved service endpoints.
- Add policy-exception objects with expiry and accountable ownership.
- Add control coverage for immutability/legal-hold governance.
- Produce JSON output for downstream SIEM/GRC workflows.
- Add trend comparison between two configuration snapshots.
- Add Azure Resource Graph import as an optional, read-only integration while keeping offline fixtures for safe testing.

## Safety and data handling

All names, resource groups, findings, and configuration values in this repository are synthetic. There are no Azure credentials, production resource identifiers, employer/client records, access tokens, secrets, exploit payloads, or destructive automation.

## License

This repository is provided as a defensive cybersecurity portfolio project. Add an explicit open-source license before reuse outside the portfolio if required.
