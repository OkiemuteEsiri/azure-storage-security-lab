# Architecture and Methodology

## Objective

This project demonstrates an offline security-engineering review of Azure Storage configuration evidence. It is designed for safe portfolio use: no subscription credentials, Azure SDK calls, production resources, or destructive changes are required.

## Architecture

```text
Synthetic / exported JSON
        |
        v
  Fail-closed loader
        |
        v
 Normalized StorageAccount model
        |
        v
 Control assessment + contextual risk engine
        |
        +--> prioritized findings
        |       |
        |       +--> MITRE ATT&CK threat context
        |       +--> remediation guidance
        |
        v
 Markdown reporting

Remediation evidence --> closure validator --> validated / needs_evidence / invalid_closure
```

## Trust boundaries

1. **Input evidence boundary** — JSON is treated as untrusted evidence and rejected if fields are missing, duplicated, mistyped, or unsupported.
2. **Assessment boundary** — the engine evaluates supplied state only. It does not infer that a control exists when evidence is absent.
3. **Threat-context boundary** — ATT&CK mappings describe why a weakness matters; they do not state that compromise occurred.
4. **Remediation boundary** — closure requires evidence of the change and post-change validation, not a ticket status alone.

## Control domains

| Domain | Defensive question |
|---|---|
| Public exposure | Can blobs or the storage endpoint be reached more broadly than intended? |
| Authorization | Is Shared Key still enabled where identity-based authorization could be used? |
| Transport | Is HTTPS enforced with TLS 1.2 as the minimum baseline? |
| Monitoring | Is diagnostic evidence available for investigation and assurance? |
| Recovery | Are versioning and deletion-recovery controls sufficient for the lab baseline? |
| Encryption | Are enhanced encryption/key-governance controls justified for sensitive workloads? |

## Contextual risk model

The model intentionally avoids presenting a cloud configuration check as a universal severity. A base control risk is modified by:

- business criticality;
- whether sensitive data is present;
- whether public network access is enabled without a recorded private endpoint.

Scores are bounded to 0–100 and translated to Low, Medium, High, or Critical. The model is transparent and deterministic so a reviewer can challenge individual assumptions.

## Remediation lifecycle

1. Record accountable owner and change reference.
2. Capture the vulnerable configuration state.
3. Implement the least-disruptive secure configuration consistent with application requirements.
4. Capture the resulting configuration state.
5. Validate the intended control outcome.
6. Confirm monitoring remains functional.
7. Close only when evidence is complete and validation succeeds.

## MITRE ATT&CK context

Mappings used in the project include T1530 (Data from Cloud Storage), T1078.004 (Cloud Accounts), T1552 (Unsecured Credentials), T1040 (Network Sniffing), T1562.008 (Disable or Modify Cloud Logs), T1485 (Data Destruction), and T1490 (Inhibit System Recovery). These are defensive analytical mappings only.

## Limitations

- This is not a replacement for Azure Policy, Defender for Cloud, Resource Graph, or a formal cloud security posture management platform.
- The sample data does not model every Storage service, networking exception, legal hold, RBAC assignment, SAS token, firewall rule, private DNS dependency, or lifecycle policy.
- Customer-managed keys are intentionally treated as context-dependent rather than universally required.
- A production implementation should ingest authoritative Azure configuration and policy state through an approved identity with least privilege.
