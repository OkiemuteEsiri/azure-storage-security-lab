# Example Azure Storage Security Assessment

> Fictional portfolio output generated from `data/synthetic_storage_accounts.json`. It does not describe a real Azure tenant.

## Executive summary

The synthetic evidence produced **9 findings**. The highest-risk condition is account-level blob public access on a sensitive, high-criticality storage account that is also reachable through the public network. Shared Key access and weak recovery controls materially increase the remediation priority of that same workload.

## Prioritized findings

| Storage account | Control | Score | Risk |
|---|---|---:|---|
| stpublicarchive01 | blob-public-access | 88 | Critical |
| stpublicarchive01 | shared-key-access | 78 | High |
| stpublicarchive01 | data-recovery | 78 | High |
| stfinanceprod02 | shared-key-access | 75 | High |
| stpublicarchive01 | public-network-only | 73 | High |
| stpublicarchive01 | transport-protection | 73 | High |
| stpublicarchive01 | diagnostic-logging | 68 | High |
| stpublicarchive01 | infrastructure-encryption | 63 | High |
| stfinanceprod02 | key-governance | 55 | Medium |

## Remediation sequence

1. Disable blob public access on `stpublicarchive01` after validating application dependencies.
2. Restrict network reachability and introduce an approved private-access pattern where operationally suitable.
3. Migrate supported workloads from Shared Key to Entra ID authorization with least privilege.
4. Enforce secure transfer and TLS 1.2.
5. Enable diagnostic logging and validate delivery to the monitoring destination.
6. Enable versioning and recovery retention appropriate to the workload.
7. Evaluate enhanced encryption/key-governance controls for sensitive and critical workloads based on policy and regulatory requirements.

## Validation evidence expected

Closure should retain the change reference, owner, before/after configuration evidence, successful post-change validation, and confirmation that monitoring continues to operate. A remediation ticket marked complete without technical evidence is not sufficient.

## ATT&CK context

Relevant defensive mappings include T1530 (Data from Cloud Storage), T1078.004 (Cloud Accounts), T1552 (Unsecured Credentials), T1040 (Network Sniffing), T1562.008 (Disable or Modify Cloud Logs), T1485 (Data Destruction), and T1490 (Inhibit System Recovery). These mappings describe threat relevance only; they do not indicate observed malicious activity.
