from __future__ import annotations

from .models import Finding, StorageAccount, severity_from_score, stable_finding_id

ATTACK = {
    "public_access": ("T1530 - Data from Cloud Storage",),
    "shared_key": ("T1078.004 - Cloud Accounts", "T1552 - Unsecured Credentials"),
    "transport": ("T1040 - Network Sniffing",),
    "logging": ("T1562.008 - Disable or Modify Cloud Logs",),
    "resilience": ("T1485 - Data Destruction", "T1490 - Inhibit System Recovery"),
    "encryption": ("T1530 - Data from Cloud Storage",),
}

CRITICALITY = {"low": 0, "medium": 5, "high": 10, "critical": 15}


def _risk(account: StorageAccount, base: int) -> int:
    score = base + CRITICALITY[account.business_criticality]
    if account.contains_sensitive_data:
        score += 10
    if account.public_network_access and account.private_endpoint_count == 0:
        score += 8
    return max(0, min(100, score))


def _finding(account: StorageAccount, control: str, base: int, rationale: str,
             remediation: str, mapping: tuple[str, ...]) -> Finding:
    score = _risk(account, base)
    return Finding(
        finding_id=stable_finding_id(account.name, control),
        account=account.name,
        control=control,
        severity=severity_from_score(score),
        score=score,
        rationale=rationale,
        remediation=remediation,
        attack_mapping=mapping,
    )


def assess(account: StorageAccount) -> list[Finding]:
    findings: list[Finding] = []
    if account.allow_blob_public_access:
        findings.append(_finding(account, "blob-public-access", 60,
            "Blob public access is permitted at the account boundary.",
            "Disable account-level blob public access and validate container access policies.",
            ATTACK["public_access"]))
    if account.public_network_access and account.private_endpoint_count == 0:
        findings.append(_finding(account, "public-network-only", 45,
            "The account is reachable through public endpoints with no private endpoint recorded.",
            "Prefer private endpoints and restrict public network access to approved scenarios.",
            ATTACK["public_access"]))
    if account.shared_key_access:
        findings.append(_finding(account, "shared-key-access", 50,
            "Shared Key authorization is enabled, increasing long-lived credential exposure.",
            "Where application compatibility permits, disable Shared Key and use Entra ID with least privilege.",
            ATTACK["shared_key"]))
    if account.minimum_tls_version != "TLS1_2" or not account.https_only:
        findings.append(_finding(account, "transport-protection", 45,
            "Transport settings do not enforce HTTPS with TLS 1.2 as the minimum baseline.",
            "Require secure transfer and set the minimum TLS version to TLS 1.2.",
            ATTACK["transport"]))
    if not account.diagnostic_logging:
        findings.append(_finding(account, "diagnostic-logging", 40,
            "Storage diagnostic logging is not enabled in the supplied configuration evidence.",
            "Enable relevant storage diagnostics and route logs to a governed monitoring destination.",
            ATTACK["logging"]))
    if account.soft_delete_days < 7 or not account.versioning_enabled:
        findings.append(_finding(account, "data-recovery", 50,
            "Recovery controls are below the lab baseline for soft delete and versioning.",
            "Enable versioning and configure soft delete retention of at least seven days based on business requirements.",
            ATTACK["resilience"]))
    if account.contains_sensitive_data and not account.infrastructure_encryption:
        findings.append(_finding(account, "infrastructure-encryption", 35,
            "Sensitive data is present but infrastructure encryption is not enabled.",
            "Evaluate infrastructure encryption for sensitive workloads and document justified exceptions.",
            ATTACK["encryption"]))
    if account.business_criticality == "critical" and not account.customer_managed_key:
        findings.append(_finding(account, "key-governance", 30,
            "A critical workload uses platform-managed keys only in this synthetic baseline.",
            "Evaluate customer-managed keys where regulatory, separation-of-duties, or key-lifecycle requirements apply.",
            ATTACK["encryption"]))
    return findings


def assess_all(accounts: list[StorageAccount]) -> list[Finding]:
    findings = [finding for account in accounts for finding in assess(account)]
    return sorted(findings, key=lambda f: (-f.score, f.account, f.control))
