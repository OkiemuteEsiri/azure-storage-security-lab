from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

VALID_CRITICALITY = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class StorageAccount:
    name: str
    resource_group: str
    kind: str
    public_network_access: bool
    allow_blob_public_access: bool
    shared_key_access: bool
    minimum_tls_version: str
    https_only: bool
    infrastructure_encryption: bool
    private_endpoint_count: int
    diagnostic_logging: bool
    soft_delete_days: int
    versioning_enabled: bool
    immutable_storage: bool
    customer_managed_key: bool
    business_criticality: str
    contains_sensitive_data: bool

    def validate(self) -> None:
        if not self.name or not self.resource_group:
            raise ValueError("storage account name and resource group are required")
        if self.business_criticality not in VALID_CRITICALITY:
            raise ValueError(f"unsupported business criticality: {self.business_criticality}")
        if self.private_endpoint_count < 0:
            raise ValueError("private_endpoint_count cannot be negative")
        if self.soft_delete_days < 0:
            raise ValueError("soft_delete_days cannot be negative")
        if self.minimum_tls_version not in {"TLS1_0", "TLS1_1", "TLS1_2"}:
            raise ValueError(f"unsupported minimum TLS version: {self.minimum_tls_version}")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    account: str
    control: str
    severity: str
    score: int
    rationale: str
    remediation: str
    attack_mapping: tuple[str, ...]


def stable_finding_id(account: str, control: str) -> str:
    digest = sha256(f"{account}|{control}".encode()).hexdigest()[:12]
    return f"AZST-{digest.upper()}"


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def metrics(findings: Iterable[Finding]) -> dict[str, int]:
    items = list(findings)
    return {
        "total": len(items),
        "critical": sum(f.severity == "critical" for f in items),
        "high": sum(f.severity == "high" for f in items),
        "medium": sum(f.severity == "medium" for f in items),
        "low": sum(f.severity == "low" for f in items),
    }
