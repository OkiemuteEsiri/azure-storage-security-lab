from __future__ import annotations

import json
from pathlib import Path

from .models import StorageAccount

REQUIRED_FIELDS = {
    "name", "resource_group", "kind", "public_network_access",
    "allow_blob_public_access", "shared_key_access", "minimum_tls_version",
    "https_only", "infrastructure_encryption", "private_endpoint_count",
    "diagnostic_logging", "soft_delete_days", "versioning_enabled",
    "immutable_storage", "customer_managed_key", "business_criticality",
    "contains_sensitive_data",
}


def load_accounts(path: str | Path) -> list[StorageAccount]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("input must be a JSON array")

    accounts: list[StorageAccount] = []
    seen: set[str] = set()
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"record {index} must be an object")
        missing = REQUIRED_FIELDS - set(item)
        if missing:
            raise ValueError(f"record {index} missing fields: {sorted(missing)}")
        unknown = set(item) - REQUIRED_FIELDS
        if unknown:
            raise ValueError(f"record {index} contains unsupported fields: {sorted(unknown)}")
        for field in (
            "public_network_access", "allow_blob_public_access", "shared_key_access",
            "https_only", "infrastructure_encryption", "diagnostic_logging",
            "versioning_enabled", "immutable_storage", "customer_managed_key",
            "contains_sensitive_data",
        ):
            if type(item[field]) is not bool:
                raise ValueError(f"record {index} field {field} must be boolean")
        if type(item["private_endpoint_count"]) is not int or type(item["soft_delete_days"]) is not int:
            raise ValueError(f"record {index} numeric controls must be integers")
        account = StorageAccount(**item)
        account.validate()
        key = account.name.lower()
        if key in seen:
            raise ValueError(f"duplicate storage account: {account.name}")
        seen.add(key)
        accounts.append(account)
    return accounts
