from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RemediationEvidence:
    finding_id: str
    change_reference: str
    accountable_owner: str
    configuration_before: str
    configuration_after: str
    validation_method: str
    validation_result: str
    monitoring_confirmed: bool


def validate_closure(evidence: RemediationEvidence) -> tuple[str, tuple[str, ...]]:
    missing: list[str] = []
    for field in (
        "finding_id", "change_reference", "accountable_owner", "configuration_before",
        "configuration_after", "validation_method", "validation_result",
    ):
        if not getattr(evidence, field).strip():
            missing.append(field)
    if missing:
        return "needs_evidence", tuple(missing)
    if evidence.configuration_before.strip() == evidence.configuration_after.strip():
        return "invalid_closure", ("configuration_state_unchanged",)
    if evidence.validation_result.strip().lower() not in {"pass", "passed", "success", "successful"}:
        return "invalid_closure", ("validation_not_successful",)
    if not evidence.monitoring_confirmed:
        return "needs_evidence", ("monitoring_confirmed",)
    return "validated", ()
