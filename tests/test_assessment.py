import json
import tempfile
import unittest
from pathlib import Path

from src.assessor import assess, assess_all
from src.loader import load_accounts
from src.models import StorageAccount, metrics, stable_finding_id
from src.remediation import RemediationEvidence, validate_closure
from src.reporting import render_markdown


def secure_account(**overrides):
    data = dict(
        name="stsecure01", resource_group="rg-demo", kind="StorageV2",
        public_network_access=False, allow_blob_public_access=False,
        shared_key_access=False, minimum_tls_version="TLS1_2", https_only=True,
        infrastructure_encryption=True, private_endpoint_count=1,
        diagnostic_logging=True, soft_delete_days=14, versioning_enabled=True,
        immutable_storage=True, customer_managed_key=True,
        business_criticality="high", contains_sensitive_data=True,
    )
    data.update(overrides)
    return StorageAccount(**data)


class AssessmentTests(unittest.TestCase):
    def test_secure_account_has_no_findings(self):
        self.assertEqual(assess(secure_account()), [])

    def test_public_blob_access_is_prioritized(self):
        findings = assess(secure_account(allow_blob_public_access=True, public_network_access=True, private_endpoint_count=0))
        controls = {f.control for f in findings}
        self.assertIn("blob-public-access", controls)
        self.assertIn("public-network-only", controls)

    def test_sensitive_context_increases_risk(self):
        sensitive = assess(secure_account(name="a", shared_key_access=True, contains_sensitive_data=True))[0]
        nonsensitive = assess(secure_account(name="b", shared_key_access=True, contains_sensitive_data=False))[0]
        self.assertGreater(sensitive.score, nonsensitive.score)

    def test_scores_are_bounded(self):
        findings = assess(secure_account(allow_blob_public_access=True, public_network_access=True, private_endpoint_count=0, business_criticality="critical"))
        self.assertTrue(all(0 <= f.score <= 100 for f in findings))

    def test_finding_id_is_deterministic(self):
        self.assertEqual(stable_finding_id("acct", "control"), stable_finding_id("acct", "control"))

    def test_assess_all_sorts_highest_risk_first(self):
        findings = assess_all([
            secure_account(name="lower", diagnostic_logging=False, contains_sensitive_data=False, business_criticality="low"),
            secure_account(name="higher", allow_blob_public_access=True, public_network_access=True, private_endpoint_count=0, business_criticality="critical"),
        ])
        self.assertGreaterEqual(findings[0].score, findings[-1].score)

    def test_metrics_count_severity(self):
        findings = assess(secure_account(shared_key_access=True))
        self.assertEqual(metrics(findings)["total"], len(findings))

    def test_report_contains_attack_context_and_remediation(self):
        report = render_markdown(assess(secure_account(shared_key_access=True)))
        self.assertIn("MITRE ATT&CK", report)
        self.assertIn("Remediation", report)

    def test_loader_rejects_duplicate_accounts(self):
        record = secure_account().__dict__
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(json.dumps([record, record]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_accounts(path)

    def test_loader_rejects_string_boolean(self):
        record = dict(secure_account().__dict__)
        record["https_only"] = "true"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(json.dumps([record]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_accounts(path)

    def test_loader_rejects_unknown_field(self):
        record = dict(secure_account().__dict__)
        record["unexpected"] = "value"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(json.dumps([record]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_accounts(path)

    def test_valid_remediation_evidence_closes(self):
        evidence = RemediationEvidence(
            finding_id="AZST-123", change_reference="CHG-1001", accountable_owner="Cloud Platform",
            configuration_before="publicNetworkAccess=Enabled", configuration_after="publicNetworkAccess=Disabled",
            validation_method="configuration review", validation_result="pass", monitoring_confirmed=True,
        )
        self.assertEqual(validate_closure(evidence)[0], "validated")

    def test_failed_validation_blocks_closure(self):
        evidence = RemediationEvidence(
            finding_id="AZST-123", change_reference="CHG-1001", accountable_owner="Cloud Platform",
            configuration_before="old", configuration_after="new", validation_method="review",
            validation_result="fail", monitoring_confirmed=True,
        )
        self.assertEqual(validate_closure(evidence)[0], "invalid_closure")

    def test_missing_monitoring_evidence_blocks_closure(self):
        evidence = RemediationEvidence(
            finding_id="AZST-123", change_reference="CHG-1001", accountable_owner="Cloud Platform",
            configuration_before="old", configuration_after="new", validation_method="review",
            validation_result="pass", monitoring_confirmed=False,
        )
        self.assertEqual(validate_closure(evidence)[0], "needs_evidence")


if __name__ == "__main__":
    unittest.main()
