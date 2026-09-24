import tempfile
import unittest
from pathlib import Path

from alfasec.workflow import (
    FindingWorkflow, enrich_findings, governance_summary, risk_score, risk_summary,
)


class WorkflowTests(unittest.TestCase):
    def test_risk_score_is_explainable_and_bounded(self):
        result = risk_score({"severity": "HIGH", "confidence": "MEDIUM"})
        self.assertEqual(result["score"], 5.25)
        self.assertEqual(result["priority"], "high")
        self.assertIn("limitations", result)

    def test_workflow_requires_rationale_for_risk_decisions(self):
        with tempfile.TemporaryDirectory() as folder:
            workflow = FindingWorkflow(Path(folder) / "workflow.json")
            with self.assertRaises(ValueError):
                workflow.update("abc", state="accepted-risk")
            record = workflow.update("abc", state="accepted-risk",
                                     owner="security", expires_at="2099-10-01",
                                     rationale="Compensating control documented")
            self.assertEqual(record["owner"], "security")
            self.assertEqual(workflow.get_all()["abc"]["state"], "accepted-risk")

    def test_enrichment_includes_workflow_and_summary(self):
        findings = [{"fingerprint": "abc", "severity": "CRITICAL", "confidence": "high"}]
        enriched = enrich_findings(findings, {"findings": {
            "abc": {"state": "in-progress", "owner": "team", "due_date": "2026-10-01",
                    "decision": None, "updated_at": "now"}
        }})
        self.assertEqual(enriched[0]["workflow"]["owner"], "team")
        self.assertEqual(risk_summary(enriched)["priority_counts"], {"urgent": 1})

    def test_overdue_and_expired_workflow_records_require_attention(self):
        findings = [{"fingerprint": "abc", "severity": "HIGH", "confidence": "high"}]
        workflow = {"findings": {
            "abc": {"state": "accepted-risk", "owner": None, "due_date": "2020-01-01",
                    "expires_at": "2020-01-01", "rationale": "old decision"}
        }}
        enriched = enrich_findings(findings, workflow)
        self.assertTrue(enriched[0]["workflow"]["overdue"])
        self.assertTrue(enriched[0]["workflow"]["expired"])
        self.assertEqual(governance_summary(workflow["findings"], enriched)["expired_accepted_risks"], 1)


if __name__ == "__main__":
    unittest.main()
