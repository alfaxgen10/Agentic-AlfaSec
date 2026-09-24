import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from alfasec import Finding
from alfasec.cli import main
from alfasec.remediation import (
    approve_remediation,
    remediation_plan,
    save_remediation_plan,
    verify_remediation,
    verify_remediation_plan,
)


class RemediationTests(unittest.TestCase):
    def _finding(self, evidence="redacted secret") -> Finding:
        return Finding(
            "secret", "Secret", "high", "medium", "CWE-798", None, "",
            "app.py", 3, evidence, "Rotate the token and use an environment variable.",
        )

    def test_plan_is_redacted_and_does_not_include_full_secret(self):
        finding = self._finding('token = "super-secret-value"')
        plan = remediation_plan([finding])
        serialized = json.dumps(plan)
        self.assertNotIn("super-secret-value", serialized)
        self.assertTrue(plan["records"][0]["patch_preview"])
        self.assertTrue(plan["records"][0]["approval_required"])

    def test_approval_and_verification_lifecycle(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "remediation.json"
            plan = save_remediation_plan(path, remediation_plan([self._finding()]))
            fingerprint = plan["records"][0]["fingerprint"]
            approved = approve_remediation(path, fingerprint)
            self.assertEqual(approved["records"][0]["status"], "approved")
            verified = verify_remediation([], approved)
            self.assertEqual(verified["records"][0]["status"], "verified")
            reappeared = verify_remediation([self._finding()], verified)
            self.assertEqual(reappeared["records"][0]["status"], "reappeared")

    def test_cli_remediation_plan_option(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "unsafe.java").write_text('String token = "demo-secret";', encoding="utf-8")
            plan_path = root / "plan.json"
            output = StringIO()
            with patch("sys.argv", ["alfasec", "scan-project", str(root),
                                    "--no-history", "--remediation-plan", str(plan_path)]):
                with redirect_stdout(output):
                    self.assertEqual(main(), 1)
            self.assertIn('"remediation"', output.getvalue())
            self.assertTrue(plan_path.exists())

    def test_persisted_plan_verification(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "remediation.json"
            save_remediation_plan(path, remediation_plan([self._finding()]))
            result = verify_remediation_plan(path, [])
            self.assertEqual(result["summary"]["counts"]["verified"], 1)
            self.assertEqual(json.loads(path.read_text())["records"][0]["status"], "verified")

    def test_cli_verification_command(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "unsafe.py").write_text('token = "super-secret-value"\n', encoding="utf-8")
            plan_path = root / "remediation.json"
            save_remediation_plan(plan_path, remediation_plan([self._finding()]))
            with patch("sys.argv", ["alfasec", "verify-remediation", str(root), str(plan_path)]):
                with redirect_stdout(StringIO()):
                    self.assertEqual(main(), 0)
            self.assertEqual(load_plan_status(plan_path), "verified")

    def test_cli_scan_includes_integrated_risk_and_governance(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "unsafe.py").write_text('token = "super-secret-value"\n', encoding="utf-8")
            output = StringIO()
            with patch("sys.argv", ["alfasec", "scan-project", str(root), "--no-history"]):
                with redirect_stdout(output):
                    self.assertEqual(main(), 1)
            result = json.loads(output.getvalue())
            self.assertIn("risk", result)
            self.assertIn("governance", result)
            self.assertIn("workflow", result["findings"][0])


def load_plan_status(path: Path) -> str:
    return json.loads(path.read_text(encoding="utf-8"))["records"][0]["status"]


if __name__ == "__main__":
    unittest.main()
