import json
import tempfile
import unittest
from pathlib import Path

from alfasec.models import Finding
from alfasec.policy import evaluate_policy, load_policy
from alfasec.reporting import exports


def finding(rule="rule", severity="HIGH", confidence="HIGH"):
    return Finding(rule, "Example", severity, confidence, "CWE-89", None, "", "a.py", 3, "x", "Fix it")


class PolicyTests(unittest.TestCase):
    def test_threshold_and_confidence(self):
        result = evaluate_policy(
            [finding(severity="HIGH", confidence="MEDIUM"), finding("low", "LOW", "LOW")],
            {"max_severity": "HIGH", "minimum_confidence": "HIGH"},
        )
        self.assertTrue(result["passed"])

        result = evaluate_policy([finding()], {"max_severity": "HIGH", "minimum_confidence": "MEDIUM"})
        self.assertFalse(result["passed"])

    def test_ignored_rules(self):
        result = evaluate_policy([finding("ignored")], {"max_severity": "HIGH", "ignored_rule_ids": ["ignored"]})
        self.assertTrue(result["passed"])

    def test_invalid_policy_is_clear(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps({"max_severity": "NOPE"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "max_severity"):
                load_policy(path)

    def test_sarif_contains_rule_metadata_and_fingerprint(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.sarif"
            exports([finding()], path, "sarif")
            report = json.loads(path.read_text(encoding="utf-8"))
            rule = report["runs"][0]["tool"]["driver"]["rules"][0]
            result = report["runs"][0]["results"][0]
            self.assertEqual(rule["shortDescription"]["text"], "Example")
            self.assertIn("help", rule)
            self.assertIn("cwe", rule["properties"])
            self.assertEqual(result["level"], "error")
            self.assertIn("partialFingerprints", result)


if __name__ == "__main__":
    unittest.main()
