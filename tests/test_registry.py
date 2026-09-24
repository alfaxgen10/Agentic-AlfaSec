import tempfile
import unittest
from pathlib import Path

from alfasec.registry import ProjectRegistry, normalize_scan_summary


class RegistryTests(unittest.TestCase):
    def test_atomic_persistence_and_bounded_history(self):
        with tempfile.TemporaryDirectory() as temp:
            registry = ProjectRegistry(Path(temp) / "registry.json", max_history=2)
            root = Path(temp) / "project"
            root.mkdir()
            registry.record_scan(root, {"scan_id": "one", "findings_count": 1})
            registry.record_scan(root, {"scan_id": "two", "findings_count": 2})
            registry.record_scan(root, {"scan_id": "three", "findings_count": 3})
            restored = ProjectRegistry(Path(temp) / "registry.json")
            project = restored.list_projects()[0]
            self.assertEqual([item["scan_id"] for item in project["history"]], ["two", "three"])
            self.assertEqual(restored.summary(project["id"])["scan_count"], 2)

    def test_normalized_lifecycle_comparison(self):
        result = {
            "scan_id": "scan", "scanned_at": "now",
            "findings": [{"severity": "HIGH"}, {"severity": "LOW"}],
            "policy": {"passed": False},
            "coverage": {"analyzed_files": 2},
            "engines": [{"engine_id": "rules", "errors": []}],
            "lifecycle": {"findings": [
                {"fingerprint": "new", "status": "open", "first_seen": "now", "last_seen": "now"},
                {"fingerprint": "fixed", "status": "fixed"},
                {"fingerprint": "again", "status": "reappeared"},
            ]},
        }
        summary = normalize_scan_summary(result)
        self.assertEqual(summary["new_fingerprints"], ["new"])
        self.assertEqual(summary["fixed_fingerprints"], ["fixed"])
        self.assertEqual(summary["reappeared_fingerprints"], ["again"])
        self.assertEqual(summary["findings_counts"], {"HIGH": 1, "LOW": 1})


if __name__ == "__main__":
    unittest.main()
