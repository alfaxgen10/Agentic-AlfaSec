import json
import tempfile
import unittest
from pathlib import Path

from alfasec.server import AuditLog, ScanJobs, ScanServer, authorize_project


class ScanServerTests(unittest.TestCase):
    def test_path_authorization(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = root / "project"
            child.mkdir()
            self.assertEqual(authorize_project(str(child), (root,)), child.resolve())
            with self.assertRaises(ValueError):
                authorize_project(str(root.parent), (root,))

    def test_job_lifecycle_and_result_shape(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            (project / "safe.py").write_text("print('ok')\n", encoding="utf-8")
            jobs = ScanJobs((project,), timeout=30)
            job_id = jobs.start(str(project))
            for _ in range(100):
                status = jobs.get(job_id)
                if status["status"] in ("complete", "failed"):
                    break
                import time
                time.sleep(0.02)
            self.assertEqual(status["status"], "complete", jobs.get(job_id))
            result = jobs.result(job_id)
            for key in ("findings", "coverage", "quality", "policy", "assets", "correlations",
                        "remediation", "risk", "governance"):
                self.assertIn(key, result)
            jobs.executor.shutdown(wait=True)

    def test_unknown_job_rejected(self):
        jobs = ScanJobs((Path.cwd(),))
        with self.assertRaises(KeyError):
            jobs.get("missing")
        jobs.executor.shutdown(wait=True)

    def test_audit_log_records_metadata_without_tokens(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.log"
            audit = AuditLog(path)
            audit.write("request_denied", path="/scan/health", token="must-not-be-written")
            content = path.read_text(encoding="utf-8")
            self.assertIn("request_denied", content)
            self.assertIn("/scan/health", content)
            self.assertNotIn("must-not-be-written", content)

    def test_origin_policy_rejects_insecure_github_origin(self):
        self.assertTrue(ScanServer.origin_allowed("https://example.github.io"))
        self.assertFalse(ScanServer.origin_allowed("http://example.github.io"))
        self.assertFalse(ScanServer.origin_allowed("https://example.github.io.attacker.test"))


if __name__ == "__main__":
    unittest.main()
