import unittest
from pathlib import Path


class CIWorkflowTests(unittest.TestCase):
    def test_security_workflow_uploads_sarif_and_enforces_gate(self):
        workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "security-scan.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("pull_request:", workflow)
        self.assertIn("--policy .github/alfasec-policy.json", workflow)
        self.assertIn("--no-history", workflow)
        self.assertIn("--format sarif", workflow)
        self.assertIn("upload-sarif@v3", workflow)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", workflow)
        self.assertIn("steps.alfasec.outcome == 'failure'", workflow)
        self.assertIn("security-events: write", workflow)


if __name__ == "__main__":
    unittest.main()
