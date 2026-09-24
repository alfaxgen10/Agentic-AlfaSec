import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1]))
from alfasec import (
    Finding,
    ScanProfile,
    ScanRequest,
    ScanScope,
    dependency_findings,
    dependencies,
    finding_quality,
    run_scan,
    scan_coverage,
    scan_project,
    port_scan,
    update_finding_history,
    scan_secrets,
    inventory_assets,
    correlate_findings,
)


class AlfaSecTests(unittest.TestCase):
    def test_asset_inventory_is_passive_and_classifies_project_assets(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.py").write_text("print('ok')", encoding="utf-8")
            (root / "Dockerfile").write_text("FROM python:3\n", encoding="utf-8")
            (root / "deployment.yaml").write_text("kind: Deployment\n", encoding="utf-8")
            assets = inventory_assets(root, [])
            self.assertIn("app.py", assets["source_files"])
            self.assertIn("Dockerfile", assets["docker_assets"])
            self.assertIn("deployment.yaml", assets["kubernetes_assets"])
            self.assertEqual(assets["local_service_indicators"], [])

    def test_correlation_requires_shared_evidence_and_disclaims_exploitability(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "app.py"
            path.write_text("x", encoding="utf-8")
            findings = scan_project(root)
            self.assertEqual(correlate_findings(findings), [])
            first = Finding("a-rule", "A", "HIGH", "high", "CWE-1", None, "", str(path), 1, "request source", "",)
            second = Finding("b-rule", "B", "MEDIUM", "medium", "CWE-2", None, "", str(path), 2, "exec sink", "",)
            groups = correlate_findings([first, second])
            self.assertEqual(len(groups), 1)
            self.assertIn("exploitability", " ".join(groups[0]["limitations"]))
    def test_detects_secret_and_sql_pattern(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unsafe.java"
            path.write_text('String token = "demo-secret";\nquery("SELECT * FROM users " + input);', encoding="utf-8")
            findings = scan_project(Path(folder))
            self.assertEqual({finding.rule_id for finding in findings}, {"secret", "sql-injection"})

    def test_safe_code_has_no_pattern_finding(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "safe.java"
            path.write_text("PreparedStatement statement = connection.prepareStatement(sql);", encoding="utf-8")
            self.assertEqual(scan_project(Path(folder)), [])

    def test_parser_finding_replaces_overlapping_heuristic(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "app.py"
            heuristic = Finding(
                "command-injection", "Potential command injection", "HIGH", "medium",
                "CWE-78", None, "", str(path), 4, "subprocess.run(value)", "Fix it",
            )
            semantic = Finding(
                "python-command-injection", "Tainted input reaches command execution", "HIGH", "high",
                "CWE-78", None, "", str(path), 4, "tainted input -> subprocess.run", "Fix it",
            )
            from alfasec.engines import deduplicate
            result = deduplicate([heuristic, semantic])
            self.assertEqual([item.rule_id for item in result], ["python-command-injection"])

    def test_port_scope_rejects_remote_target(self):
        with self.assertRaises(ValueError):
            port_scan("example.com", 80, 80, set())

    def test_ast_tracks_request_input_to_command_sink(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unsafe.js"
            path.write_text(
                "const value = req.query.name;\nchild_process.exec(value);",
                encoding="utf-8",
            )
            findings = scan_project(Path(folder))
            self.assertEqual({finding.rule_id for finding in findings}, {"js-command-injection"})

    def test_ast_does_not_flag_constant_command(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "safe.ts"
            path.write_text('child_process.execFile("whoami", []);', encoding="utf-8")
            self.assertEqual(scan_project(Path(folder)), [])

    def test_ast_tracks_request_input_through_helper_function(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "helper.js"
            path.write_text(
                "function run(command) { exec(command); }\nrun(req.body.command);",
                encoding="utf-8",
            )
            findings = scan_project(Path(folder))
            self.assertEqual({finding.rule_id for finding in findings}, {"js-command-injection"})

    def test_ast_tracks_request_input_across_imported_helper(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "runner.js").write_text(
                "export function run(command) { exec(command); }",
                encoding="utf-8",
            )
            (root / "route.js").write_text(
                'import { run } from "./runner.js";\nrun(req.body.command);',
                encoding="utf-8",
            )
            findings = scan_project(root)
            self.assertEqual({finding.rule_id for finding in findings}, {"js-command-injection"})

    def test_ast_respects_known_html_sanitizer(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "safe.js"
            path.write_text(
                "const clean = DOMPurify.sanitize(req.body.comment);\n"
                "document.body.innerHTML = clean;",
                encoding="utf-8",
            )
            self.assertEqual(scan_project(Path(folder)), [])

    def test_finding_history_marks_fixed_and_reappeared(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "unsafe.java"
            path.write_text('String token = "demo-secret";', encoding="utf-8")
            first = scan_project(root)
            history = root / "history.json"
            first_state = update_finding_history(root, first, history)
            self.assertEqual(first_state["counts"], {"open": 1})
            path.write_text("String token = System.getenv(\"TOKEN\");", encoding="utf-8")
            fixed_state = update_finding_history(root, scan_project(root), history)
            self.assertEqual(fixed_state["counts"], {"fixed": 1})
            path.write_text('String token = "demo-secret";', encoding="utf-8")
            restored_state = update_finding_history(root, scan_project(root), history)
            self.assertEqual(restored_state["counts"], {"reappeared": 1})

    def test_scan_coverage_reports_analyzed_and_skipped_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "safe.py").write_text("print('ok')", encoding="utf-8")
            (root / "notes.md").write_text("not analyzed", encoding="utf-8")
            coverage = scan_coverage(root)
            self.assertEqual(coverage["files_analyzed"], 1)
            self.assertEqual(coverage["files_skipped"], 1)
            self.assertIn("unsupported file type", coverage["skipped_files"][0]["reason"])

    def test_finding_quality_separates_confidence_levels(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "unsafe.java"
            path.write_text('String token = "demo-secret";', encoding="utf-8")
            quality = finding_quality(scan_project(root))
            self.assertEqual(quality["confidence_counts"]["medium"], 1)
            self.assertEqual(quality["review_required_findings"], 1)

    def test_unified_scan_contract_returns_engine_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "safe.py").write_text("print('ok')", encoding="utf-8")
            result = run_scan(
                ScanRequest(
                    ScanScope(root),
                    ScanProfile(include_history=False),
                )
            )
            self.assertTrue(result.scan_id.startswith("scan-"))
            self.assertEqual(
                {engine.engine_id for engine in result.engines},
                {"heuristics", "javascript-typescript-ast", "python-ast", "java-ast", "dependencies", "secrets", "configuration"},
            )

    def test_python_ast_detects_tainted_command_and_deserialization(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unsafe.py"
            path.write_text(
                "from flask import request\nimport os, pickle\n"
                "value = request.args.get('value')\nos.system(value)\npickle.loads(value)\n",
                encoding="utf-8",
            )
            result = run_scan(ScanRequest(ScanScope(Path(folder)), ScanProfile(include_history=False)))
            self.assertTrue({"python-command-injection", "python-unsafe-deserialization"} <=
                            {item.rule_id for item in result.findings})

    def test_python_ast_accepts_parameterized_query(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "safe.py"
            path.write_text(
                "import sqlite3\nconn = sqlite3.connect(':memory:')\n"
                "value = input()\nconn.execute('select ?', (value,))\n",
                encoding="utf-8",
            )
            result = run_scan(ScanRequest(ScanScope(Path(folder)), ScanProfile(include_history=False)))
            self.assertNotIn("python-sql-injection", {item.rule_id for item in result.findings})

    def test_java_ast_detects_spring_flow_and_weak_crypto(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Controller.java"
            path.write_text(
                'void run(@RequestParam String name) { String sql = "select " + name; '
                'statement.executeQuery(sql); Runtime.getRuntime().exec(name); }\n'
                'MessageDigest.getInstance("MD5");\n',
                encoding="utf-8",
            )
            result = run_scan(ScanRequest(ScanScope(Path(folder)), ScanProfile(include_history=False)))
            ids = {item.rule_id for item in result.findings}
            self.assertTrue({"java-sql-injection", "java-command-injection", "java-weak-crypto"} <= ids)
            self.assertTrue(all(item.confidence == "high" for item in result.findings
                                if item.rule_id.startswith("java-")))

    def test_java_ast_ignores_constants_and_prepared_binding(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Safe.java"
            path.write_text(
                'String sql = "select 1"; statement.executeQuery(sql);\n'
                'PreparedStatement ps = connection.prepareStatement("select ?");\n'
                'ps.setString(1, request.getParameter("name")); ps.executeQuery();\n',
                encoding="utf-8",
            )
            result = run_scan(ScanRequest(ScanScope(Path(folder)), ScanProfile(include_history=False)))
            self.assertNotIn("java-sql-injection", {item.rule_id for item in result.findings})

    def test_configuration_engine_detects_container_and_workflow_issues(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Dockerfile").write_text(
                "FROM python:3\nRUN curl https://example.test/install.sh | sh\nENV API_TOKEN=real-token-value\n",
                encoding="utf-8",
            )
            workflow = root / ".github" / "workflows"
            workflow.mkdir(parents=True)
            (workflow / "ci.yml").write_text(
                "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        run: echo ${{ secrets.TOKEN }}\n",
                encoding="utf-8",
            )
            findings = run_scan(ScanRequest(ScanScope(root), ScanProfile(include_history=False))).findings
            rules = {item.rule_id for item in findings}
            self.assertTrue({"docker-pipe-to-shell", "docker-secret-in-build", "docker-user-missing"} <= rules)
            self.assertTrue({"github-action-unpinned", "github-target-checkout", "github-secrets-in-run"} <= rules)

    def test_configuration_engine_does_not_flag_safe_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Dockerfile").write_text("FROM python:3\nUSER app\nCOPY . /app\n", encoding="utf-8")
            (root / "docker-compose.yml").write_text(
                "services:\n  app:\n    image: example/app:1\n    networks: [app]\n", encoding="utf-8")
            findings = run_scan(ScanRequest(ScanScope(root), ScanProfile(include_history=False))).findings
            self.assertEqual([item for item in findings if item.file.endswith(("Dockerfile", "docker-compose.yml"))], [])

    def test_dependency_inventory_reads_npm_lockfile(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "package-lock.json").write_text(
                '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/demo": '
                '{"name": "demo", "version": "1.2.3"}}}',
                encoding="utf-8",
            )
            items = dependencies(root)
            demo = next(item for item in items if item["package"] == "demo")
            self.assertEqual(demo["version"], "1.2.3")
            self.assertEqual(demo["source"], str(root / "package-lock.json"))
            self.assertTrue(demo["lockfile"])

    def test_dependency_advisory_becomes_verified_finding(self):
        items = [{"package": "demo", "version": "1.2.3", "source": "package-lock.json"}]
        findings = dependency_findings(items, [{
            "package": "demo", "version": "1.2.3", "id": "OSV-2026-TEST",
            "summary": "Test advisory", "severity": "HIGH",
        }])
        self.assertEqual(findings[0].cve, "OSV-2026-TEST")
        self.assertEqual(findings[0].confidence, "high")

    def test_dependency_inventory_reads_python_and_maven_manifests(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Pipfile.lock").write_text(
                '{"default": {"requests": {"version": "==2.31.0"}}, "develop": {}}',
                encoding="utf-8",
            )
            (root / "pom.xml").write_text(
                "<project><dependencies><dependency><groupId>org.demo</groupId>"
                "<artifactId>demo</artifactId><version>1.0.0</version>"
                "</dependency></dependencies></project>",
                encoding="utf-8",
            )
            items = dependencies(root)
            self.assertIn("requests", {item["package"] for item in items})
            self.assertIn("org.demo:demo", {item["package"] for item in items})

    def test_dependency_inventory_reads_gradle_and_poetry_lockfiles(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "build.gradle").write_text(
                'implementation "org.demo:demo:1.0.0"', encoding="utf-8"
            )
            (root / "poetry.lock").write_text(
                '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
                encoding="utf-8",
            )
            items = dependencies(root)
            self.assertIn("org.demo:demo", {item["package"] for item in items})
            self.assertIn("requests", {item["package"] for item in items})

    def test_secret_engine_redacts_provider_token(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "config.env"
            path.write_text("GITHUB_TOKEN=ghp_123456789012345678901234\n", encoding="utf-8")
            findings = scan_secrets(root)
            self.assertEqual(findings[0].rule_id, "github-token")
            self.assertNotIn("ghp_123456789012345678901234", findings[0].evidence)
            self.assertIn("[REDACTED]", findings[0].evidence)

    def test_secret_engine_ignores_placeholder(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "example.env"
            path.write_text('API_KEY="change-me"', encoding="utf-8")
            self.assertEqual(scan_secrets(Path(folder)), [])


if __name__ == "__main__":
    unittest.main()
