"""JavaScript and TypeScript AST subprocess integration."""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path
from .models import Finding
def scan_javascript_ast(path: Path) -> list[Finding]:
    node = shutil.which("node")
    analyzer = Path(__file__).parent.parent / "ast_analyzer.mjs"
    if node is None:
        raise RuntimeError("Node.js is required for JavaScript/TypeScript AST analysis.")
    if not analyzer.exists():
        raise RuntimeError(f"AST analyzer is missing: {analyzer}")
    completed = subprocess.run(
        [node, str(analyzer), str(path)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "unknown parser error"
        raise RuntimeError(f"AST analysis failed for {path}: {detail}")
    try:
        records = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"AST analyzer returned invalid JSON for {path}: {error}") from error
    return [
        Finding(
            rule_id=item["rule_id"],
            title=item["title"],
            severity=item["severity"],
            confidence=item["confidence"],
            cwe=item["cwe"],
            cve=None,
            cvss=item.get("cvss", "context-dependent"),
            file=str(path),
            line=int(item["line"]),
            evidence=item["evidence"][:300],
            remediation=item["remediation"],
        )
        for item in records
    ]

def scan_javascript_project(root: Path) -> list[Finding]:
    node = shutil.which("node")
    analyzer = Path(__file__).parent.parent / "ast_project_analyzer.mjs"
    if node is None:
        raise RuntimeError("Node.js is required for JavaScript/TypeScript AST analysis.")
    completed = subprocess.run(
        [node, str(analyzer), str(root)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "unknown parser error"
        raise RuntimeError(f"Project AST analysis failed: {detail}")
    try:
        records = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Project AST analyzer returned invalid JSON: {error}") from error
    return [
        Finding(
            rule_id=item["rule_id"],
            title=item["title"],
            severity=item["severity"],
            confidence=item["confidence"],
            cwe=item["cwe"],
            cve=None,
            cvss=item.get("cvss", "context-dependent"),
            file=item["file"],
            line=int(item["line"]),
            evidence=item["evidence"][:300],
            remediation=item["remediation"],
        )
        for item in records
    ]
