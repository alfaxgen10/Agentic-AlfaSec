"""Local secret detection with provider patterns and redacted evidence."""
from __future__ import annotations

import math
import re
import shutil
import subprocess
from pathlib import Path

from .models import Finding
from .rules import IGNORED_DIRECTORIES, SUPPORTED_EXTENSIONS

PATTERNS = (
    ("aws-access-key", "AWS access key", "CRITICAL", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", "GitHub token", "CRITICAL", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("slack-token", "Slack token", "HIGH", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("private-key", "Private key material", "CRITICAL", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", "JSON Web Token", "HIGH", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("generic-secret", "Hardcoded secret", "HIGH", re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_ -]?key|client[_ -]?secret)\b\s*[:=]\s*[\"']([^\"']{8,})[\"']"
    )),
)

PLACEHOLDERS = {"changeme", "change-me", "example", "demo", "placeholder", "your-token", "replace-me"}


def _entropy(value: str) -> float:
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}...{value[-4:]} [REDACTED]"


def _finding(rule_id: str, title: str, severity: str, path: Path, line: int, value: str, evidence: str) -> Finding:
    output_rule_id = "secret" if rule_id == "generic-secret" else rule_id
    return Finding(
        rule_id=output_rule_id,
        title=title,
        severity=severity,
        confidence="high" if rule_id != "generic-secret" else "medium",
        cwe="CWE-798" if rule_id != "private-key" else "CWE-321",
        cve=None,
        cvss="context-dependent",
        file=str(path),
        line=line,
        evidence=f"{evidence}: {_redact(value)}",
        remediation="Revoke and rotate the secret, remove it from source history, and use a secret manager.",
    )


def scan_secrets(root: Path) -> list[Finding]:
    findings = []
    paths = list(root.rglob("*")) if root.is_dir() else [root]
    for path in paths:
        if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue
        if path.stat().st_size > 2_000_000 or path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            for rule_id, title, severity, pattern in PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                value = match.group(2) if rule_id == "generic-secret" else match.group(0)
                if rule_id == "generic-secret" and value.lower() in PLACEHOLDERS:
                    continue
                if rule_id == "generic-secret" and _entropy(value) < 2.5:
                    continue
                findings.append(_finding(rule_id, title, severity, path, number, value, "Secret detected"))
    return findings


def scan_git_history(root: Path) -> list[Finding]:
    git = shutil.which("git")
    if git is None or not (root / ".git").exists():
        return []
    completed = subprocess.run(
        [git, "-C", str(root), "log", "--all", "--format=", "-p", "--"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if completed.returncode != 0:
        return []
    findings = []
    for number, line in enumerate(completed.stdout.splitlines(), 1):
        for rule_id, title, severity, pattern in PATTERNS:
            match = pattern.search(line.lstrip("+"))
            if match:
                value = match.group(2) if rule_id == "generic-secret" else match.group(0)
                if rule_id != "generic-secret" or value.lower() not in PLACEHOLDERS:
                    findings.append(_finding(f"history-{rule_id}", f"{title} in Git history", severity, root / ".git", number, value, "Secret found in Git history"))
    return findings
