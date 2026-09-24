"""Pattern-based security rules."""
from __future__ import annotations
import re
from pathlib import Path
from .models import Finding

RULES = (
    ("sql-injection", "Potential SQL injection", "HIGH", "CWE-89", re.compile(r"(?i)(executeQuery|executeUpdate|SELECT.{0,120}\+|SELECT.{0,120}\$\{)"), "Use parameterized queries and verify the complete input-to-query data flow."),
    ("command-injection", "Potential command injection", "HIGH", "CWE-78", re.compile(r"(?i)(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|os\.system|subprocess\.(run|Popen|call)|child_process\.(exec|execSync))"), "Avoid shell execution; use safe APIs and strict argument allowlists."),
    ("xss", "Potential cross-site scripting sink", "HIGH", "CWE-79", re.compile(r"(?i)(innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|v-html\s*=)"), "Use contextual output encoding and safe DOM APIs."),
    ("path-traversal", "Potential path traversal", "HIGH", "CWE-22", re.compile(r"(?i)\b(readFile|writeFile|open|FileInputStream|Paths?\.get)\s*\([^)]*(request|params|query|input|filename)"), "Normalize and constrain paths below a fixed base directory."),
    ("weak-crypto", "Weak cryptography", "MEDIUM", "CWE-327", re.compile(r"(?i)\b(MD5|SHA1|SHA-1|DES|3DES|RC4|ECB)\b"), "Use modern authenticated encryption or a password hashing algorithm such as Argon2id."),
    ("tls-disabled", "TLS verification disabled", "HIGH", "CWE-295", re.compile(r"(?i)(verify\s*[:=]\s*false|rejectUnauthorized\s*:\s*false|TrustAll)"), "Keep certificate and hostname verification enabled."),
    ("debug", "Debug mode enabled", "MEDIUM", "CWE-489", re.compile(r"(?i)(DEBUG\s*=\s*True|debug\s*[:=]\s*true)"), "Disable debug mode in production."),
)

AST_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SUPPORTED_EXTENSIONS = {
    ".java", ".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".cs", ".go",
    ".rb", ".rs", ".c", ".cpp", ".h", ".yml", ".yaml", ".json", ".xml",
    ".properties", ".env", ".toml", ".ini", ".txt",
}
IGNORED_DIRECTORIES = {".git", "node_modules", "target", "build", "dist", "__pycache__", ".alfasec"}

def finding(rule, path: Path, line_number: int, line: str) -> Finding:
    rule_id, title, severity, cwe, _pattern, remediation = rule
    return Finding(rule_id, title, severity, "medium", cwe, None,
                   "context-dependent", str(path), line_number, line.strip()[:300], remediation)

def scan_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        for rule in RULES:
            if rule[4].search(line):
                findings.append(finding(rule, path, number, line))
    return findings
