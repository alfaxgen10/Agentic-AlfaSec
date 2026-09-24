"""Conservative, standard-library Java/Spring source-to-sink analysis."""
from __future__ import annotations

import re
from pathlib import Path

from .models import EngineResult, Finding, ScanRequest
from .rules import IGNORED_DIRECTORIES

_REQUEST = re.compile(
    r"(?:request\s*\.\s*getParameter\s*\(|@(?:RequestParam|PathVariable)\b)",
    re.I,
)
_ASSIGN = re.compile(r"\b(?:String|var|Object|Path|File|URI|int|long)\s+([A-Za-z_]\w*)\s*=\s*(.+)")
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\((.*)\)")
_SINKS = (
    ("java-sql-injection", "Tainted request input reaches a JDBC query", "HIGH", "CWE-89",
     re.compile(r"\b(?:Statement|statement|stmt|query|connection)\s*\.\s*(?:execute|executeQuery|executeUpdate)\s*\((.*)\)", re.I),
     "Use PreparedStatement with placeholders and bind values separately."),
    ("java-command-injection", "Tainted request input reaches command execution", "HIGH", "CWE-78",
     re.compile(r"(?:Runtime\s*\.\s*getRuntime\s*\(\)\s*\.\s*exec|new\s+ProcessBuilder)\s*\((.*)\)", re.I),
     "Avoid shell execution; use fixed argument lists and strict allowlists."),
    ("java-path-traversal", "Tainted request input reaches a filesystem path", "HIGH", "CWE-22",
     re.compile(r"(?:new\s+(?:FileInputStream|FileReader|FileOutputStream)|Files\s*\.\s*read\w*|Paths\s*\.\s*get)\s*\((.*)\)", re.I),
     "Resolve paths below a fixed base directory and reject traversal."),
    ("java-unsafe-deserialization", "Tainted input reaches Java deserialization", "HIGH", "CWE-502",
     re.compile(r"(?:new\s+ObjectInputStream|ObjectInputStream\s*\w*\s*=\s*[^;]*|\.readObject\s*\()\s*(?:\((.*)\))?", re.I),
     "Use a safe data format and never deserialize untrusted bytes."),
)


def _finding(rule: str, title: str, severity: str, cwe: str, path: Path,
             line: int, evidence: str, remediation: str, confidence: str = "high") -> Finding:
    return Finding(rule, title, severity, confidence, cwe, None, "context-dependent",
                   str(path), line, evidence.strip()[:300], remediation)


def _is_tainted(expr: str, tainted: set[str]) -> bool:
    if _REQUEST.search(expr):
        return True
    return any(re.search(r"\b" + re.escape(name) + r"\b", expr) for name in tainted)


def _scan_file(path: Path) -> list[Finding]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    tainted: set[str] = set()
    constants: set[str] = set()
    findings: list[Finding] = []
    reported: set[tuple[str, int]] = set()
    annotation_pending = False

    # First pass handles direct sources, aliases, and annotated controller parameters.
    for text in lines:
        assignment = _ASSIGN.search(text)
        if assignment and _REQUEST.search(assignment.group(2)):
            tainted.add(assignment.group(1))
        if re.search(r"@\s*(?:RequestParam|PathVariable)\b", text):
            annotation_pending = True
        match = re.search(r"\b(?:public|private|protected)?\s*[\w<>, ?\[\]]+\s+\w+\s*\(([^)]*)\)", text)
        if annotation_pending and match:
            for param in match.group(1).split(","):
                name = re.search(r"\b([A-Za-z_]\w*)\s*$", param.strip())
                if name:
                    tainted.add(name.group(1))
            annotation_pending = False

    # Propagate taint through simple same-file helper calls. This intentionally
    # only considers declared methods and a few fixed-point passes.
    helpers: dict[str, list[str]] = {}
    for text in lines:
        declaration = re.search(
            r"\b(?:public|private|protected|static|final|\s)*[\w<>, ?\[\]]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{?",
            text,
        )
        if declaration:
            params = []
            for param in declaration.group(2).split(","):
                found = re.search(r"\b([A-Za-z_]\w*)\s*$", param.strip())
                if found:
                    params.append(found.group(1))
            helpers[declaration.group(1)] = params
    for _ in range(3):
        changed = False
        for text in lines:
            for helper, params in helpers.items():
                call = re.search(r"\b" + re.escape(helper) + r"\s*\(([^;\n]*)\)", text)
                if call and _is_tainted(call.group(1), tainted):
                    for param in params:
                        if param not in tainted:
                            tainted.add(param)
                            changed = True
        if not changed:
            break

    for number, text in enumerate(lines, 1):
        assignment = _ASSIGN.search(text)
        if assignment:
            name, expr = assignment.groups()
            if _is_tainted(expr, tainted):
                tainted.add(name)
                constants.discard(name)
            elif re.match(r'(?s)^\s*["\']', expr) or re.match(r"^\s*(?:true|false|null|-?\d)", expr):
                constants.add(name)
                tainted.discard(name)

        for rule, title, severity, cwe, pattern, remediation in _SINKS:
            match = pattern.search(text)
            if not match:
                continue
            args = match.group(1) or text
            # A PreparedStatement and its bind calls are deliberately safe.
            if rule == "java-sql-injection" and (
                re.search(r"\bPreparedStatement\b|\.prepareStatement\s*\(", text)
                or re.search(r"\.set(?:String|Int|Long|Object|Bytes)\s*\(", text)
            ):
                continue
            if not _is_tainted(args, tainted):
                continue
            key = (rule, number)
            if key not in reported:
                reported.add(key)
                findings.append(_finding(rule, title, severity, cwe, path, number,
                                         f"request input -> {text}", remediation))

        if re.search(r"\b(?:MessageDigest|getInstance)\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']", text, re.I) or \
                re.search(r"\b(?:Cipher|getInstance)\s*\(\s*[\"'](?:DES|DESede|3DES)(?:/|[\"'])", text, re.I):
            findings.append(_finding("java-weak-crypto", "Weak cryptographic algorithm", "MEDIUM",
                                     "CWE-327", path, number, text,
                                     "Use SHA-256 or stronger modern authenticated encryption.", "high"))
        if re.search(r"(?:TrustManager|HostnameVerifier|X509TrustManager).*(?:return\s+null|return\s+true|checkServerTrusted\s*\(\s*\{\s*\})|"
                     r"setHostnameVerifier\s*\([^;]*(?:ALLOW_ALL|NoopHostnameVerifier|return\s+true)|"
                     r"SSLContext\s*\.\s*getInstance\s*\(\s*[\"']SSL[\"']", text, re.I):
            findings.append(_finding("java-tls-disabled", "TLS certificate verification is disabled",
                                     "HIGH", "CWE-295", path, number, text,
                                     "Keep certificate and hostname verification enabled.", "high"))
    return findings


class JavaAstEngine:
    """Java flow engine using conservative lexical parsing (no third-party parser)."""

    engine_id = "java-ast"

    def run(self, request: ScanRequest) -> EngineResult:
        root = request.scope.root
        paths = [root] if root.is_file() else list(root.rglob("*.java"))
        findings = [
            finding for path in paths
            if path.is_file() and not any(part in IGNORED_DIRECTORIES for part in path.parts)
            and path.stat().st_size <= 2_000_000
            for finding in _scan_file(path)
        ]
        return EngineResult(self.engine_id, findings, {"mode": "conservative Java lexical flow"}, [])
