"""Security checks for container, orchestration, and CI configuration files.

The parser intentionally uses only line-oriented, conservative checks.  This
keeps the engine useful without making a YAML dependency a requirement.
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import EngineResult, Finding, ScanRequest
from .rules import IGNORED_DIRECTORIES


_SECRET_NAME = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)")
_PLACEHOLDER = re.compile(r"(?i)^(?:\$\{?[^}]+\}?|change(?:-me)?|example|placeholder|your[-_].*|redacted)$")


def _finding(rule_id: str, title: str, severity: str, cwe: str, path: Path,
             line: int, evidence: str, remediation: str,
             confidence: str = "high") -> Finding:
    return Finding(rule_id, title, severity, confidence, cwe, None,
                   "context-dependent", str(path), line, evidence.strip()[:300],
                   remediation)


def _dockerfile(path: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    has_user = False
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        instruction, _, argument = line.partition(" ")
        instruction = instruction.upper()
        if instruction == "USER":
            has_user = True
            if argument.strip().lower() in {"root", "0"}:
                findings.append(_finding(
                    "docker-user-root", "Dockerfile runs as root", "HIGH", "CWE-250",
                    path, number, raw, "Create and use a non-root user in the image.",
                ))
        elif instruction == "ADD" and re.search(r"(?i)\bhttps?://", argument):
            findings.append(_finding(
                "docker-add-remote", "Docker ADD uses a remote URL", "MEDIUM", "CWE-829",
                path, number, raw, "Download and verify artifacts explicitly, then use COPY.",
            ))
        elif instruction in {"RUN", "CMD", "ENTRYPOINT"} and re.search(
                r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash|zsh|ash)\b", argument):
            findings.append(_finding(
                "docker-pipe-to-shell", "Docker command pipes a download to a shell",
                "HIGH", "CWE-829", path, number, raw,
                "Verify a pinned artifact and execute it without piping network content to a shell.",
            ))
        elif instruction in {"ENV", "ARG"} and _SECRET_NAME.search(argument):
            if "=" in argument:
                value = argument.split("=", 1)[1].strip()
            else:
                parts = argument.split(None, 1)
                value = parts[1].strip() if len(parts) == 2 else ""
            if value and not _PLACEHOLDER.match(value.strip("\"'")):
                findings.append(_finding(
                    "docker-secret-in-build", "Dockerfile exposes a secret in ENV or ARG",
                    "HIGH", "CWE-798", path, number, raw,
                    "Use BuildKit secret mounts or runtime secret injection; do not bake secrets into layers.",
                ))
    if not has_user:
        findings.append(_finding(
            "docker-user-missing", "Dockerfile does not specify a non-root USER",
            "MEDIUM", "CWE-250", path, 1,
            "No USER instruction found", "Add a dedicated non-root USER before the runtime command.",
            "medium",
        ))
    return findings


def _compose(path: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        lower = line.lower()
        if re.match(r"(?i)^privileged\s*:\s*true\b", line):
            findings.append(_finding("compose-privileged", "Compose service is privileged",
                "HIGH", "CWE-250", path, number, raw,
                "Remove privileged mode and grant only the capabilities required."))
        if re.match(r"(?i)^network_mode\s*:\s*(?:host|['\"]host['\"])\s*$", line):
            findings.append(_finding("compose-host-network", "Compose service uses host networking",
                "HIGH", "CWE-668", path, number, raw,
                "Use an isolated network instead of sharing the host network namespace."))
        if "docker.sock" in lower and re.search(r"(?i)(?:/var/run/)?docker\.sock", line):
            findings.append(_finding("compose-docker-socket", "Compose exposes the Docker socket",
                "HIGH", "CWE-668", path, number, raw,
                "Remove the socket bind or use a narrowly scoped Docker API proxy."))
        if re.match(r"(?i)^\s*-?\s*[\"']?[^:]+:\s*[\"']?[^$]", line) and _SECRET_NAME.search(line):
            value = line.split(":", 1)[1].strip().strip("\"'")
            if value and not _PLACEHOLDER.match(value):
                findings.append(_finding("compose-plaintext-secret", "Compose contains a plaintext secret",
                    "HIGH", "CWE-798", path, number, raw,
                    "Use Docker secrets or an external secret manager instead of committing secret values.",
                    "medium"))
    return findings


def _kubernetes(path: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    in_container = False
    container_indent = 0
    saw_limits = False
    container_line = 1
    for number, raw in enumerate(lines, 1):
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if re.match(r"(?i)^kind\s*:\s*(?:Deployment|DaemonSet|StatefulSet|Pod|Job|CronJob)\s*$", stripped):
            pass
        if re.match(r"^-\s+name\s*:", stripped) and container_indent and indent == container_indent:
            if in_container and not saw_limits:
                findings.append(_finding(
                    "k8s-resource-limits-missing", "Kubernetes container has no resource limits",
                    "MEDIUM", "CWE-400", path, container_line,
                    "No resources.limits found for container",
                    "Define CPU and memory limits for every container.", "medium",
                ))
            in_container = True
            container_line = number
            saw_limits = False
        if re.match(r"(?i)^containers\s*:", stripped) or re.match(r"(?i)^initContainers\s*:", stripped):
            in_container = False
            container_indent = indent + 2
        if in_container and re.match(r"(?i)^privileged\s*:\s*true\b", stripped):
            findings.append(_finding("k8s-privileged-container", "Kubernetes container is privileged",
                "HIGH", "CWE-250", path, number, raw,
                "Set privileged to false and remove unnecessary Linux capabilities."))
        if re.match(r"(?i)^hostNetwork\s*:\s*true\b", stripped):
            findings.append(_finding("k8s-host-network", "Kubernetes pod uses hostNetwork",
                "HIGH", "CWE-668", path, number, raw,
                "Use pod networking unless host networking is explicitly required."))
        if re.match(r"(?i)^hostPID\s*:\s*true\b", stripped):
            findings.append(_finding("k8s-host-pid", "Kubernetes pod uses hostPID",
                "HIGH", "CWE-250", path, number, raw,
                "Avoid sharing the host PID namespace with workloads."))
        if re.match(r"(?i)^hostPath\s*:", stripped) or re.match(r"(?i)^-?\s*hostPath\s*:", stripped):
            findings.append(_finding("k8s-hostpath", "Kubernetes volume uses hostPath",
                "HIGH", "CWE-668", path, number, raw,
                "Use a managed persistent volume instead of mounting arbitrary host paths."))
        if re.match(r"(?i)^type\s*:\s*LoadBalancer\s*$", stripped):
            findings.append(_finding("k8s-loadbalancer", "Kubernetes service is externally exposed",
                "MEDIUM", "CWE-284", path, number, raw,
                "Restrict exposure and enforce authentication, authorization, and network policy.",
                "medium"))
        if re.match(r"(?i)^limits\s*:", stripped):
            saw_limits = True
    if in_container and not saw_limits:
        findings.append(_finding("k8s-resource-limits-missing", "Kubernetes container has no resource limits",
            "MEDIUM", "CWE-400", path, container_line, "No resources.limits found for container",
            "Define CPU and memory limits for every container.", "medium"))
    return findings


def _actions(path: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    target_workflow = any(re.search(r"(?i)pull_request_target\s*:", item) for item in lines)
    run_indent: int | None = None
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if re.match(r"(?i)run\s*:", line):
            run_indent = indent
        elif run_indent is not None and indent <= run_indent and line and not line.startswith("#"):
            run_indent = None
        uses = re.search(r"(?i)^\s*-\s*uses\s*:\s*([^\s#]+)", raw)
        if uses and "@" in uses.group(1) and not re.search(r"@[0-9a-fA-F]{40}$", uses.group(1)):
            findings.append(_finding("github-action-unpinned", "GitHub Action is not pinned to a commit",
                "MEDIUM", "CWE-829", path, number, raw,
                "Pin third-party actions to a full commit SHA and review updates."))
        if re.search(r"(?i)pull_request_target\s*:", line):
            findings.append(_finding("github-pull-request-target", "Workflow uses pull_request_target",
                "HIGH", "CWE-74", path, number, raw,
                "Avoid running untrusted fork code with write tokens; prefer pull_request for untrusted changes.",
                "medium"))
        if re.search(r"(?i)\buses\s*:\s*actions/checkout@", line):
            if target_workflow:
                findings.append(_finding("github-target-checkout", "pull_request_target checks out untrusted code",
                    "HIGH", "CWE-94", path, number, raw,
                    "Do not checkout fork-controlled code in a privileged pull_request_target workflow."))
        if (re.search(r"(?i)\brun\s*:", line) or run_indent is not None) and re.search(r"\$\{\{\s*secrets\.", line):
            findings.append(_finding("github-secrets-in-run", "Workflow interpolates a secret in a shell command",
                "HIGH", "CWE-78", path, number, raw,
                "Pass secrets through environment variables and avoid shell interpolation; quote and validate inputs."))
    return findings


def _is_dockerfile(path: Path) -> bool:
    return path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile.")


def _kind(path: Path, text: str) -> str | None:
    if _is_dockerfile(path):
        return "dockerfile"
    if path.name.lower().startswith(("docker-compose", "compose")):
        return "compose"
    if ".github" in path.parts and "workflows" in path.parts:
        return "actions"
    if re.search(r"(?im)^\s*kind\s*:\s*(?:Deployment|DaemonSet|StatefulSet|Pod|Job|CronJob|Service)\s*$", text):
        return "kubernetes"
    return None


class ConfigurationEngine:
    engine_id = "configuration"

    def run(self, request: ScanRequest) -> EngineResult:
        paths = list(request.scope.root.rglob("*")) if request.scope.root.is_dir() else [request.scope.root]
        findings: list[Finding] = []
        files = 0
        for path in paths:
            if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            kind = _kind(path, text)
            if not kind:
                continue
            files += 1
            lines = text.splitlines()
            findings.extend({"dockerfile": _dockerfile, "compose": _compose,
                             "kubernetes": _kubernetes, "actions": _actions}[kind](path, lines))
        return EngineResult(self.engine_id, findings, {"mode": "stdlib configuration checks", "files": files}, [])
