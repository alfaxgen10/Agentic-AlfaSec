"""Passive project asset inventory.

Inventory is filesystem-only: it never resolves hosts, opens sockets, or
contacts package/advisory services.  Paths are relative to the project root
where possible so reports remain portable.
"""
from __future__ import annotations

from pathlib import Path
from .models import Finding
from .rules import IGNORED_DIRECTORIES

_SOURCE = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
           ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".rs", ".kt", ".swift"}
_CONFIG_NAMES = {"package.json", "requirements.txt", "pipfile", "pipfile.lock",
                 "poetry.lock", "pyproject.toml", "pom.xml", "build.gradle",
                 "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
                 ".env", ".env.example"}
_SERVICE_TERMS = ("listen", "server", "service", "port", "hostnetwork",
                  "loadbalancer", "docker.sock", "localhost", "127.0.0.1")


def _relative(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def inventory_assets(root: Path, findings: list[Finding] | None = None,
                     dependency_items: list[dict] | None = None) -> dict:
    """Return a deterministic, passive inventory of project assets."""
    root = root.resolve()
    paths = ([root] if root.is_file() else list(root.rglob("*")))
    files = [p for p in paths if p.is_file() and
             not any(part in IGNORED_DIRECTORIES for part in p.parts)]
    sources = [_relative(root, p) for p in files if p.suffix.lower() in _SOURCE]
    configs = []
    docker, kubernetes, actions = [], [], []
    for path in files:
        rel = _relative(root, path)
        name = path.name.lower()
        if (name in _CONFIG_NAMES or name.startswith(".env.") or
                path.suffix.lower() in {".yaml", ".yml", ".ini", ".cfg", ".conf"}):
            configs.append(rel)
        if name == "dockerfile" or name.startswith("dockerfile."):
            docker.append(rel)
        if name.endswith((".yaml", ".yml")):
            parts = {part.lower() for part in path.parts}
            is_k8s = "k8s" in parts or "kubernetes" in parts
            if not is_k8s:
                try:
                    is_k8s = "kind:" in path.read_text(encoding="utf-8", errors="replace").lower()
                except OSError:
                    is_k8s = False
            if is_k8s:
                kubernetes.append(rel)
        if ".github" in path.parts and "workflows" in path.parts:
            actions.append(rel)
    deps = list(dependency_items or [])
    if not deps:
        # Avoid importing the dependency scanner at module import time.
        from .dependencies import dependencies
        deps = dependencies(root)
    service_findings = []
    for finding in findings or []:
        text = f"{finding.title} {finding.evidence}".lower()
        if any(term in text for term in _SERVICE_TERMS):
            service_findings.append({
                "finding_fingerprint": finding_fingerprint(finding),
                "file": _relative(root, Path(finding.file)),
                "rule_id": finding.rule_id,
                "evidence": finding.evidence,
            })
    return {
        "project_root": str(root),
        "source_files": sorted(sources),
        "dependency_packages": deps,
        "configuration_files": sorted(configs),
        "docker_assets": sorted(docker),
        "kubernetes_assets": sorted(kubernetes),
        "github_actions_assets": sorted(actions),
        "local_service_indicators": service_findings,
        "limitations": [
            "Inventory is based on local file names and findings only.",
            "It does not probe networks or verify that a service is running.",
        ],
    }


def finding_fingerprint(finding: Finding) -> str:
    import hashlib
    value = "|".join(str(getattr(finding, key)) for key in
                     ("rule_id", "file", "line", "evidence"))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


asset_inventory = inventory_assets
