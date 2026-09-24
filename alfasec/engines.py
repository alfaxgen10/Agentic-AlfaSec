"""Scan engines and orchestration."""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Protocol
from .models import Finding, ScanRequest, EngineResult, ScanResult
from .rules import scan_file, AST_EXTENSIONS, SUPPORTED_EXTENSIONS, IGNORED_DIRECTORIES
from .analysis import scan_javascript_ast, scan_javascript_project
from .dependencies import dependencies, dependency_findings, osv_lookup
from .lifecycle import update_finding_history
from .coverage import scan_coverage, finding_quality
from .secrets import scan_secrets, scan_git_history
from .configuration import ConfigurationEngine
from .python_analysis import PythonAstEngine
from .java_analysis import JavaAstEngine
from .assets import inventory_assets
from .correlation import correlate_findings
from .remediation import remediation_plan

def confidence_rank(value: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(value, 0)

class ScanEngine(Protocol):
    engine_id: str

    def run(self, request: ScanRequest) -> EngineResult:
        ...

class HeuristicEngine:
    engine_id = "heuristics"

    def run(self, request: ScanRequest) -> EngineResult:
        findings = []
        errors = []
        paths = list(request.scope.root.rglob("*")) if request.scope.root.is_dir() else [request.scope.root]
        for path in paths:
            if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.parts):
                continue
            if path.stat().st_size <= 2_000_000 and path.suffix.lower() in SUPPORTED_EXTENSIONS and path.suffix.lower() not in AST_EXTENSIONS:
                findings.extend(scan_file(path))
        return EngineResult(self.engine_id, findings, {"mode": "pattern rules"}, errors)

class JavaScriptAstEngine:
    engine_id = "javascript-typescript-ast"

    def run(self, request: ScanRequest) -> EngineResult:
        try:
            root = request.scope.root
            has_javascript = root.is_dir() and any(
                path.is_file() and path.suffix.lower() in AST_EXTENSIONS
                and not any(part in IGNORED_DIRECTORIES for part in path.parts)
                for path in root.rglob("*")
            )
            findings = scan_javascript_project(root) if has_javascript else []
            return EngineResult(self.engine_id, findings, {"mode": "parser and data-flow"}, [])
        except (OSError, RuntimeError) as error:
            return EngineResult(self.engine_id, [], {}, [str(error)])

class DependencyEngine:
    engine_id = "dependencies"

    def run(self, request: ScanRequest) -> EngineResult:
        items = dependencies(request.scope.root)
        advisories = osv_lookup(items) if request.profile.include_osv else []
        return EngineResult(
            self.engine_id,
            dependency_findings(items, advisories),
            {"dependencies": items, "advisories": len(advisories), "osv_enabled": request.profile.include_osv},
            [],
        )

class SecretsEngine:
    engine_id = "secrets"

    def run(self, request: ScanRequest) -> EngineResult:
        findings = scan_secrets(request.scope.root)
        if request.profile.include_git_history:
            findings.extend(scan_git_history(request.scope.root))
        return EngineResult(
            self.engine_id,
            findings,
            {"provider_patterns": 5, "entropy_analysis": "generic assignments", "git_history": request.profile.include_git_history},
            [],
        )

def engine_registry() -> tuple[ScanEngine, ...]:
    return (HeuristicEngine(), JavaScriptAstEngine(), PythonAstEngine(), JavaAstEngine(), DependencyEngine(), SecretsEngine(), ConfigurationEngine())

def scan_project(root: Path) -> list[Finding]:
    findings = scan_secrets(root)
    paths = list(root.rglob("*")) if root.is_dir() else [root]
    if root.is_dir() and any(
        path.is_file() and path.suffix.lower() in AST_EXTENSIONS
        and not any(part in IGNORED_DIRECTORIES for part in path.parts)
        for path in paths
    ):
        findings.extend(scan_javascript_project(root))
        paths = list(root.rglob("*"))
    for path in paths:
        if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue
        if path.stat().st_size <= 2_000_000 and path.suffix.lower() in SUPPORTED_EXTENSIONS:
            if path.suffix.lower() in AST_EXTENSIONS:
                findings.extend(scan_javascript_ast(path))
            else:
                findings.extend(scan_file(path))
    return deduplicate(findings)

def run_scan(request: ScanRequest, engines: Iterable[ScanEngine] | None = None) -> ScanResult:
    started = datetime.now(timezone.utc)
    selected = tuple(engines or engine_registry())
    results = [engine.run(request) for engine in selected]
    errors = [f"{result.engine_id}: {error}" for result in results for error in result.errors]
    if errors:
        raise RuntimeError("Scan engines failed: " + "; ".join(errors))
    findings = deduplicate(item for result in results for item in result.findings)
    lifecycle = None
    if request.profile.include_history:
        lifecycle = update_finding_history(request.scope.root, findings, request.profile.history_path)
    return ScanResult(
        scan_id=f"scan-{started.strftime('%Y%m%dT%H%M%SZ')}-{hashlib.sha256(str(request.scope.root).encode()).hexdigest()[:8]}",
        started_at=started.isoformat(),
        completed_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        engines=results,
        coverage=scan_coverage(request.scope.root),
        quality=finding_quality(findings),
        dependencies=dependencies(request.scope.root) if request.profile.include_dependencies else [],
        lifecycle=lifecycle,
        assets=inventory_assets(
            request.scope.root, findings,
            dependencies(request.scope.root) if request.profile.include_dependencies else [],
        ),
        correlations=correlate_findings(findings),
        remediation=remediation_plan(findings)["summary"],
    )

def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, int, str], Finding] = {}
    for item in findings:
        exact_key = (item.rule_id, item.file, item.line, item.evidence)
        if exact_key in unique:
            continue
        overlap = next(
            (key for key, existing in unique.items() if _overlaps(existing, item)),
            None,
        )
        if overlap is None:
            unique[exact_key] = item
        elif confidence_rank(item.confidence) > confidence_rank(unique[overlap].confidence):
            unique[overlap] = item
    return list(unique.values())


def _overlaps(first: Finding, second: Finding) -> bool:
    """Merge only adjacent reports for the same CWE and vulnerability family."""
    if first.file != second.file or first.cwe != second.cwe:
        return False
    if abs(first.line - second.line) > 1:
        return False
    families = (
        ("command", "exec"),
        ("sql", "query"),
        ("xss", "html"),
        ("path", "traversal"),
    )
    first_text = f"{first.rule_id} {first.title}".lower()
    second_text = f"{second.rule_id} {second.title}".lower()
    return any(
        any(term in first_text for term in terms)
        and any(term in second_text for term in terms)
        for terms in families
    )
