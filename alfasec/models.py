"""Core scan data models."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe: str
    cve: str | None
    cvss: str
    file: str
    line: int
    evidence: str
    remediation: str
    status: str = "open"

@dataclass(frozen=True)
class ScanScope:
    root: Path
    authorized_paths: tuple[str, ...] = ()

@dataclass(frozen=True)
class ScanProfile:
    name: str = "default"
    include_code: bool = True
    include_dependencies: bool = True
    include_history: bool = True
    include_osv: bool = False
    include_git_history: bool = False
    history_path: Path | None = None

@dataclass(frozen=True)
class ScanRequest:
    scope: ScanScope
    profile: ScanProfile = ScanProfile()

@dataclass
class EngineResult:
    engine_id: str
    findings: list[Finding]
    metadata: dict
    errors: list[str]

@dataclass
class ScanResult:
    scan_id: str
    started_at: str
    completed_at: str
    findings: list[Finding]
    engines: list[EngineResult]
    coverage: dict
    quality: dict
    dependencies: list[dict]
    lifecycle: dict | None
    assets: dict = field(default_factory=dict)
    correlations: list[dict] = field(default_factory=list)
    remediation: dict | None = None
