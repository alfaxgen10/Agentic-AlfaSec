"""Small, atomic JSON registry for local projects and scan history."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

MAX_HISTORY = 50


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProjectRegistry:
    def __init__(self, path: Path | str | None = None, max_history: int = MAX_HISTORY):
        self.path = Path(path or os.environ.get("ALFASEC_REGISTRY_PATH", ".alfasec/registry.json")).expanduser()
        self.max_history = max(1, max_history)
        self._lock = RLock()

    @staticmethod
    def project_id(root: Path | str) -> str:
        return hashlib.sha256(str(Path(root).resolve()).encode("utf-8")).hexdigest()[:20]

    def _read(self) -> dict:
        if not self.path.exists():
            return {"projects": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Cannot read project registry {self.path}: {error}") from error
        return data if isinstance(data, dict) and isinstance(data.get("projects", {}), dict) else {"projects": {}}

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".registry-", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def register(self, root: Path | str, name: str | None = None) -> dict:
        root_path = Path(root).resolve()
        project_id = self.project_id(root_path)
        with self._lock:
            data = self._read()
            old = data["projects"].get(project_id, {})
            now = _now()
            project = {
                "id": project_id, "name": name or old.get("name") or root_path.name,
                "root": str(root_path), "created_at": old.get("created_at", now),
                "updated_at": now, "last_scan": old.get("last_scan"),
                "history": old.get("history", []),
            }
            data["projects"][project_id] = project
            self._write(data)
            return dict(project)

    def record_scan(self, root: Path | str, summary: dict, name: str | None = None) -> dict:
        project = self.register(root, name)
        with self._lock:
            data = self._read()
            project = data["projects"][project["id"]]
            record = dict(summary)
            record.setdefault("scanned_at", _now())
            record["project_id"] = project["id"]
            project["history"] = (project.get("history", []) + [record])[-self.max_history:]
            project["last_scan"] = record
            project["updated_at"] = _now()
            data["projects"][project["id"]] = project
            self._write(data)
            return dict(project)

    def list_projects(self) -> list[dict]:
        with self._lock:
            return [dict(item) for item in self._read()["projects"].values()]

    def get(self, project_id: str) -> dict:
        with self._lock:
            project = self._read()["projects"].get(project_id)
            if not project:
                raise KeyError("unknown project id")
            return dict(project)

    def history(self, project_id: str) -> list[dict]:
        return list(self.get(project_id).get("history", []))

    def summary(self, project_id: str) -> dict:
        project = self.get(project_id)
        history = project.get("history", [])
        return {"id": project["id"], "name": project["name"], "root": project["root"],
                "scan_count": len(history), "last_scan": project.get("last_scan"),
                "trend": [{"scanned_at": item.get("scanned_at"), "findings": item.get("findings_count", 0),
                            "risk_score": (item.get("risk") or {}).get("total_score", 0),
                            "policy_pass": item.get("policy_pass"),
                            "new": len(item.get("new_fingerprints", [])),
                            "fixed": len(item.get("fixed_fingerprints", [])),
                            "reappeared": len(item.get("reappeared_fingerprints", []))}
                           for item in history]}


def normalize_scan_summary(result: dict) -> dict:
    findings = result.get("findings", [])
    lifecycle = result.get("lifecycle") or {}
    records = lifecycle.get("findings", [])
    statuses = {item.get("status"): [] for item in records}
    for item in records:
        statuses.setdefault(item.get("status"), []).append(item.get("fingerprint"))
    fingerprints = {item.get("fingerprint") for item in records if item.get("fingerprint")}
    return {
        "scan_id": result.get("scan_id"), "scanned_at": result.get("scanned_at"),
        "findings_count": len(findings), "findings_counts": _severity_counts(findings),
        "fingerprints": sorted(fingerprints),         "new_fingerprints": [item.get("fingerprint") for item in records
                             if item.get("status") == "open" and item.get("first_seen") == item.get("last_seen")],
        "fixed_fingerprints": statuses.get("fixed", []),
        "reappeared_fingerprints": statuses.get("reappeared", []),
        "policy_pass": bool((result.get("policy") or {}).get("passed", False)),
        "risk": result.get("risk", {}),
        "coverage": result.get("coverage", {}), "engines": result.get("engines", []),
    }


def _severity_counts(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        counts[severity] = counts.get(severity, 0) + 1
    return counts
