"""Loopback-only HTTP API for running bounded local project scans.

This module deliberately uses only the Python standard library.  It is a
separate service from the Java network-check agent so either service can be
updated or stopped independently.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .engines import run_scan
from .models import ScanProfile, ScanRequest, ScanScope
from .policy import evaluate_policy
from .registry import ProjectRegistry, normalize_scan_summary
from .workflow import FindingWorkflow, enrich_findings, governance_summary, risk_summary
from .remediation import load_remediation_plan, verify_remediation
from dataclasses import asdict

MAX_JOBS = 2
DEFAULT_TIMEOUT = 300
DEFAULT_PORT = 8775


class AuditLog:
    """Append-only local audit trail that never records tokens or source content."""

    def __init__(self, path: Path | None):
        self.path = path
        self.lock = threading.Lock()

    def write(self, event: str, **details: object) -> None:
        if self.path is None:
            return
        safe_details = {key: value for key, value in details.items()
                        if key.lower() not in {"token", "secret", "password", "source", "content"}}
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **safe_details}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def authorized_roots(value: str | None = None) -> tuple[Path, ...]:
    raw = value if value is not None else os.environ.get("ALFASEC_ALLOWED_ROOTS", os.getcwd())
    roots = []
    for item in raw.split(os.pathsep):
        if item.strip():
            path = Path(item).expanduser().resolve()
            if path.exists() and path.is_dir():
                roots.append(path)
    return tuple(roots)


def authorize_project(value: str, roots: tuple[Path, ...]) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("project_path is required")
    path = Path(value).expanduser().resolve()
    if not path.exists() or not path.is_dir():
        raise ValueError("project_path must be an existing local directory")
    if not any(_inside(path, root) for root in roots):
        raise ValueError("project_path is outside the authorized local roots")
    return path


class ScanJobs:
    def __init__(self, roots: tuple[Path, ...], max_jobs: int = MAX_JOBS, timeout: int = DEFAULT_TIMEOUT,
                 registry: ProjectRegistry | None = None, audit: AuditLog | None = None):
        self.roots, self.timeout = roots, timeout
        self.executor = ThreadPoolExecutor(max_workers=max_jobs)
        self.jobs: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.max_jobs = max_jobs
        self.registry = registry or ProjectRegistry()
        self.audit = audit or AuditLog(None)

    def start(self, project_path: str) -> str:
        path = authorize_project(project_path, self.roots)
        with self.lock:
            active = sum(job["status"] in {"queued", "running"} for job in self.jobs.values())
            if active >= self.max_jobs:
                raise RuntimeError("scan capacity is full; retry later")
            job_id = uuid.uuid4().hex
            self.jobs[job_id] = {"id": job_id, "status": "queued", "project": str(path),
                                 "started_at": None, "completed_at": None, "result": None, "error": None}
        self.executor.submit(self._run, job_id, path)
        self.audit.write("scan_queued", job_id=job_id, project=str(path))
        return job_id

    def _run(self, job_id: str, path: Path) -> None:
        with self.lock:
            self.jobs[job_id]["status"] = "running"
            self.jobs[job_id]["started_at"] = time.time()
        try:
            request = ScanRequest(ScanScope(path), ScanProfile())
            scan = run_scan(request)
            findings = [asdict(item) for item in scan.findings]
            lifecycle_records = (scan.lifecycle or {}).get("findings", [])
            fingerprints = {(item.get("rule_id"), item.get("file"), item.get("line")): item.get("fingerprint")
                            for item in lifecycle_records}
            for finding in findings:
                finding["fingerprint"] = fingerprints.get(
                    (finding.get("rule_id"), finding.get("file"), finding.get("line")), "")
            workflow = FindingWorkflow(path / ".alfasec" / "workflow.json")
            workflow_records = workflow.get_all()
            findings = enrich_findings(findings, {"findings": workflow_records})
            policy = evaluate_policy(scan.findings, {})
            result = {
                "scan_id": scan.scan_id, "scanned_at": scan.completed_at,
                "findings": findings,
                "coverage": scan.coverage, "quality": scan.quality,
                "policy": {"passed": policy["passed"], "blocked_findings": [asdict(i) for i in policy["blocked_findings"]],
                           "reasons": policy["reasons"], "config": policy["policy"]},
                "assets": scan.assets, "correlations": scan.correlations,
                "remediation": scan.remediation or {},
                "risk": risk_summary(findings),
                "governance": governance_summary(workflow_records, findings),
                "engines": [{"engine_id": e.engine_id, "metadata": e.metadata, "errors": e.errors} for e in scan.engines],
            }
            with self.lock:
                self.jobs[job_id].update(status="complete", completed_at=time.time(), result=result)
            self.registry.record_scan(path, normalize_scan_summary(result))
            self.audit.write("scan_completed", job_id=job_id, findings=len(findings))
        except Exception as error:  # make failures visible to the API, never a false success
            with self.lock:
                self.jobs[job_id].update(status="failed", completed_at=time.time(),
                                         error=f"{type(error).__name__}: {error}")
            self.audit.write("scan_failed", job_id=job_id, error=type(error).__name__)

    def get(self, job_id: str) -> dict:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError("unknown scan id")
            if job["status"] == "running" and job["started_at"] and time.time() - job["started_at"] > self.timeout:
                job.update(status="timed_out", completed_at=time.time(),
                           error=f"scan exceeded {self.timeout} second timeout")
            public = {key: value for key, value in job.items() if key != "project"}
            if job["status"] == "complete":
                public["result_available"] = True
            return public

    def result(self, job_id: str) -> dict:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError("unknown scan id")
            if job["status"] == "running" and job["started_at"] and time.time() - job["started_at"] > self.timeout:
                job.update(status="timed_out", completed_at=time.time(),
                           error=f"scan exceeded {self.timeout} second timeout")
            if job["status"] != "complete":
                raise RuntimeError(f"scan is {job['status']}")
            return job["result"]


class ScanHandler(BaseHTTPRequestHandler):
    server_version = "AlfaSecScan/1"

    def _api(self) -> "ScanServer":
        return self.server  # type: ignore[return-value]

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        origin = self.headers.get("Origin")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", origin if self._api().origin_allowed(origin) else "null")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-AlfaSec-Token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        allowed = self._api().origin_allowed(self.headers.get("Origin"))
        valid = secrets.compare_digest(self.headers.get("X-AlfaSec-Token", ""), self._api().token)
        if not (allowed and valid):
            self._api().audit.write("request_denied", method=self.command, path=urlparse(self.path).path)
        return allowed and valid

    def do_OPTIONS(self) -> None:
        self._json(204, {})

    def do_GET(self) -> None:
        if not self._authorized():
            self._json(401, {"error": "valid local origin and X-AlfaSec-Token required"}); return
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/scan/health":
                self._json(200, {"service": "alfasec-python-scan", "status": "ready", "scope": "authorized local roots"})
            elif parsed.path == "/scan/status":
                self._json(200, self._api().jobs.get(parse_qs(parsed.query).get("id", [""])[0]))
            elif parsed.path == "/scan/result":
                self._json(200, self._api().jobs.result(parse_qs(parsed.query).get("id", [""])[0]))
            elif parsed.path == "/projects":
                self._json(200, {"projects": self._api().jobs.registry.list_projects()})
            elif parsed.path in {"/projects/history", "/projects/summary"}:
                project_id = parse_qs(parsed.query).get("id", [""])[0]
                payload = (self._api().jobs.registry.history(project_id)
                           if parsed.path.endswith("history") else self._api().jobs.registry.summary(project_id))
                self._json(200, payload if isinstance(payload, dict) else {"history": payload})
            elif parsed.path == "/projects/findings":
                project_id = parse_qs(parsed.query).get("id", [""])[0]
                project = self._api().jobs.registry.get(project_id)
                path = authorize_project(project["root"], self._api().roots)
                records = FindingWorkflow(path / ".alfasec" / "workflow.json").get_all()
                self._json(200, {"project_id": project_id, "findings": records})
            elif parsed.path == "/projects/governance":
                project_id = parse_qs(parsed.query).get("id", [""])[0]
                project = self._api().jobs.registry.get(project_id)
                path = authorize_project(project["root"], self._api().roots)
                workflow = FindingWorkflow(path / ".alfasec" / "workflow.json")
                self._json(200, {"project_id": project_id,
                                 "governance": governance_summary(workflow.get_all())})
            else:
                self._json(404, {"error": "endpoint not found"})
        except (KeyError, RuntimeError) as error:
            self._json(404 if isinstance(error, KeyError) else 409, {"error": str(error)})

    def do_POST(self) -> None:
        if not self._authorized():
            self._json(401, {"error": "valid local origin and X-AlfaSec-Token required"}); return
        endpoint = urlparse(self.path).path
        if endpoint not in {"/scan/start", "/projects/register", "/projects/finding-action",
                            "/projects/remediation-verify"}:
            self._json(404, {"error": "endpoint not found"}); return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16_384:
                raise ValueError("request body is too large")
            payload = json.loads(self.rfile.read(length))
            if endpoint == "/projects/remediation-verify":
                project = self._api().jobs.registry.get(payload.get("project_id", ""))
                path = authorize_project(project["root"], self._api().roots)
                plan_path = Path(payload.get("plan_path") or (path / ".alfasec" / "remediation.json")).expanduser().resolve()
                if not _inside(plan_path, path) or not plan_path.is_file():
                    raise ValueError("plan_path must be an existing file inside the project")
                scan = run_scan(ScanRequest(
                    ScanScope(path),
                    ScanProfile(include_history=False, include_osv=False, include_git_history=False),
                ))
                plan = verify_remediation(load_remediation_plan(plan_path), scan.findings)
                plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
                self._json(200, plan); return
            if endpoint == "/projects/finding-action":
                project = self._api().jobs.registry.get(payload.get("project_id", ""))
                path = authorize_project(project["root"], self._api().roots)
                record = FindingWorkflow(path / ".alfasec" / "workflow.json").update(
                    payload.get("fingerprint", ""), state=payload.get("state", "open"),
                    owner=payload.get("owner"), due_date=payload.get("due_date"),
                    decision=payload.get("decision"), rationale=payload.get("rationale"),
                    expires_at=payload.get("expires_at"))
                self._json(200, record); return
            path = authorize_project(payload.get("project_path"), self._api().roots)
            if endpoint == "/projects/register":
                self._json(201, self._api().jobs.registry.register(path, payload.get("name"))); return
            job_id = self._api().jobs.start(str(path))
            self._json(202, {"id": job_id, "status": "queued"})
        except (ValueError, json.JSONDecodeError, KeyError) as error:
            self._json(400, {"error": str(error)})
        except RuntimeError as error:
            self._json(429, {"error": str(error)})

    def log_message(self, *_args) -> None:
        return


class ScanServer(ThreadingHTTPServer):
    def __init__(self, address, roots, token, timeout=DEFAULT_TIMEOUT, registry_path=None):
        super().__init__(address, ScanHandler)
        self.token, self.roots = token, roots
        audit_path = Path(os.environ["ALFASEC_AUDIT_LOG"]).expanduser().resolve() if os.environ.get("ALFASEC_AUDIT_LOG") else (
            roots[0] / ".alfasec" / "audit.log" if roots else None)
        self.audit = AuditLog(audit_path)
        self.jobs = ScanJobs(roots, timeout=timeout, registry=ProjectRegistry(registry_path), audit=self.audit)

    @staticmethod
    def origin_allowed(origin: str | None) -> bool:
        return origin is None or origin in {"http://localhost:8000", "http://127.0.0.1:8000"} or (
            origin.startswith("https://") and origin.endswith(".github.io"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Loopback AlfaSec Python scan API")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--allow-root", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--token")
    args = parser.parse_args()
    roots = authorized_roots(os.pathsep.join(args.allow_root) if args.allow_root else None)
    if not roots:
        raise SystemExit("No existing authorized roots")
    token = args.token or secrets.token_urlsafe(32)
    server = ScanServer(("127.0.0.1", args.port), roots, token, args.timeout)
    print(f"Python scan API listening on http://127.0.0.1:{args.port}", flush=True)
    print(f"Session token: {token}", flush=True)
    print("Authorized roots: " + ", ".join(map(str, roots)), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
