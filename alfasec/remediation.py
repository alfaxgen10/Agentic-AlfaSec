"""Safe, approval-gated remediation planning.

This module only records proposed actions.  It never edits source files or
executes a patch.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .assets import finding_fingerprint
from .models import Finding

_STATUSES = {"proposed", "approved", "applied", "verified", "rejected", "reappeared"}
_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|token|secret|password|private[_-]?key)\s*[:=]\s*[\"']?[^\"'\s,;]+"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(value: str) -> str:
    return _SECRET.sub(lambda match: match.group(0).split("=")[0].split(":")[0] + "=<redacted>", value)


def _record(finding: Finding, now: str | None = None) -> dict:
    now = now or _now()
    recommendation = _redact(finding.remediation or "Review this finding and apply an appropriate fix.")
    return {
        "fingerprint": finding_fingerprint(finding),
        "finding": {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "file": finding.file,
            "line": finding.line,
        },
        "recommendation": recommendation,
        "patch_preview": _redact(
            f"Manual review at {finding.file}:{finding.line}; proposed change: {recommendation}"
        ),
        "approval_required": True,
        "status": "proposed",
        "created_at": now,
        "updated_at": now,
        "verification": None,
        "history": [{"status": "proposed", "at": now}],
    }


def remediation_plan(findings: Iterable[Finding]) -> dict:
    """Build a redacted, non-applying remediation plan for findings."""
    records = [_record(item) for item in findings]
    return {
        "version": 1,
        "updated_at": _now(),
        "records": records,
        "summary": _summary(records),
    }


def _summary(records: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for record in records:
        status = record.get("status", "proposed")
        counts[status] = counts.get(status, 0) + 1
    return {"total": len(records), "counts": counts}


def _merge(existing: dict, incoming: dict) -> dict:
    old_records = {item.get("fingerprint"): item for item in existing.get("records", [])}
    merged = []
    for fresh in incoming.get("records", []):
        old = old_records.pop(fresh.get("fingerprint"), None)
        if old:
            preserved = {**fresh, **old}
            preserved["finding"] = fresh.get("finding", old.get("finding", {}))
            preserved["recommendation"] = fresh.get("recommendation", old.get("recommendation", ""))
            preserved["patch_preview"] = fresh.get("patch_preview", old.get("patch_preview", ""))
            preserved["updated_at"] = _now()
            merged.append(preserved)
        else:
            merged.append(fresh)
    # Keep historical records so fixed findings can be verified later.
    merged.extend(old_records.values())
    result = {"version": 1, "updated_at": _now(), "records": merged}
    result["summary"] = _summary(merged)
    return result


def save_remediation_plan(path: Path, plan: dict) -> dict:
    """Persist a plan, merging with an existing plan to preserve history."""
    path = Path(path)
    try:
        existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot read remediation plan {path}: {error}") from error
    merged = _merge(existing, plan) if existing.get("records") else plan
    merged["summary"] = _summary(merged.get("records", []))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    except OSError as error:
        raise RuntimeError(f"Cannot write remediation plan {path}: {error}") from error
    return merged


def load_remediation_plan(path: Path) -> dict:
    path = Path(path)
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot read remediation plan {path}: {error}") from error
    plan.setdefault("records", [])
    plan["summary"] = _summary(plan["records"])
    return plan


def approve_remediation(path: Path, fingerprint: str) -> dict:
    """Approve one record only; this function never changes source code."""
    plan = load_remediation_plan(path)
    now = _now()
    for record in plan["records"]:
        if record.get("fingerprint") == fingerprint:
            record["status"] = "approved"
            record["approval_required"] = True
            record["updated_at"] = now
            record.setdefault("history", []).append({"status": "approved", "at": now})
            plan["updated_at"] = now
            plan["summary"] = _summary(plan["records"])
            Path(path).write_text(json.dumps(plan, indent=2), encoding="utf-8")
            return plan
    raise KeyError(f"Finding fingerprint not found in remediation plan: {fingerprint}")


def verify_remediation(findings: Iterable[Finding], plan: dict) -> dict:
    """Mark planned records verified when absent, or reappeared when present."""
    current = {finding_fingerprint(item) for item in findings}
    now = _now()
    for record in plan.get("records", []):
        fingerprint = record.get("fingerprint")
        status = "reappeared" if fingerprint in current else "verified"
        record["status"] = status
        record["verification"] = {
            "status": status,
            "verified_at": now,
            "finding_present": fingerprint in current,
        }
        record["updated_at"] = now
        record.setdefault("history", []).append({"status": status, "at": now})
    plan["updated_at"] = now
    plan["summary"] = _summary(plan.get("records", []))
    return plan


def verify_remediation_plan(path: Path, findings: Iterable[Finding]) -> dict:
    """Verify a persisted plan against a fresh scan and save the result."""
    plan = load_remediation_plan(path)
    verified = verify_remediation(findings, plan)
    try:
        Path(path).write_text(json.dumps(verified, indent=2), encoding="utf-8")
    except OSError as error:
        raise RuntimeError(f"Cannot write remediation plan {path}: {error}") from error
    return verified
