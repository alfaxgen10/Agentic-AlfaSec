"""Transparent risk prioritization and finding workflow records."""
from __future__ import annotations

import json
import os
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from threading import RLock

_SEVERITY = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0}
_CONFIDENCE = {"HIGH": 1.0, "MEDIUM": 0.75, "LOW": 0.5}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _date_value(value: str | None, field: str) -> date | None:
    if value is None or value == "":
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{field} must use YYYY-MM-DD") from error


def risk_score(finding: dict) -> dict:
    """Return a bounded, explainable score; this is prioritization, not exploitability."""
    severity = str(finding.get("severity", "INFO")).upper()
    confidence = str(finding.get("confidence", "LOW")).upper()
    base = _SEVERITY.get(severity, 0)
    multiplier = _CONFIDENCE.get(confidence, 0.5)
    score = round(base * multiplier, 2)
    if score >= 8:
        priority = "urgent"
    elif score >= 5:
        priority = "high"
    elif score >= 2:
        priority = "normal"
    else:
        priority = "informational"
    return {
        "score": score,
        "priority": priority,
        "factors": {
            "severity": severity,
            "severity_points": base,
            "confidence": confidence,
            "confidence_multiplier": multiplier,
        },
        "limitations": [
            "Score prioritizes review using scanner severity and confidence.",
            "It does not prove exploitability, business impact, or asset exposure.",
        ],
    }


def enrich_findings(findings: list[dict], workflow: dict | None = None) -> list[dict]:
    records = (workflow or {}).get("findings", {})
    today = datetime.now(timezone.utc).date()
    enriched = []
    for finding in findings:
        item = dict(finding)
        fingerprint = str(item.get("fingerprint", ""))
        item["risk"] = risk_score(item)
        record = records.get(fingerprint)
        if record:
            due = _date_value(record.get("due_date"), "due_date")
            expires = _date_value(record.get("expires_at"), "expires_at")
            overdue = bool(due and due < today and record.get("state") not in {"resolved", "false-positive"})
            expired = bool(expires and expires < today and record.get("state") == "accepted-risk")
            state = record.get("state", "open")
            effective_state = "reopened" if state in {"resolved", "false-positive"} else state
            item["workflow"] = {
                "state": state,
                "effective_state": effective_state,
                "owner": record.get("owner"),
                "due_date": record.get("due_date"),
                "expires_at": record.get("expires_at"),
                "decision": record.get("decision"),
                "updated_at": record.get("updated_at"),
                "overdue": overdue,
                "expired": expired,
                "attention_required": overdue or expired or effective_state == "reopened",
            }
        else:
            item["workflow"] = {"state": "open", "owner": None, "due_date": None,
                                "expires_at": None, "decision": None, "updated_at": None,
                                "effective_state": "open", "overdue": False, "expired": False,
                                "attention_required": False}
        enriched.append(item)
    return enriched


class FindingWorkflow:
    """Atomic, local-only records for ownership and accepted-risk decisions."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path or os.environ.get(
            "ALFASEC_WORKFLOW_PATH", ".alfasec/workflow.json")).expanduser()
        self._lock = RLock()

    def _read(self) -> dict:
        if not self.path.exists():
            return {"findings": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Cannot read finding workflow {self.path}: {error}") from error
        return data if isinstance(data, dict) and isinstance(data.get("findings", {}), dict) else {"findings": {}}

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".workflow-", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def update(self, fingerprint: str, *, state: str = "open", owner: str | None = None,
               due_date: str | None = None, decision: str | None = None,
               rationale: str | None = None, expires_at: str | None = None) -> dict:
        allowed = {"open", "in-progress", "accepted-risk", "false-positive", "resolved"}
        if not fingerprint:
            raise ValueError("fingerprint is required")
        if state not in allowed:
            raise ValueError(f"state must be one of: {', '.join(sorted(allowed))}")
        if state in {"accepted-risk", "false-positive"} and not rationale:
            raise ValueError("rationale is required for accepted-risk or false-positive decisions")
        _date_value(due_date, "due_date")
        _date_value(expires_at, "expires_at")
        if state == "accepted-risk" and not expires_at:
            raise ValueError("expires_at is required for accepted-risk decisions")
        with self._lock:
            data = self._read()
            previous = data["findings"].get(fingerprint, {})
            record = {
                "fingerprint": fingerprint, "state": state, "owner": owner,
                "due_date": due_date, "decision": decision, "rationale": rationale,
                "expires_at": expires_at,
                "created_at": previous.get("created_at", _now()), "updated_at": _now(),
            }
            data["findings"][fingerprint] = record
            self._write(data)
            return dict(record)

    def get_all(self) -> dict:
        with self._lock:
            return dict(self._read().get("findings", {}))


def risk_summary(findings: list[dict]) -> dict:
    counts = {}
    total = 0.0
    for finding in findings:
        risk = finding.get("risk") or risk_score(finding)
        priority = risk["priority"]
        counts[priority] = counts.get(priority, 0) + 1
        total += float(risk["score"])
    attention = sum(1 for finding in findings
                    if (finding.get("workflow") or {}).get("attention_required"))
    return {"total_score": round(total, 2), "priority_counts": counts,
            "attention_required": attention,
            "method": "severity points multiplied by confidence multiplier"}


def governance_summary(records: dict, findings: list[dict] | None = None) -> dict:
    today = datetime.now(timezone.utc).date()
    counts: dict[str, int] = {}
    overdue = expired = unowned = 0
    for record in records.values():
        state = record.get("state", "open")
        counts[state] = counts.get(state, 0) + 1
        due = _date_value(record.get("due_date"), "due_date")
        expires = _date_value(record.get("expires_at"), "expires_at")
        if due and due < today and state not in {"resolved", "false-positive"}:
            overdue += 1
        if expires and expires < today and state == "accepted-risk":
            expired += 1
        if not record.get("owner") and state not in {"resolved", "false-positive"}:
            unowned += 1
    return {
        "state_counts": counts, "overdue": overdue, "expired_accepted_risks": expired,
        "unowned_open": unowned, "tracked": len(records),
        "observed_findings": len(findings or []),
        "limitations": ["Governance dates are local workflow metadata and do not establish exploitability."],
    }
