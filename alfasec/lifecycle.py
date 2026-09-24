"""Finding fingerprints and persisted lifecycle history."""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from .models import Finding
def finding_fingerprint(item: Finding, root: Path) -> str:
    try:
        location = str(Path(item.file).resolve().relative_to(root.resolve()))
    except ValueError:
        location = item.file
    identity = "\n".join((item.rule_id, item.cwe, location, item.evidence))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]

def update_finding_history(root: Path, findings: list[Finding], history_path: Path | None = None) -> dict:
    history_path = history_path or root / ".alfasec" / "history.json"
    now = datetime.now(timezone.utc).isoformat()
    try:
        previous = json.loads(history_path.read_text(encoding="utf-8")) if history_path.exists() else {}
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot read finding history {history_path}: {error}") from error
    records = previous.get("findings", {})
    current = {}
    for item in findings:
        fingerprint = finding_fingerprint(item, root)
        old = records.get(fingerprint)
        status = "reappeared" if old and old.get("status") == "fixed" else "open"
        current[fingerprint] = {
            "fingerprint": fingerprint,
            "rule_id": item.rule_id,
            "file": item.file,
            "line": item.line,
            "title": item.title,
            "severity": item.severity,
            "first_seen": old.get("first_seen", now) if old else now,
            "last_seen": now,
            "times_seen": int(old.get("times_seen", 0)) + 1 if old else 1,
            "status": status,
        }
    for fingerprint, old in records.items():
        if fingerprint not in current and old.get("status") != "accepted-risk":
            current[fingerprint] = {**old, "status": "fixed"}
    history = {"updated_at": now, "findings": current}
    try:
        history_path.parent.mkdir(parents=True, exist_ok=True)
        history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
    except OSError as error:
        raise RuntimeError(f"Cannot write finding history {history_path}: {error}") from error
    counts = {}
    for record in current.values():
        counts[record["status"]] = counts.get(record["status"], 0) + 1
    return {"path": str(history_path), "counts": counts, "findings": list(current.values())}
