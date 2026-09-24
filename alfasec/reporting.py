"""Finding report exporters."""
from __future__ import annotations
import csv
import html
import json
import hashlib
import re
from dataclasses import asdict
from pathlib import Path
from .models import Finding
def exports(findings: list[Finding], output: Path, fmt: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output.write_text(json.dumps([asdict(item) for item in findings], indent=2), encoding="utf-8")
    elif fmt == "csv":
        with output.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=asdict(findings[0]).keys() if findings else [field.name for field in Finding.__dataclass_fields__.values()])
            writer.writeheader()
            writer.writerows(asdict(item) for item in findings)
    elif fmt == "sarif":
        rules = {}
        for item in findings:
            if item.rule_id in rules:
                continue
            rule = {
                "id": item.rule_id,
                "shortDescription": {"text": item.title},
                "help": {"text": item.remediation or item.title},
                "properties": {"cwe": item.cwe} if item.cwe else {},
            }
            cwe_match = re.search(r"(\d+)", item.cwe or "")
            if cwe_match:
                rule["helpUri"] = (
                    "https://cwe.mitre.org/data/definitions/"
                    f"{cwe_match.group(1)}.html"
                )
            rules[item.rule_id] = rule
        results = []
        for item in findings:
            level = {
                "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "none",
            }.get(item.severity.upper(), "warning")
            fingerprint = hashlib.sha256(
                f"{item.rule_id}|{item.file}|{item.line}|{item.evidence}".encode()
            ).hexdigest()
            results.append({
                "ruleId": item.rule_id,
                "level": level,
                "message": {"text": item.title},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": item.file},
                    "region": {"startLine": item.line},
                }}],
                "fingerprints": {"alfasec/v1": fingerprint},
                "partialFingerprints": {"alfasec/v1": fingerprint},
            })
        document = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "runs": [{"tool": {"driver": {
                        "name": "Agentic AlfaSec", "rules": list(rules.values())
                    }}, "results": results}]}
        output.write_text(json.dumps(document, indent=2), encoding="utf-8")
    else:
        rows = "".join(f"<tr><td>{html.escape(item.severity)}</td><td>{html.escape(item.title)}</td><td>{html.escape(item.file)}:{item.line}</td><td>{html.escape(item.evidence)}</td></tr>" for item in findings)
        output.write_text(f"<!doctype html><meta charset='utf-8'><title>Agentic AlfaSec report</title><h1>Agentic AlfaSec report</h1><table border='1'><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Evidence</th></tr>{rows}</table>", encoding="utf-8")
