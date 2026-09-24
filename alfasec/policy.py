"""Configurable CI policy gates for scan findings."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
DEFAULT_POLICY = {
    "max_severity": "CRITICAL",
    "minimum_confidence": "LOW",
    "ignored_rule_ids": [],
}


def _choice(value: Any, choices: tuple[str, ...], name: str) -> str:
    if not isinstance(value, str) or value.upper() not in choices:
        raise ValueError(f"{name} must be one of {', '.join(choices)}")
    return value.upper()


def normalize_policy(policy: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate a policy and fill missing fields with conservative defaults."""
    if policy is None:
        policy = {}
    if not isinstance(policy, Mapping):
        raise ValueError("policy must be a JSON object")
    result = dict(DEFAULT_POLICY)
    # Accept the common spelling used by older CI configuration examples.
    result.update(policy)
    result["max_severity"] = _choice(result["max_severity"], SEVERITIES, "max_severity")
    result["minimum_confidence"] = _choice(
        result["minimum_confidence"], CONFIDENCES, "minimum_confidence"
    )
    ignored = result["ignored_rule_ids"]
    if not isinstance(ignored, list) or not all(isinstance(item, str) for item in ignored):
        raise ValueError("ignored_rule_ids must be a list of strings")
    result["ignored_rule_ids"] = list(dict.fromkeys(ignored))
    return result


def load_policy(path: Path | str) -> dict[str, Any]:
    """Load and validate a JSON policy, raising clear configuration errors."""
    path = Path(path)
    try:
        with path.open(encoding="utf-8") as stream:
            document = json.load(stream)
    except FileNotFoundError as error:
        raise ValueError(f"policy file not found: {path}") from error
    except (OSError, UnicodeError) as error:
        raise ValueError(f"could not read policy file {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid policy JSON in {path}: {error.msg}") from error
    try:
        return normalize_policy(document)
    except ValueError as error:
        raise ValueError(f"invalid policy in {path}: {error}") from error


def evaluate_policy(findings: list[Any], policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return gate status, blocked findings, and human-readable blocking reasons."""
    config = normalize_policy(policy)
    severity_limit = SEVERITIES.index(config["max_severity"])
    confidence_floor = CONFIDENCES.index(config["minimum_confidence"])
    blocked = []
    reasons = []
    ignored = set(config["ignored_rule_ids"])
    for finding in findings:
        rule_id = getattr(finding, "rule_id", "")
        if rule_id in ignored:
            continue
        severity = str(getattr(finding, "severity", "INFO")).upper()
        confidence = str(getattr(finding, "confidence", "LOW")).upper()
        if severity not in SEVERITIES or confidence not in CONFIDENCES:
            continue
        # Higher severity/confidence appears earlier in each ordered list.
        if SEVERITIES.index(severity) <= severity_limit and CONFIDENCES.index(confidence) <= confidence_floor:
            blocked.append(finding)
            reasons.append(
                f"{rule_id} ({severity}, {confidence} confidence) meets the "
                f"{config['max_severity']} severity and {config['minimum_confidence']} "
                "confidence gate"
            )
    passed = not blocked
    return {
        "passed": passed,
        "pass": passed,
        "fail": not passed,
        "blocked_findings": blocked,
        "reasons": reasons,
        "policy": config,
    }
