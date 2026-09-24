"""Conservative, evidence-linked finding correlation."""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from .models import Finding
from .assets import finding_fingerprint

_SEVERITY = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_SOURCE = re.compile(r"\b(request|input|query|param|upload|user|source)\b", re.I)
_SINK = re.compile(r"\b(exec|command|sql|query|html|innerhtml|deserialize|path|file|sink)\b", re.I)
_CONFIG = re.compile(r"docker|compose|k8s|kubernetes|workflow|action|\.ya?ml|dockerfile", re.I)


def _family(rule_id: str) -> str:
    return rule_id.lower().split("-", 1)[0]


def correlate_findings(findings: list[Finding]) -> list[dict]:
    """Group only findings with a concrete shared signal.

    A group is not an exploit claim.  It records the signal that caused the
    association and explicitly limits interpretation.
    """
    if len(findings) < 2:
        return []
    edges: dict[int, set[int]] = defaultdict(set)
    reasons: dict[tuple[int, int], str] = {}
    for left, first in enumerate(findings):
        for right in range(left + 1, len(findings)):
            second = findings[right]
            reason = None
            if first.file == second.file:
                reason = "shared file"
            elif _family(first.rule_id) == _family(second.rule_id):
                reason = "shared rule family"
            elif ((_SOURCE.search(first.evidence) and _SINK.search(second.evidence)) or
                  (_SOURCE.search(second.evidence) and _SINK.search(first.evidence))):
                reason = "source/sink evidence terms"
            elif (_CONFIG.search(first.file) != _CONFIG.search(second.file) and
                  (_CONFIG.search(first.file) or _CONFIG.search(second.file))):
                # Configuration + code is useful only when both findings have
                # evidence, rather than treating every config warning alike.
                if first.evidence.strip() and second.evidence.strip():
                    reason = "configuration and code relationship"
            if reason:
                edges[left].add(right)
                edges[right].add(left)
                reasons[(left, right)] = reason
    groups, seen = [], set()
    for start in range(len(findings)):
        if start in seen or start not in edges:
            continue
        members, queue = [], [start]
        while queue:
            index = queue.pop()
            if index in seen:
                continue
            seen.add(index)
            members.append(index)
            queue.extend(edges[index] - seen)
        if len(members) < 2:
            continue
        items = [findings[index] for index in sorted(members)]
        signals = sorted({reason for pair, reason in reasons.items()
                          if pair[0] in members and pair[1] in members})
        severity = max(items, key=lambda item: _SEVERITY.get(item.severity.upper(), 0)).severity
        confidence = "high" if all(item.confidence.lower() == "high" for item in items) else "medium"
        fingerprints = [finding_fingerprint(item) for item in items]
        groups.append({
            "group_id": f"risk-{finding_fingerprint(items[0])}",
            "kind": "risk_group",
            "title": "Related findings requiring review",
            "severity": severity,
            "confidence": confidence,
            "finding_fingerprints": fingerprints,
            "finding_references": [
                {"fingerprint": fp, "rule_id": item.rule_id, "file": item.file, "line": item.line}
                for fp, item in zip(fingerprints, items)
            ],
            "rationale": "; ".join(signals),
            "attack_path": [
                {"from": item.file, "rule_id": item.rule_id}
                for item in items
            ] if "source/sink evidence terms" in signals else [],
            "limitations": [
                "Correlation indicates related evidence, not exploitability or a confirmed attack path.",
                "Dynamic behavior, deployment context, and reachability are not verified.",
            ],
        })
    return groups


correlate = correlate_findings
