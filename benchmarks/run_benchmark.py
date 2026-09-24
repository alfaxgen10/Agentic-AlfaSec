"""Repeatable local accuracy and performance benchmark for AlfaSec."""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from alfasec.engines import run_scan
from alfasec.models import ScanProfile, ScanRequest, ScanScope

CASES = {
    "safe": {
        "expected_rules": set(),
        "description": "Parameterized SQL query",
    },
    "vulnerable": {
        "expected_rules": {"python-command-injection", "python-sql-injection",
                           "docker-user-root", "docker-add-remote"},
        "description": "Request data flowing to command/SQL sinks and unsafe Dockerfile",
    },
}


def run_case(name: str, iterations: int) -> dict:
    case = CASES[name]
    root = ROOT / "benchmarks" / "fixtures" / name
    durations = []
    observed = set()
    coverage = {}
    for _ in range(iterations):
        request = ScanRequest(
            ScanScope(root),
            ScanProfile(include_history=False, include_osv=False, include_git_history=False),
        )
        started = time.perf_counter()
        result = run_scan(request)
        durations.append(round(time.perf_counter() - started, 6))
        observed.update(item.rule_id for item in result.findings)
        coverage = result.coverage
    expected = case["expected_rules"]
    matched = expected & observed
    unexpected = observed - expected
    return {
        "description": case["description"],
        "path": str(root),
        "iterations": iterations,
        "durations_seconds": durations,
        "mean_seconds": round(statistics.mean(durations), 6),
        "median_seconds": round(statistics.median(durations), 6),
        "files_analyzed": coverage.get("files_analyzed", 0),
        "findings": len(observed),
        "observed_rules": sorted(observed),
        "expected_rules": sorted(expected),
        "matched_expected_rules": sorted(matched),
        "missing_expected_rules": sorted(expected - observed),
        "unexpected_rules": sorted(unexpected),
        "expected_rule_recall": round(len(matched) / len(expected), 3) if expected else 1.0,
        "unexpected_rule_count": len(unexpected),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")
    report = {
        "tool": "Agentic AlfaSec",
        "version": 1,
        "cases": {name: run_case(name, args.iterations) for name in CASES},
    }
    encoded = json.dumps(report, indent=2)
    print(encoded)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(encoded + "\n", encoding="utf-8")
    return 0 if all(not case["missing_expected_rules"] for case in report["cases"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
