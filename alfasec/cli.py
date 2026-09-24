"""Command-line interface."""
from __future__ import annotations
import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from .models import ScanProfile, ScanRequest, ScanScope
from .engines import run_scan
from .network import port_scan
from .reporting import exports
from .remediation import (
    approve_remediation,
    remediation_plan,
    save_remediation_plan,
    verify_remediation_plan,
)
from .policy import evaluate_policy, load_policy
from .workflow import FindingWorkflow, enrich_findings, governance_summary, risk_summary


def _public_findings(scan, root: Path) -> tuple[list[dict], dict]:
    findings = [asdict(item) for item in scan.findings]
    lifecycle = (scan.lifecycle or {}).get("findings", [])
    fingerprints = {(item.get("rule_id"), item.get("file"), item.get("line")): item.get("fingerprint")
                    for item in lifecycle}
    for finding in findings:
        finding["fingerprint"] = fingerprints.get(
            (finding.get("rule_id"), finding.get("file"), finding.get("line")), "")
    workflow = FindingWorkflow(root / ".alfasec" / "workflow.json")
    records = workflow.get_all()
    return enrich_findings(findings, {"findings": records}), records


def main() -> int:
    parser = argparse.ArgumentParser(prog="alfasec", description="Agentic AlfaSec authorized defensive scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    project = sub.add_parser("scan-project")
    project.add_argument("path", type=Path)
    project.add_argument("--format", choices=("json", "csv", "sarif", "html"))
    project.add_argument("--output", type=Path)
    project.add_argument("--history", type=Path)
    project.add_argument("--no-history", action="store_true")
    project.add_argument("--osv", action="store_true")
    project.add_argument("--git-history", action="store_true")
    project.add_argument("--remediation-plan", type=Path)
    project.add_argument("--approve-finding")
    project.add_argument("--policy", type=Path, help="JSON CI policy file")
    project.add_argument("--fail-on", choices=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    verify = sub.add_parser("verify-remediation")
    verify.add_argument("path", type=Path)
    verify.add_argument("plan", type=Path)
    ports = sub.add_parser("scan-ports")
    ports.add_argument("host")
    ports.add_argument("start", type=int)
    ports.add_argument("end", type=int)
    ports.add_argument("--allow", action="append", default=[])
    args = parser.parse_args()
    if args.command == "scan-ports":
        try:
            print(json.dumps(port_scan(args.host, args.start, args.end, set(args.allow)), indent=2))
            return 0
        except ValueError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 2
    if args.command == "verify-remediation":
        try:
            scan = run_scan(ScanRequest(
                ScanScope(args.path),
                ScanProfile(include_history=False, include_osv=False, include_git_history=False),
            ))
            plan = verify_remediation_plan(args.plan, scan.findings)
            print(json.dumps(plan, indent=2))
            return 1 if plan["summary"]["counts"].get("reappeared", 0) else 0
        except (OSError, RuntimeError, ValueError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 2
    try:
        request = ScanRequest(
            ScanScope(args.path),
            ScanProfile(
                include_history=not args.no_history,
                history_path=args.history,
                include_osv=args.osv,
                include_git_history=args.git_history,
            ),
        )
        scan = run_scan(request)
        findings = scan.findings
        public_findings, workflow_records = _public_findings(scan, args.path)
    except (OSError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    try:
        configured_gate = args.policy is not None or args.fail_on is not None
        policy = load_policy(args.policy) if args.policy else {}
        if args.fail_on:
            policy["max_severity"] = args.fail_on
        policy_result = evaluate_policy(findings, policy)
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    remediation = remediation_plan(findings)
    if args.remediation_plan:
        try:
            remediation = save_remediation_plan(args.remediation_plan, remediation)
            if args.approve_finding:
                remediation = approve_remediation(args.remediation_plan, args.approve_finding)
            args.remediation_plan.write_text(json.dumps(remediation, indent=2), encoding="utf-8")
        except (OSError, RuntimeError, KeyError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 2
    elif args.approve_finding:
        print("ERROR: --approve-finding requires --remediation-plan", file=sys.stderr)
        return 2
    result = {
        "scan_id": scan.scan_id,
        "scanned_at": scan.completed_at,
        "findings": public_findings,
        "engines": [
            {"engine_id": item.engine_id, "metadata": item.metadata, "errors": item.errors}
            for item in scan.engines
        ],
        "quality": scan.quality,
        "coverage": scan.coverage,
        "dependencies": scan.dependencies,
        "assets": scan.assets,
        "correlations": scan.correlations,
        "remediation": remediation["summary"],
        "risk": risk_summary(public_findings),
        "governance": governance_summary(workflow_records, public_findings),
        "policy": {
            "passed": policy_result["passed"],
            "blocked_findings": [asdict(item) for item in policy_result["blocked_findings"]],
            "reasons": policy_result["reasons"],
            "config": policy_result["policy"],
        },
    }
    if scan.lifecycle:
        result["lifecycle"] = scan.lifecycle
    print(json.dumps(result, indent=2))
    if args.format and args.output:
        exports(findings, args.output, args.format)
    # Keep the original "any finding fails" behavior unless a gate was requested.
    return 1 if (findings and not configured_gate) or not policy_result["passed"] else 0
