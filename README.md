# Agentic AlfaSec

Release: `1.0.0`

Agentic AlfaSec is a separate local companion for authorized defensive checks that a GitHub Pages browser cannot perform. It is intentionally loopback-only in this first version.

The project now also includes [`alfasec.py`](./alfasec.py), a Python CLI for repeatable project scans and CI-friendly exports. JavaScript and TypeScript files use the parser-backed `ast_analyzer.mjs` engine.

## Python CLI

```text
python alfasec.py scan-project . --format sarif --output alfasec.sarif
python alfasec.py scan-project . --format html --output alfasec.html
python alfasec.py scan-project . --osv
python alfasec.py scan-project . --fail-on HIGH
python alfasec.py scan-project . --policy .alfasec-policy.json
python alfasec.py verify-remediation . .alfasec/remediation.json
python alfasec.py scan-ports 127.0.0.1 1 256
python benchmarks\run_benchmark.py --iterations 5 --json benchmark-results.json
python -m unittest discover -s tests -v
```

The local benchmark harness in `benchmarks\` measures scan duration, analyzed
files, expected-rule recall, and unexpected-rule signals against controlled safe
and vulnerable fixtures. It is a regression smoke test, not a substitute for
benchmarking representative production applications.

Findings from different engines are conservatively merged when they share the
same file, CWE family, adjacent source line, and vulnerability family. The
higher-confidence finding is retained; unrelated rules and distinct evidence
remain separate.

An opt-in GitHub Actions workflow is included at
`.github/workflows/security-scan.yml`. It runs the local scanner on pushes and
pull requests, uploads `alfasec.sarif` to code scanning, and fails the job for
HIGH or CRITICAL findings. It does not enable OSV or send source code to an
external service. Review the workflow policy before using it in a production
repository.

## Local Python scan API

The Java agent and Python project scanner are separate loopback services. Their
session tokens are temporary local authentication credentials, not cloud API
keys, provider keys, or billing credentials. They are generated at process
startup, printed only in the local service console, and become invalid when
that service stops. Start
the Java checks with `agent\run-agent.bat` and the project API with
`agent\run-scan-server.bat`. Each prints a different random session token;
enter the Java token in **Connect agent** and the Python token in **Project
scan**. The Python API listens on `127.0.0.1:8775`, permits only directories
under its authorized root (the repository by default), and never accepts
remote targets. To authorize another local parent directory, launch it
explicitly, for example:

```text
python -m alfasec.server --allow-root "C:\work\my-projects"
```

Endpoints require `X-AlfaSec-Token` and an approved browser origin:
`GET /scan/health`, `POST /scan/start` with
`{"project_path":"C:\\work\\my-project"}`, `GET /scan/status?id=...`, and
`GET /scan/result?id=...`. Project persistence is available through
`GET /projects`, authorized `POST /projects/register` with
`{"project_path":"...","name":"..."}`, `GET /projects/history?id=...`, and
`GET /projects/summary?id=...`. Registry data is standard-library JSON at
`.alfasec/registry.json` (override with `ALFASEC_REGISTRY_PATH`) and uses
atomic writes with a bounded history. Jobs are asynchronous, limited to two concurrent
scans, and report failures or timeout states explicitly. Results include
findings, coverage, quality, policy, assets, correlations, and remediation
summary; secret evidence remains redacted by the scanner.
The API writes a local append-only audit trail to
`.alfasec/audit.log` (or the path in `ALFASEC_AUDIT_LOG`); it records event
metadata only and never records session tokens or source content. The
dashboard requires an explicit authorization acknowledgement before local
checks can be started.
Findings also receive an explainable risk-priority score based only on severity
and confidence; this score is a review aid, not exploitability or business-impact
proof. Project workflow records can be viewed with `GET /projects/findings?id=...`
and updated through authenticated `POST /projects/finding-action` using a project
ID and finding fingerprint. Supported states are `open`, `in-progress`,
`accepted-risk`, `false-positive`, and `resolved`; accepted-risk and
false-positive decisions require a rationale. Accepted-risk records also
require an expiration date. Fresh scans expose overdue, expired, unowned, and
reopened workflow states. `GET /projects/governance?id=...` returns governance
counters. Records are stored atomically in the project's `.alfasec/workflow.json`.

Install the JavaScript/TypeScript analysis dependency once:

```text
npm install
```

The AST engine tracks common request sources through local aliases, same-file helper functions, and simple relative imports into high-risk sinks such as command execution, HTML assignment, dynamic evaluation, filesystem paths, and SQL queries. It recognizes a small explicit set of HTML sanitizers (`DOMPurify.sanitize`, `sanitizeHtml`, `escapeHtml`, and `encodeHtml`) to reduce known XSS false positives. Findings include a source-to-sink evidence path and are still subject to review. Framework-specific modeling and broader module resolution remain future work.

The CLI provides evidence-bearing findings with rule ID, severity, confidence, CWE, remediation, source location, deduplication, JSON output, CSV/SARIF/HTML exports, supported `package.json` and `requirements.txt` dependency discovery, and an explicit OSV advisory lookup. OSV receives package names and versions only when `--osv` is requested. Project scans keep a local `.alfasec/history.json` by default; findings are fingerprinted and tracked as `open`, `fixed`, or `reappeared`. Use `--history PATH` to choose another location or `--no-history` to disable persistence. Every JSON scan also includes scan ID, engine metadata, coverage, quality, and lifecycle data. Engines fail explicitly rather than silently producing a success-shaped partial result.

CI gates are optional. `--fail-on HIGH` (or `--policy PATH`) makes the command
exit 1 only when a finding meets the configured gate; findings below the gate
still appear in JSON and exit successfully. A policy is JSON with safe defaults:

```json
{
  "max_severity": "HIGH",
  "minimum_confidence": "MEDIUM",
  "ignored_rule_ids": ["debug"]
}
```

Policy runs include `policy.passed`, blocked findings, reasons, and normalized
configuration in JSON. Invalid policy files and scanner errors exit 2. Without
either option, the legacy behavior (exit 1 for any finding) is preserved.
SARIF exports include rule descriptions, remediation help, CWE metadata,
stable fingerprints, severity levels, and CWE help links where available.

Remediation planning is approval-gated and never edits source files. Add
`--remediation-plan PATH` to persist redacted remediation records, or
`--approve-finding FINGERPRINT` (together with that option) to record approval
only. Records retain their history and include a text-only patch preview,
timestamps, and verification state. Call `verify_remediation` from the Python
API after a fresh scan to mark absent findings `verified` and present findings
`reappeared`. The `verify-remediation PROJECT PLAN` command persists the result
and exits 1 if any planned finding reappeared. The authenticated API endpoint
`POST /projects/remediation-verify` performs the same operation for a
registered project; plan paths must remain inside that project.

Milestone 5 adds a passive asset inventory and conservative finding
correlations to scan JSON. `assets` identifies the project root, source and
configuration files, dependency packages, Docker/Kubernetes/GitHub Actions
assets, and local-service indicators derived from findings. It performs no
network probing. `correlations` contains stable group IDs, severity and
confidence, finding fingerprints/references, rationale, and limitations.
Groups describe shared evidence (for example a file, rule family, or
configuration/code relationship); they do not claim exploitability or a
confirmed attack path.

The Phase 2 engine set includes dependency inventory and a dedicated secrets engine. Secret checks cover provider-shaped tokens, private keys, JWTs, generic secret assignments, redacted evidence, placeholder suppression, and optional Git history scanning. Use `--git-history` to inspect repository history; it is disabled by default. Secrets are never printed in full in findings.

Phase 3 adds a standard-library-only configuration engine for Dockerfiles,
Docker Compose, Kubernetes manifests, and GitHub Actions workflows. It checks
root containers, remote downloads and build-time secrets, privileged or
host-connected services, unsafe Kubernetes exposure and missing limits,
unpinned actions, unsafe `pull_request_target` checkouts, and shell secret
interpolation. Findings include rule IDs, severity, confidence, CWE, evidence,
and remediation; YAML is intentionally handled conservatively without a
third-party parser.

Phase 4 adds a standard-library `ast` Python engine (`python-ast`). It tracks
Flask/FastAPI request values and `input()` through local aliases and same-file
helpers into command, SQL, filesystem, and unsafe deserialization sinks. It
also reports weak MD5/SHA-1 use. Explicit flows are high-confidence and
include source-to-sink evidence, CWE identifiers, and remediation. Constant
queries with bound parameters and a small set of safe path/quoting helpers are
handled as safe where their intent is explicit; dynamic Python behavior remains
outside the conservative analysis.

The Java milestone adds a standard-library lexical flow engine (`java-ast`).
It models Spring request parameters and servlet request access through JDBC,
command execution, filesystem, and Java deserialization sinks, as well as
weak hashes and disabled TLS verification. Explicit source-to-sink flows are
high confidence; constants and `PreparedStatement` parameter binding are
excluded.

The platform supports npm lockfiles, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, Maven `pom.xml`, and Gradle build files. OSV findings are opt-in with `--osv`; without it, no external advisory request is made. Advisory findings retain the ecosystem, verified advisory ID, severity, CVSS metadata when supplied, and affected-version range data. Future scanners can implement the same engine interface without changing report or lifecycle code.

## Start the agent

1. Install a JDK 11 or newer.
2. Open `agent\run-agent.bat`.
3. Copy the one-session token printed in the console.
4. Serve the `web` folder:

```text
cd web
python -m http.server 8000
```

5. Open `http://localhost:8000`, paste the token, and connect.

The dashboard can also be deployed as a static GitHub Pages site from the `web` folder using `.github/workflows/pages.yml`. The deployed page is only the dashboard; the local Java agent must still be installed and running on the user's computer for checks to work.

The repository includes [MIT licensing](./LICENSE), [contribution guidance](./CONTRIBUTING.md),
and a [private vulnerability reporting policy](./SECURITY.md). Continuous
integration validates Python 3.11-3.13, Node.js 22, and Java 11/17/21.

## Available checks

- Authorized TCP port availability on `localhost`/`127.0.0.1` (maximum 256 ports)
- Passive HTTP security-header checks for localhost
- TLS certificate and protocol inspection for localhost
- Local DNS resolution

The agent binds only to `127.0.0.1`, requires a random session token, validates browser origins, rejects non-loopback targets, applies timeouts, and does not execute exploits or brute-force requests.

This is a defensive local agent, not a replacement for mature scanners. Only test systems you own or are authorized to assess.

## Scope and limitations

The project is a local-first defensive foundation, not an enterprise replacement for CodeQL, Semgrep, ZAP, Trivy, ClamAV, Nessus, or OpenVAS. Pattern findings can be false positives or false negatives and require review. The network functions are passive/availability checks only: no exploit execution, brute force, malware execution, or unrestricted scanning is provided. CVE/CVSS values are only shown when a trusted advisory source supplies them; generic code findings must not be presented as verified CVEs.
