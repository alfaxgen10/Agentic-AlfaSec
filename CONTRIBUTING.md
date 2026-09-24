# Contributing to Agentic AlfaSec

Thank you for helping improve Agentic AlfaSec. Contributions should preserve
the project's local-first, defensive-only scope.

## Before submitting a change

1. Explain the user-facing problem and the security impact.
2. Keep network checks loopback-only unless the scope is explicitly reviewed.
3. Do not add telemetry, source-code uploads, exploit execution, or secrets.
4. Add or update regression tests for behavior changes.
5. Run:

```text
python -m unittest discover -s tests -v
python benchmarks\run_benchmark.py --iterations 3
```

Pull requests should document limitations and any new external dependency.
