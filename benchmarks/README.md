# AlfaSec benchmarks

Run the repeatable benchmark from the project root:

```text
python benchmarks\run_benchmark.py
python benchmarks\run_benchmark.py --iterations 5 --json benchmark-results.json
```

The harness uses local fixtures and disables history, OSV, and Git-history
scanning. It reports elapsed time, files covered, finding counts, expected-rule
recall, and unexpected-rule precision signals. Known heuristic signals remain
visible rather than being silently excluded. These fixtures are not a
substitute for a representative application corpus; they are regression
smoke tests for the scanner's known supported behavior.
