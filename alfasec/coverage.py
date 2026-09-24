"""Coverage and finding quality metrics."""
from __future__ import annotations
from pathlib import Path
from .rules import AST_EXTENSIONS, SUPPORTED_EXTENSIONS, IGNORED_DIRECTORIES, RULES
from .models import Finding
def finding_quality(findings: list[Finding]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0}
    for item in findings:
        level = item.confidence.lower()
        counts[level] = counts.get(level, 0) + 1
    return {
        "confidence_counts": counts,
        "high_confidence_findings": counts.get("high", 0),
        "review_required_findings": counts.get("medium", 0) + counts.get("low", 0),
        "interpretation": (
            "High-confidence findings have an explicit modeled source-to-sink path."
            if counts.get("high", 0)
            else "No high-confidence source-to-sink findings were produced."
        ),
    }

def scan_coverage(root: Path) -> dict:
    paths = list(root.rglob("*")) if root.is_dir() else [root]
    analyzed = []
    skipped = []
    ignored = []
    for path in paths:
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRECTORIES for part in path.parts):
            ignored.append(str(path))
            continue
        try:
            size = path.stat().st_size
        except OSError:
            skipped.append({"file": str(path), "reason": "unreadable metadata"})
            continue
        if size > 2_000_000:
            skipped.append({"file": str(path), "reason": "file exceeds 2 MB limit"})
        elif path.suffix.lower() in SUPPORTED_EXTENSIONS or path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
            analyzed.append(str(path))
        else:
            skipped.append({"file": str(path), "reason": "unsupported file type"})
    languages = {}
    for item in analyzed:
        suffix = Path(item).suffix.lower() or "<no extension>"
        languages[suffix] = languages.get(suffix, 0) + 1
    limitations = [
        "A clean result means no enabled rule matched; it does not prove the project is secure.",
        "Framework-specific behavior, dynamic imports, and unsupported file types may not be analyzed.",
    ]
    if skipped:
        limitations.append("Some files were skipped; review the skipped-file list before relying on the result.")
    return {
        "files_analyzed": len(analyzed),
        "files_skipped": len(skipped),
        "files_ignored": len(ignored),
        "languages": languages,
        "rules_executed": len(RULES) + 5 + 15 + 6,
        "ast_engine": "javascript/typescript parser and Java conservative flow engines" if any(
            Path(item).suffix.lower() in AST_EXTENSIONS for item in analyzed
        ) or any(Path(item).suffix.lower() == ".java" for item in analyzed) else "not applicable",
        "skipped_files": skipped,
        "limitations": limitations,
    }
