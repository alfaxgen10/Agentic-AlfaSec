"""Dependency inventory and OSV advisory lookup."""
from __future__ import annotations
import json
import re
import tomllib
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


def _item(name: str, version: str, source: Path, ecosystem: str, lockfile: bool = False) -> dict:
    return {
        "package": name,
        "version": version,
        "source": str(source),
        "ecosystem": ecosystem,
        "lockfile": lockfile,
    }


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dependencies(root: Path) -> list[dict]:
    results = []
    package = root / "package.json"
    if package.exists():
        try:
            data = _read_json(package)
            for group in ("dependencies", "devDependencies"):
                results.extend(_item(name, str(version), package, "npm") for name, version in data.get(group, {}).items())
        except (OSError, json.JSONDecodeError):
            pass
    for lock_name in ("package-lock.json", "npm-shrinkwrap.json"):
        lockfile = root / lock_name
        if lockfile.exists():
            try:
                data = _read_json(lockfile)
                packages = data.get("packages", {})
                for location, package_data in packages.items():
                    name = package_data.get("name")
                    version = package_data.get("version")
                    if name and version:
                        results.append(_item(name, str(version), lockfile, "npm", True))
                if not packages:
                    for name, package_data in data.get("dependencies", {}).items():
                        version = package_data.get("version")
                        if version:
                            results.append(_item(name, str(version), lockfile, "npm", True))
            except (OSError, json.JSONDecodeError):
                pass
    requirements = root / "requirements.txt"
    if requirements.exists():
        for line in requirements.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|~=)\s*([^\s;]+)", line)
            if match:
                results.append(_item(match.group(1), match.group(2), requirements, "PyPI"))
    for lock_name in ("Pipfile.lock",):
        lockfile = root / lock_name
        if lockfile.exists():
            try:
                data = _read_json(lockfile)
                for section in ("default", "develop"):
                    for name, spec in data.get(section, {}).items():
                        version = str(spec.get("version", "")).lstrip("=")
                        if version:
                            results.append(_item(name, version, lockfile, "PyPI", True))
            except (OSError, json.JSONDecodeError):
                pass
    poetry = root / "poetry.lock"
    if poetry.exists():
        try:
            data = tomllib.loads(poetry.read_text(encoding="utf-8"))
            for package_data in data.get("package", []):
                if package_data.get("name") and package_data.get("version"):
                    results.append(_item(package_data["name"], str(package_data["version"]), poetry, "PyPI", True))
        except (OSError, tomllib.TOMLDecodeError):
            pass
    pom = root / "pom.xml"
    if pom.exists():
        try:
            tree = ET.parse(pom)
            for dependency in tree.findall(".//{*}dependency"):
                group = dependency.findtext("{*}groupId")
                name = dependency.findtext("{*}artifactId")
                version = dependency.findtext("{*}version")
                if group and name and version and "${" not in version:
                    results.append(_item(f"{group}:{name}", version.strip(), pom, "Maven"))
        except (OSError, ET.ParseError):
            pass
    for gradle_name in ("build.gradle", "build.gradle.kts"):
        gradle = root / gradle_name
        if gradle.exists():
            pattern = re.compile(
                r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[
                (]?\s*["']([^:"']+):([^:"']+):([^"']+)["']""",
                re.VERBOSE,
            )
            for match in pattern.finditer(gradle.read_text(encoding="utf-8", errors="replace")):
                results.append(_item(f"{match.group(1)}:{match.group(2)}", match.group(3), gradle, "Maven"))
    unique = {}
    for result in results:
        unique[(result["package"], result["version"], result["source"])] = result
    return list(unique.values())


def dependency_findings(items: list[dict], advisories: list[dict]) -> list:
    from .models import Finding

    findings = []
    for advisory in advisories:
        item = next(
            (candidate for candidate in items
             if candidate["package"] == advisory["package"] and candidate["version"] == advisory["version"]),
            None,
        )
        if not item or not advisory.get("id"):
            continue
        findings.append(Finding(
            rule_id="dependency-vulnerability",
            title=advisory.get("summary") or f"Known vulnerability in {item['package']}",
            severity=advisory.get("severity", "HIGH"),
            confidence="high",
            cwe="CWE-1395",
            cve=advisory["id"],
            cvss=advisory.get("cvss", "advisory-provided"),
            file=item["source"],
            line=1,
            evidence=(
                f"{item.get('ecosystem', 'unknown')} package {item['package']} {item['version']} "
                f"matches advisory {advisory['id']}"
            ),
            remediation=f"Upgrade {item['package']} to a version not affected by {advisory['id']}.",
        ))
    return findings

def osv_lookup(items: list[dict]) -> list[dict]:
    advisories = []
    for item in items[:100]:
        body = json.dumps({"package": {"name": item["package"]}, "version": item["version"]}).encode()
        request = urllib.request.Request("https://api.osv.dev/v1/query", data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                for vuln in json.loads(response.read()).get("vulns", []):
                    advisories.append({
                        "package": item["package"],
                        "version": item["version"],
                        "id": vuln.get("id"),
                        "summary": vuln.get("summary", ""),
                        "severity": _advisory_severity(vuln),
                        "cvss": _advisory_cvss(vuln),
                        "affected": _advisory_ranges(vuln),
                    })
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            continue
    return advisories


def _advisory_severity(vulnerability: dict) -> str:
    database = vulnerability.get("database_specific") or {}
    severity = str(database.get("severity", "")).upper()
    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return severity
    for entry in vulnerability.get("severity", []):
        score = str(entry.get("score", ""))
        match = re.search(r"(CRITICAL|HIGH|MEDIUM|LOW)", score.upper())
        if match:
            return match.group(1)
    return "HIGH"


def _advisory_cvss(vulnerability: dict) -> str:
    database = vulnerability.get("database_specific") or {}
    return str(database.get("cvss", "advisory-provided"))


def _advisory_ranges(vulnerability: dict) -> list[dict]:
    ranges = []
    for affected in vulnerability.get("affected", []):
        for version_range in affected.get("ranges", []):
            ranges.append({
                "type": version_range.get("type"),
                "events": version_range.get("events", []),
            })
    return ranges
