"""Tests for the native-format adapters of the normalizer.

Until these adapters existed, the normalizer only read the simplified arrays of
the stub plugins, and every real dependency, secret and container scanner fell
through to an empty list without a warning. The fixtures are real outputs,
trimmed, captured by running each tool on intentionally vulnerable projects
(DVPWA, PyGoat, OWASP Juice Shop); the secrets they held are replaced by fakes.
The two ``*_constructed`` fixtures are the exception, and say so.
"""

from __future__ import annotations

import json
from pathlib import Path

from orchestrator.correlate import dedup_and_correlate
from orchestrator.models import (
    CodeLocation,
    Confidence,
    ContainerLocation,
    DepsLocation,
    RawScanArtifact,
    ScanType,
    Severity,
)
from orchestrator.normalize import normalize_artifact, normalize_all

FIXTURES = Path(__file__).parent / "fixtures" / "native"


def _artifact(name: str, scan_type: ScanType, tool: str) -> RawScanArtifact:
    return RawScanArtifact(
        plugin_name=tool,
        scan_type=scan_type,
        tool=tool,
        stdout=(FIXTURES / name).read_text(encoding="utf-8"),
    )


# ---------------------------------------------------------------------------
# pip-audit
# ---------------------------------------------------------------------------

def test_pip_audit_native_is_no_longer_silently_empty():
    findings = normalize_artifact(_artifact("pip_audit.json", ScanType.DEPS, "pip-audit"))

    assert len(findings) == 2          # two advisories on aiohttp, none on aiohttp-jinja2
    f = findings[0]
    assert f.source is ScanType.DEPS
    assert isinstance(f.location, DepsLocation)
    assert f.location.package_name == "aiohttp"
    assert f.location.package_version == "3.5.3"
    assert f.cve == ["CVE-2021-21330"]  # taken from the aliases, not the PYSEC id
    assert "3.7.4" in (f.remediation or "")


def test_pip_audit_reports_no_severity_and_none_is_invented():
    findings = normalize_artifact(_artifact("pip_audit.json", ScanType.DEPS, "pip-audit"))
    assert {f.severity_raw for f in findings} == {Severity.UNKNOWN}


def test_pip_audit_repeated_advisory_is_deduplicated():
    """pip-audit lists this advisory twice; the fingerprint collapses them."""
    findings = normalize_artifact(_artifact("pip_audit.json", ScanType.DEPS, "pip-audit"))
    for f in findings:
        from orchestrator.models import fingerprint
        f.id = fingerprint(f)
    assert len(dedup_and_correlate(findings)) == 1


# ---------------------------------------------------------------------------
# npm audit
# ---------------------------------------------------------------------------

def test_npm_audit_one_finding_per_advisory_and_none_for_propagation():
    data = json.loads((FIXTURES / "npm_audit.json").read_text(encoding="utf-8"))
    owner = next(k for k, v in data["vulnerabilities"].items()
                 if any(isinstance(x, dict) for x in v["via"]))
    advisories = [x for x in data["vulnerabilities"][owner]["via"] if isinstance(x, dict)]

    findings = normalize_artifact(_artifact("npm_audit.json", ScanType.DEPS, "npm-audit"))

    assert len(findings) == len(advisories)
    assert {f.location.package_name for f in findings} == {owner}
    assert all(f.severity_raw is Severity.HIGH for f in findings)
    assert all(f.cwe == ["CWE-78"] for f in findings)
    assert all("GHSA-" in f.title for f in findings)


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------

def test_trivy_fs_manifest_packages_are_dependencies_not_container():
    findings = normalize_artifact(_artifact("trivy_fs.json", ScanType.CONTAINER, "trivy"))
    pkgs = [f for f in findings if f.source is ScanType.DEPS]

    assert len(pkgs) == 3
    assert all(isinstance(f.location, DepsLocation) for f in pkgs)
    assert all(f.location.manifest_path == "requirements.txt" for f in pkgs)
    assert all(f.severity_raw is not Severity.UNKNOWN for f in pkgs)
    assert all(f.cve and f.cve[0].startswith("CVE-") for f in pkgs)


def test_trivy_secrets_are_secrets_with_location():
    findings = normalize_artifact(_artifact("trivy_fs.json", ScanType.CONTAINER, "trivy"))
    secrets = [f for f in findings if f.source is ScanType.SECRETS]

    assert len(secrets) == 2
    assert all(isinstance(f.location, CodeLocation) and f.location.start_line for f in secrets)


def test_trivy_os_package_in_image_is_container():
    data = {
        "SchemaVersion": 2, "ArtifactName": "nginx:1.25", "ArtifactType": "container_image",
        "Results": [{"Target": "nginx:1.25 (debian 12.5)", "Class": "os-pkgs", "Type": "debian",
                     "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl",
                                          "InstalledVersion": "3.0.11", "Severity": "HIGH"}]}],
    }
    art = RawScanArtifact(plugin_name="trivy", scan_type=ScanType.CONTAINER, tool="trivy",
                          stdout=json.dumps(data))
    (f,) = normalize_artifact(art)
    assert f.source is ScanType.CONTAINER
    assert isinstance(f.location, ContainerLocation)
    assert f.location.image_ref == "nginx:1.25"


# ---------------------------------------------------------------------------
# Grype and Safety (constructed from their documented schemas)
# ---------------------------------------------------------------------------

def test_grype_splits_application_and_os_packages():
    findings = normalize_artifact(_artifact("grype_constructed.json", ScanType.CONTAINER, "grype"))
    by_pkg = {f.location.package_name: f for f in findings}

    assert by_pkg["aiohttp"].source is ScanType.DEPS
    assert by_pkg["aiohttp"].cve == ["CVE-2021-21330"]     # from relatedVulnerabilities
    assert by_pkg["libc6"].source is ScanType.CONTAINER
    assert by_pkg["libc6"].location.image_ref == "python:3.12-slim"
    assert by_pkg["libc6"].severity_raw is Severity.HIGH


def test_safety_native():
    (f,) = normalize_artifact(_artifact("safety_constructed.json", ScanType.DEPS, "safety"))
    assert f.location.package_name == "aiohttp"
    assert f.cve == ["CVE-2021-21330"]
    assert f.severity_raw is Severity.MEDIUM


# ---------------------------------------------------------------------------
# Secrets: Gitleaks and TruffleHog
# ---------------------------------------------------------------------------

def test_gitleaks_keeps_file_and_line():
    """The capitalised fields used to be missed: every finding was "unknown"."""
    findings = normalize_artifact(_artifact("gitleaks.json", ScanType.SECRETS, "gitleaks"))

    assert len(findings) == 2
    assert all(f.location.file_path != "unknown" for f in findings)
    assert all(isinstance(f.location.start_line, int) for f in findings)
    assert len({f.id for f in findings}) == 2      # no longer collapsed by dedup


def test_gitleaks_evidence_never_contains_the_secret():
    raw = json.loads((FIXTURES / "gitleaks.json").read_text(encoding="utf-8"))
    findings = normalize_artifact(_artifact("gitleaks.json", ScanType.SECRETS, "gitleaks"))
    for f, item in zip(findings, raw):
        assert item["Secret"] not in (f.evidence or "")
        assert item["Secret"][:4] in (f.evidence or "")


def test_trufflehog_json_lines_are_parsed():
    findings = normalize_artifact(_artifact("trufflehog.jsonl", ScanType.SECRETS, "trufflehog"))

    assert len(findings) == 2                      # the log line is skipped
    assert all(f.location.file_path.startswith("test/") for f in findings)
    assert all(f.confidence_raw is Confidence.MEDIUM for f in findings)   # unverified
    assert all("FAKEjwt" not in (f.evidence or "")[5:] for f in findings)


# ---------------------------------------------------------------------------
# End to end: the corroboration rule now fires on real output
# ---------------------------------------------------------------------------

def test_pip_audit_and_grype_corroborate_on_the_same_cve():
    findings = normalize_all([
        _artifact("pip_audit.json", ScanType.DEPS, "pip-audit"),
        _artifact("grype_constructed.json", ScanType.CONTAINER, "grype"),
    ])
    findings = dedup_and_correlate(findings)
    pip = [f for f in findings if f.tool == "pip-audit"]
    grype = [f for f in findings if f.tool == "grype" and f.location.package_name == "aiohttp"]

    assert pip and grype
    assert grype[0].id in pip[0].corroborating_ids
    assert pip[0].risk_related_ids == []           # a second opinion, not a second fact


# ---------------------------------------------------------------------------
# Semgrep SARIF
# ---------------------------------------------------------------------------

def test_semgrep_sarif_title_and_cwe_identifier():
    sarif = {"runs": [{
        "tool": {"driver": {"name": "Semgrep OSS", "rules": [{
            "id": "python.lang.security.audit.formatted-sql-query",
            "shortDescription": {"text": "Semgrep Finding: python.lang.security.audit.formatted-sql-query"},
            "properties": {"tags": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "OWASP-A03:2021 - Injection"]},
        }]}},
        "results": [{"ruleId": "python.lang.security.audit.formatted-sql-query", "level": "warning",
                     "message": {"text": "Detected possible formatted SQL query."},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "sqli/dao/student.py"},
                                                         "region": {"startLine": 45}}}]}],
    }]}
    art = RawScanArtifact(plugin_name="semgrep", scan_type=ScanType.SAST, tool="semgrep",
                          stdout=json.dumps(sarif))
    (f,) = normalize_artifact(art)
    assert f.title == "formatted-sql-query"
    assert f.cwe == ["CWE-89"]
