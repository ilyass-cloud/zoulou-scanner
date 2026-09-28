"""Tests for deterministic fingerprint stability."""

from __future__ import annotations

from orchestrator.models import (
    CodeLocation,
    DepsLocation,
    Finding,
    NetworkLocation,
    ScanType,
    Severity,
    fingerprint,
)


def _code_finding(**kwargs) -> Finding:
    defaults = dict(
        source=ScanType.SAST,
        tool="semgrep",
        title="SQL Injection",
        description="User input flows into SQL query",
        location=CodeLocation(file_path="app/db.py", start_line=42),
        severity_raw=Severity.HIGH,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _deps_finding(**kwargs) -> Finding:
    defaults = dict(
        source=ScanType.DEPS,
        tool="pip-audit",
        title="requests 2.25.0 – CVE-2023-32681",
        description="SSRF vulnerability",
        location=DepsLocation(
            manifest_path="requirements.txt",
            package_name="requests",
            package_version="2.25.0",
        ),
        cve=["CVE-2023-32681"],
        severity_raw=Severity.HIGH,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Stability tests
# ---------------------------------------------------------------------------

def test_fingerprint_is_stable():
    """Same inputs must always produce the same fingerprint."""
    f1 = _code_finding()
    f2 = _code_finding()
    assert f1.id == f2.id


def test_fingerprint_changes_on_different_file():
    f1 = _code_finding()
    f2 = _code_finding(location=CodeLocation(file_path="app/other.py", start_line=42))
    assert f1.id != f2.id


def test_fingerprint_changes_on_different_line():
    f1 = _code_finding()
    f2 = _code_finding(location=CodeLocation(file_path="app/db.py", start_line=99))
    assert f1.id != f2.id


def test_fingerprint_changes_on_different_tool():
    f1 = _code_finding(tool="semgrep")
    f2 = _code_finding(tool="bandit")
    assert f1.id != f2.id


def test_fingerprint_changes_on_different_title():
    f1 = _code_finding(title="SQL Injection")
    f2 = _code_finding(title="XSS")
    assert f1.id != f2.id


def test_fingerprint_length():
    """Fingerprint must be exactly 16 hex characters."""
    f = _code_finding()
    assert len(f.id) == 16
    assert all(c in "0123456789abcdef" for c in f.id)


def test_fingerprint_deps_stable():
    f1 = _deps_finding()
    f2 = _deps_finding()
    assert f1.id == f2.id


def test_fingerprint_deps_changes_on_version():
    f1 = _deps_finding()
    f2 = _deps_finding(
        location=DepsLocation(
            manifest_path="requirements.txt",
            package_name="requests",
            package_version="2.28.0",
        )
    )
    assert f1.id != f2.id


def test_fingerprint_network():
    loc = NetworkLocation(host="10.0.0.1", port=443, protocol="tcp")
    f1 = Finding(
        source=ScanType.NETWORK,
        tool="nmap",
        title="Open port 443/tcp",
        description="HTTPS",
        location=loc,
    )
    f2 = Finding(
        source=ScanType.NETWORK,
        tool="nmap",
        title="Open port 443/tcp",
        description="HTTPS",
        location=loc,
    )
    assert f1.id == f2.id


def test_fingerprint_cve_order_independent():
    """CVE list order must not affect fingerprint."""
    f1 = _deps_finding(cve=["CVE-2023-32681", "CVE-2022-1234"])
    f2 = _deps_finding(cve=["CVE-2022-1234", "CVE-2023-32681"])
    assert f1.id == f2.id

