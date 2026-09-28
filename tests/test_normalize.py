"""Tests for the normalization dispatcher and its SAST normalizers."""

from __future__ import annotations

import json

from orchestrator.models import (
    CodeLocation,
    RawScanArtifact,
    ScanType,
    Severity,
)
from orchestrator.normalize import normalize_artifact


def _artifact(payload, scan_type: ScanType = ScanType.SAST, tool: str = "test-tool") -> RawScanArtifact:
    return RawScanArtifact(
        plugin_name="sast",
        scan_type=scan_type,
        tool=tool,
        stdout=json.dumps(payload),
    )


# ---------------------------------------------------------------------------
# Plain JSON array — the sast stub's documented input format
# ---------------------------------------------------------------------------

def test_plain_array_stays_sast():
    """A plain SAST array must not be reclassified as a dependency finding."""
    findings = normalize_artifact(_artifact([
        {"title": "SQL injection", "file": "app.py", "line": 42, "severity": "HIGH"},
    ]))

    assert len(findings) == 1
    assert findings[0].source is ScanType.SAST
    assert isinstance(findings[0].location, CodeLocation)


def test_plain_array_preserves_content():
    """Title, location and severity must survive normalization."""
    findings = normalize_artifact(_artifact([
        {
            "title": "SQL injection",
            "file": "app.py",
            "line": 42,
            "severity": "HIGH",
            "confidence": "medium",
            "description": "unsanitised input reaches the cursor",
            "cwe": "CWE-89",
        },
    ]))
    f = findings[0]

    assert "SQL injection" in f.title
    assert f.location.file_path == "app.py"
    assert f.location.start_line == 42
    assert f.severity_raw is Severity.HIGH
    assert f.description == "unsanitised input reaches the cursor"
    assert f.cwe == ["CWE-89"]


def test_plain_array_accepts_key_spellings():
    """Tools spell the same field differently; all common variants must work."""
    findings = normalize_artifact(_artifact([
        {"message": "Hardcoded secret", "file_path": "conf.py", "line_number": 7},
    ]))
    f = findings[0]

    assert f.location.file_path == "conf.py"
    assert f.location.start_line == 7
    assert "Hardcoded secret" in f.title


def test_rule_id_prefixes_title():
    findings = normalize_artifact(_artifact([
        {"rule_id": "PY-SQL-001", "title": "SQL injection", "file": "a.py", "line": 1},
    ]))

    assert findings[0].title.startswith("PY-SQL-001")


def test_missing_location_falls_back():
    """A finding without a file must still normalize rather than crash."""
    findings = normalize_artifact(_artifact([{"title": "Vague finding"}]))

    assert findings[0].location.file_path == "unknown"
    assert findings[0].location.start_line is None


# ---------------------------------------------------------------------------
# Existing routing must not regress
# ---------------------------------------------------------------------------

def test_sarif_still_routed_to_sarif_normalizer():
    findings = normalize_artifact(_artifact({
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": []}},
            "results": [{
                "ruleId": "sql-injection",
                "level": "error",
                "message": {"text": "SQL injection"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 10},
                    }
                }],
            }],
        }],
    }))

    assert len(findings) == 1
    assert findings[0].source is ScanType.SAST
    assert findings[0].location.file_path == "app.py"


def test_bandit_envelope_still_routed_to_bandit_normalizer():
    findings = normalize_artifact(_artifact({
        "results": [{
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
            "filename": "plugin.py",
            "line_number": 55,
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "issue_text": "subprocess call with shell=True",
            "issue_cwe": {"id": 78},
            "code": "subprocess.run(cmd, shell=True)",
        }],
        "metrics": {},
    }))
    f = findings[0]

    assert f.source is ScanType.SAST
    assert f.title.startswith("B602")
    assert f.location.file_path == "plugin.py"
    assert f.cwe == ["CWE-78"]
    assert f.evidence == "subprocess.run(cmd, shell=True)"


def test_deps_array_still_normalized_as_deps():
    findings = normalize_artifact(_artifact(
        [{"package": "requests", "version": "2.25.0", "cve": "CVE-2023-32681"}],
        scan_type=ScanType.DEPS,
    ))

    assert findings[0].source is ScanType.DEPS
    assert findings[0].location.package_name == "requests"


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------

def test_invalid_json_returns_empty():
    artifact = RawScanArtifact(
        plugin_name="sast", scan_type=ScanType.SAST, tool="t", stdout="not json",
    )

    assert normalize_artifact(artifact) == []


def test_empty_stdout_returns_empty():
    artifact = RawScanArtifact(
        plugin_name="sast", scan_type=ScanType.SAST, tool="t", stdout="",
    )

    assert normalize_artifact(artifact) == []
