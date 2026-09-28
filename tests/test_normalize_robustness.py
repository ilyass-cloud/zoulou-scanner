"""Robustness of the normalization layer against malformed scanner output.

Scanner output is untrusted: it comes from third-party tools run against an
arbitrary repository, and in parse-only mode it can be uploaded directly. Every
case below previously raised out of normalize_all() and aborted post-processing,
discarding the findings of every other scanner in the run.
"""

from __future__ import annotations

import json

import pytest

from orchestrator.models import RawScanArtifact, ScanType
from orchestrator.normalize import normalize_all, normalize_artifact


def _artifact(scan_type: ScanType, payload, tool: str = "t") -> RawScanArtifact:
    return RawScanArtifact(
        plugin_name=tool,
        scan_type=scan_type,
        tool=tool,
        stdout=payload if isinstance(payload, str) else json.dumps(payload),
        exit_code=0,
    )


# ---------------------------------------------------------------------------
# Blast radius — the property that matters most
# ---------------------------------------------------------------------------

def test_one_malformed_artifact_does_not_discard_the_others():
    """A tool emitting unparseable output costs its own findings, not the run's."""
    good = _artifact(ScanType.SAST, {"results": [
        {"test_id": "B101", "filename": "a.py", "line_number": 1, "issue_severity": "HIGH"},
    ]}, tool="bandit")
    broken = _artifact(ScanType.SAST, {"runs": [{"results": [{"ruleId": "r", "locations": [None]}]}]})
    deps = _artifact(ScanType.DEPS, [
        {"package": "requests", "version": "1.0", "cve": "CVE-1", "severity": "high"},
    ], tool="pip-audit")

    findings = normalize_all([good, broken, deps])
    tools = {f.tool for f in findings}
    assert "bandit" in tools
    assert "pip-audit" in tools


def test_a_normalizer_raising_is_contained(monkeypatch):
    """Even an unforeseen failure mode must not sink the whole run."""
    import orchestrator.normalize as normalize

    def explode(*_args, **_kwargs):
        raise RuntimeError("unforeseen")

    monkeypatch.setattr(normalize, "_normalize_deps", explode)

    good = _artifact(ScanType.SAST, {"results": [{"test_id": "B101", "filename": "a.py"}]})
    bad = _artifact(ScanType.DEPS, [{"package": "x"}])
    assert len(normalize_all([good, bad])) == 1


# ---------------------------------------------------------------------------
# SARIF — the richest source of shape surprises
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload,label", [
    ({"runs": [{"tool": {"driver": {"rules": [{"name": "x"}]}}, "results": []}]}, "rule without id"),
    ({"runs": [{"results": [{"ruleId": "r", "locations": [None]}]}]}, "null location"),
    ({"runs": [{"results": [{"ruleId": "r", "locations": "nope"}]}]}, "locations not a list"),
    ({"runs": [{"results": [{"ruleId": "r", "locations": []}]}]}, "empty locations"),
    ({"runs": [{"results": [{"ruleId": "r", "message": "plain string"}]}]}, "message not an object"),
    ({"runs": [{"results": [{"ruleId": "r", "level": 3}]}]}, "level not a string"),
    ({"runs": [{"results": [{"ruleId": "r", "locations": [{"physicalLocation": "x"}]}]}]}, "physicalLocation not an object"),
    ({"runs": [{"results": [{"ruleId": "r", "locations": [{"physicalLocation": {"region": {"startLine": "ten"}}}]}]}]}, "startLine not an int"),
    ({"runs": [{"tool": "nope", "results": []}]}, "tool not an object"),
    ({"runs": [{"results": "nope"}]}, "results not a list"),
    ({"runs": "nope"}, "runs not a list"),
    ({"runs": [None]}, "null run"),
    ({"runs": [{"results": [None]}]}, "null result"),
    ({"runs": [{"tool": {"driver": {"rules": "nope"}}, "results": []}]}, "rules not a list"),
], ids=lambda v: v if isinstance(v, str) else "")
def test_malformed_sarif_does_not_raise(payload, label):
    normalize_artifact(_artifact(ScanType.SAST, payload))


def test_sarif_keeps_the_finding_when_only_the_location_is_broken():
    """Degrade the field, not the finding."""
    findings = normalize_artifact(_artifact(ScanType.SAST, {
        "runs": [{"results": [{"ruleId": "rule-1", "locations": [None]}]}]
    }))
    assert len(findings) == 1
    assert findings[0].location.file_path == "unknown"


def test_sarif_skips_only_the_unusable_rule():
    findings = normalize_artifact(_artifact(ScanType.SAST, {
        "runs": [{
            "tool": {"driver": {"rules": [{"name": "no-id"}, {"id": "good", "name": "Good"}]}},
            "results": [{"ruleId": "good"}],
        }]
    }))
    assert len(findings) == 1
    assert findings[0].title == "Good"


# ---------------------------------------------------------------------------
# List-shaped normalizers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scan_type", [
    ScanType.DEPS, ScanType.SECRETS, ScanType.CONTAINER, ScanType.NETWORK,
])
@pytest.mark.parametrize("payload", [
    [None],
    [1, 2, 3],
    ["a string"],
    [[]],
])
def test_non_object_entries_yield_no_findings(scan_type, payload):
    """A list of scalars is not a list of findings; skip, do not raise."""
    assert normalize_artifact(_artifact(scan_type, payload)) == []


@pytest.mark.parametrize("scan_type", [
    ScanType.DEPS, ScanType.SECRETS, ScanType.CONTAINER, ScanType.NETWORK,
])
def test_empty_object_entry_still_produces_a_finding(scan_type):
    """An empty object is a valid, if uninformative, finding — it must not be
    silently dropped along with the genuinely malformed entries."""
    assert len(normalize_artifact(_artifact(scan_type, [{}]))) == 1


@pytest.mark.parametrize("scan_type", [
    ScanType.DEPS, ScanType.SECRETS, ScanType.CONTAINER, ScanType.NETWORK,
])
def test_good_entries_survive_alongside_malformed_ones(scan_type):
    """Per-entry isolation: one bad row does not discard the good rows."""
    findings = normalize_artifact(_artifact(scan_type, [None, {"package": "x", "host": "h"}, 42]))
    assert len(findings) == 1


@pytest.mark.parametrize("scan_type,payload", [
    (ScanType.DEPS, [{"package": "x", "severity": 5}]),
    (ScanType.DEPS, [{"package": "x", "references": "http://one"}]),
    (ScanType.DEPS, [{"package": None, "version": None, "cve": None}]),
    (ScanType.SECRETS, [{"file": 42, "line": "not-an-int"}]),
    (ScanType.CONTAINER, [{"references": {"a": 1}}]),
    (ScanType.NETWORK, [{"host": None, "port": "eighty"}]),
    (ScanType.SAST, [{"cwe": 79, "cve": 2021, "references": "http://x"}]),
    (ScanType.SAST, [{"title": {"nested": "object"}}]),
])
def test_wrongly_typed_fields_do_not_raise(scan_type, payload):
    normalize_artifact(_artifact(scan_type, payload))


def test_scalar_reference_is_coerced_to_a_list():
    findings = normalize_artifact(_artifact(ScanType.DEPS, [
        {"package": "x", "references": "http://example.com"},
    ]))
    assert findings[0].references == ["http://example.com"]


def test_numeric_cwe_is_coerced_to_a_string():
    findings = normalize_artifact(_artifact(ScanType.SAST, [{"cwe": 79, "file": "a.py"}]))
    assert findings[0].cwe == ["79"]


# ---------------------------------------------------------------------------
# Parser limits
# ---------------------------------------------------------------------------

def test_deeply_nested_json_is_rejected_not_fatal():
    """json.loads raises RecursionError, which is not a ValueError and so was
    not caught by the JSONDecodeError handler."""
    assert normalize_artifact(_artifact(ScanType.SAST, "[" * 60000 + "]" * 60000)) == []


@pytest.mark.parametrize("payload", ["", "not json", "{", '{"runs":', "\x00\x01"])
def test_unparseable_stdout_yields_no_findings(payload):
    assert normalize_artifact(_artifact(ScanType.SAST, payload)) == []


def test_top_level_scalar_yields_no_findings():
    for payload in ["123", '"a string"', "null", "true"]:
        assert normalize_artifact(_artifact(ScanType.SAST, payload)) == []
