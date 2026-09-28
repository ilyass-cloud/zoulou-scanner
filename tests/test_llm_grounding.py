"""Tests for the grounding rule and the evidence that feeds it.

The rule — "if a finding has no evidence, say 'insufficient evidence to assess
this finding'" — was only ever a sentence in the prompt. Asking a model not to
speculate is not a control: small local models, which is what this project
targets, answer anyway, and the fabricated line numbers and remediation steps
then appear in the report indistinguishable from grounded ones.
"""

from __future__ import annotations

import json

import pytest

from orchestrator.llm_analysis import (
    INSUFFICIENT_EVIDENCE,
    analyze_finding,
    analyze_findings,
    is_grounded,
)
from orchestrator.models import (
    CodeLocation,
    Confidence,
    Finding,
    RawScanArtifact,
    ScanType,
    Severity,
)
from orchestrator.normalize import normalize_artifact


class FakeClient:
    """A model that ignores the grounding instruction — the realistic case."""

    def __init__(self, payload=None, raise_on_call=False):
        self.calls = 0
        self.payload = payload if payload is not None else json.dumps({
            "justification": "Trivially exploitable via the id parameter.",
            "remediation": "Replace the f-string on line 42 with a parameterised query.",
        })
        self.raise_on_call = raise_on_call

    def generate(self, prompt, system_prompt=None, json_schema=None):
        self.calls += 1
        if self.raise_on_call:
            raise RuntimeError("LM Studio unreachable")
        return self.payload


def _finding(evidence=None, **kw) -> Finding:
    return Finding(
        source=kw.pop("source", ScanType.SAST),
        tool="semgrep",
        title="SQL injection",
        description="Tainted input reaches a query",
        location=CodeLocation(file_path="app.py", start_line=42),
        severity_raw=Severity.HIGH,
        confidence_raw=Confidence.MEDIUM,
        evidence=evidence,
        **kw,
    )


# ---------------------------------------------------------------------------
# is_grounded
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("evidence", [None, "", "   ", "\n\t "])
def test_blank_evidence_is_not_grounded(evidence):
    assert is_grounded(_finding(evidence)) is False


def test_real_evidence_is_grounded():
    assert is_grounded(_finding("query = f'SELECT {uid}'")) is True


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

def test_ungrounded_finding_gets_the_mandated_response():
    client = FakeClient()
    f = _finding(None)
    analyze_finding(client, f)
    assert f.llm_justification == INSUFFICIENT_EVIDENCE
    assert f.llm_remediation == INSUFFICIENT_EVIDENCE


def test_ungrounded_finding_is_never_sent_to_the_model():
    """Enforcement is structural, not corrective — and saves a round-trip."""
    client = FakeClient()
    analyze_finding(client, _finding(None))
    assert client.calls == 0


def test_model_output_cannot_override_the_grounding_rule():
    """The regression that motivated this: the model answers confidently for a
    finding with no evidence, and the fabrication reaches the report."""
    client = FakeClient()
    f = _finding(None)
    analyze_finding(client, f)
    assert "parameterised query" not in (f.llm_remediation or "")
    assert "exploitable" not in (f.llm_justification or "")


def test_grounded_finding_is_analysed_normally():
    client = FakeClient()
    f = _finding("query = f'SELECT * FROM users WHERE id={uid}'")
    analyze_finding(client, f)
    assert client.calls == 1
    assert f.llm_justification == "Trivially exploitable via the id parameter."
    assert f.llm_remediation == "Replace the f-string on line 42 with a parameterised query."


def test_enforcement_applies_across_a_batch():
    client = FakeClient()
    grounded = _finding("code snippet here")
    ungrounded = _finding(None)
    analyze_findings(client, [grounded, ungrounded], top_n=10, max_workers=1)
    assert ungrounded.llm_justification == INSUFFICIENT_EVIDENCE
    assert grounded.llm_justification != INSUFFICIENT_EVIDENCE
    assert client.calls == 1, "only the grounded finding costs a call"


# ---------------------------------------------------------------------------
# Malformed model responses
# ---------------------------------------------------------------------------

def test_unparseable_response_is_not_presented_as_remediation():
    """A response we could not parse is not a remediation plan."""
    client = FakeClient(payload="I think maybe you should look at line 42?")
    f = _finding("evidence present")
    analyze_finding(client, f)
    assert f.llm_remediation is None
    assert "line 42" in f.llm_justification


def test_fenced_json_is_unwrapped():
    client = FakeClient(payload='```json\n{"justification": "j", "remediation": "r"}\n```')
    f = _finding("evidence present")
    analyze_finding(client, f)
    assert f.llm_justification == "j"
    assert f.llm_remediation == "r"


@pytest.mark.parametrize("payload", ["", "   ", "null", "[1,2,3]", '"a string"', "123"])
def test_degenerate_responses_do_not_raise(payload):
    client = FakeClient(payload=payload)
    analyze_finding(client, _finding("evidence present"))


def test_non_string_fields_are_coerced_or_dropped():
    client = FakeClient(payload=json.dumps({"justification": {"a": 1}, "remediation": 42}))
    f = _finding("evidence present")
    analyze_finding(client, f)
    assert f.llm_justification is None
    assert f.llm_remediation == "42"


def test_runaway_response_is_truncated():
    client = FakeClient(payload="x" * 10000)
    f = _finding("evidence present")
    analyze_finding(client, f)
    assert len(f.llm_justification) < 2100
    assert f.llm_justification.endswith("[truncated]")


def test_client_failure_is_recorded_not_raised():
    client = FakeClient(raise_on_call=True)
    f = _finding("evidence present")
    analyze_finding(client, f)
    assert "LLM unavailable" in f.llm_justification
    assert f.llm_remediation is None


# ---------------------------------------------------------------------------
# Evidence extraction — without this, enforcement guts the feature
# ---------------------------------------------------------------------------

def _normalize(scan_type, payload):
    return normalize_artifact(RawScanArtifact(
        plugin_name="p", scan_type=scan_type, tool="t",
        stdout=json.dumps(payload), exit_code=0,
    ))


def test_sarif_snippet_becomes_evidence():
    """SARIF carries the offending source; discarding it left every semgrep
    finding unassessable under the grounding rule."""
    findings = _normalize(ScanType.SAST, {"runs": [{"results": [{"ruleId": "sqli", "locations": [
        {"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                              "region": {"startLine": 42, "snippet": {"text": "query = f'{uid}'"}}}}
    ]}]}]})
    assert findings[0].evidence == "query = f'{uid}'"
    assert is_grounded(findings[0])


def test_sarif_falls_back_to_context_region():
    findings = _normalize(ScanType.SAST, {"runs": [{"results": [{"ruleId": "sqli", "locations": [
        {"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                              "contextRegion": {"snippet": {"text": "def handler(uid):"}}}}
    ]}]}]})
    assert findings[0].evidence == "def handler(uid):"


def test_sarif_without_a_snippet_stays_ungrounded():
    findings = _normalize(ScanType.SAST, {"runs": [{"results": [{"ruleId": "sqli"}]}]})
    assert findings[0].evidence is None
    assert not is_grounded(findings[0])


def test_network_banner_becomes_evidence():
    findings = _normalize(ScanType.NETWORK, [
        {"host": "10.0.0.1", "port": 22, "protocol": "tcp",
         "service": "ssh", "product": "OpenSSH", "product_version": "8.9"},
    ])
    assert findings[0].evidence == "10.0.0.1:22/tcp ssh OpenSSH 8.9"


def test_network_without_a_banner_stays_ungrounded():
    findings = _normalize(ScanType.NETWORK, [{"host": "10.0.0.1", "port": 22}])
    assert findings[0].evidence is None


@pytest.mark.parametrize("malformed", [
    {"runs": [{"results": [{"ruleId": "r", "locations": [{"physicalLocation": {"region": {"snippet": "not-an-object"}}}]}]}]},
    {"runs": [{"results": [{"ruleId": "r", "locations": [{"physicalLocation": {"region": {"snippet": {"text": None}}}}]}]}]},
    {"runs": [{"results": [{"ruleId": "r", "locations": [{"physicalLocation": {"contextRegion": 5}}]}]}]},
])
def test_malformed_snippet_shapes_do_not_raise(malformed):
    _normalize(ScanType.SAST, malformed)
