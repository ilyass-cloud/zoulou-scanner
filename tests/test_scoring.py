"""Tests for the deterministic scoring formula."""

from __future__ import annotations

import pytest

from orchestrator.models import (
    CodeLocation,
    Confidence,
    Exposure,
    Finding,
    NetworkLocation,
    ScanType,
    Severity,
)
from orchestrator.scoring import (
    SEVERITY_BASE,
    effective_confidence,
    score_all,
    score_finding,
)


def _finding(
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    exposure: Exposure = Exposure.UNKNOWN,
    related_ids: list | None = None,
    risk_related_ids: list | None = None,
    corroborating_ids: list | None = None,
) -> Finding:
    risk = risk_related_ids or []
    corr = corroborating_ids or []
    return Finding(
        source=ScanType.SAST,
        tool="test",
        title="Test finding",
        description="desc",
        location=CodeLocation(file_path="foo.py", start_line=1),
        severity_raw=severity,
        confidence_raw=confidence,
        exposure=exposure,
        related_ids=related_ids if related_ids is not None else sorted(set(risk) | set(corr)),
        risk_related_ids=risk,
        corroborating_ids=corr,
    )


# ---------------------------------------------------------------------------
# Base score tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sev,expected_base", [
    (Severity.CRITICAL, 80.0),
    (Severity.HIGH,     60.0),
    (Severity.MEDIUM,   40.0),
    (Severity.LOW,      20.0),
    (Severity.INFO,      5.0),
])
def test_base_score_mapping(sev, expected_base):
    f = _finding(severity=sev)
    score = score_finding(f, external_exposure_boost=0, low_confidence_penalty=0)
    assert score == expected_base


# ---------------------------------------------------------------------------
# Modifier tests
# ---------------------------------------------------------------------------

def test_external_exposure_boost():
    f = _finding(severity=Severity.MEDIUM, exposure=Exposure.EXTERNAL)
    score = score_finding(f, external_exposure_boost=15.0, low_confidence_penalty=0)
    assert score == 40.0 + 15.0


def test_no_boost_for_internal():
    f = _finding(severity=Severity.MEDIUM, exposure=Exposure.INTERNAL)
    score = score_finding(f, external_exposure_boost=15.0, low_confidence_penalty=0)
    assert score == 40.0


def test_low_confidence_penalty():
    f = _finding(severity=Severity.HIGH, confidence=Confidence.LOW)
    score = score_finding(f, external_exposure_boost=0, low_confidence_penalty=10.0)
    assert score == 60.0 - 10.0


def test_medium_confidence_no_penalty():
    f = _finding(severity=Severity.HIGH, confidence=Confidence.MEDIUM)
    score = score_finding(f, external_exposure_boost=0, low_confidence_penalty=10.0)
    assert score == 60.0


def test_correlation_boost():
    f = _finding(severity=Severity.MEDIUM, risk_related_ids=["aaa", "bbb"])
    score = score_finding(
        f,
        external_exposure_boost=0,
        low_confidence_penalty=0,
        correlation_boost_per_link=5.0,
        max_correlation_boost=15.0,
    )
    assert score == 40.0 + 10.0  # 2 links × 5


def test_correlation_boost_capped():
    f = _finding(severity=Severity.MEDIUM, risk_related_ids=["a", "b", "c", "d", "e"])
    score = score_finding(
        f,
        external_exposure_boost=0,
        low_confidence_penalty=0,
        correlation_boost_per_link=5.0,
        max_correlation_boost=15.0,
    )
    assert score == 40.0 + 15.0  # capped at 15


# ---------------------------------------------------------------------------
# The two axes: corroboration answers "is it real", not "how bad is it"
# ---------------------------------------------------------------------------

def test_corroboration_alone_does_not_raise_risk():
    """Two tools reporting the same CVE is redundancy of tooling, not a second
    fact. It must not buy the correlation boost — the defect this separation
    was introduced to fix."""
    f = _finding(severity=Severity.MEDIUM, corroborating_ids=["aaa", "bbb"])
    score = score_finding(
        f,
        external_exposure_boost=0,
        low_confidence_penalty=0,
        correlation_boost_per_link=5.0,
        max_correlation_boost=15.0,
    )
    assert score == 40.0, "a shared CVE must not raise the risk score"


def test_corroboration_lifts_a_low_confidence_finding_out_of_the_penalty():
    """A second tool reporting the same issue is evidence against a false
    positive, so the low-confidence penalty no longer applies."""
    alone = _finding(severity=Severity.MEDIUM, confidence=Confidence.LOW)
    backed = _finding(
        severity=Severity.MEDIUM, confidence=Confidence.LOW, corroborating_ids=["other"]
    )
    kw = dict(external_exposure_boost=0, low_confidence_penalty=10.0)
    assert score_finding(alone, **kw) == 30.0
    assert score_finding(backed, **kw) == 40.0


def test_corroboration_does_not_raise_an_already_confident_finding():
    """Corroboration removes a doubt; where there is none it adds nothing."""
    alone = _finding(severity=Severity.MEDIUM, confidence=Confidence.HIGH)
    backed = _finding(
        severity=Severity.MEDIUM, confidence=Confidence.HIGH, corroborating_ids=["other"]
    )
    kw = dict(external_exposure_boost=0, low_confidence_penalty=10.0)
    assert score_finding(alone, **kw) == score_finding(backed, **kw) == 40.0


def test_confidence_raw_is_never_overwritten():
    """The raw value is what the scanner said; the report must keep being able
    to say where a value came from."""
    f = _finding(severity=Severity.MEDIUM, confidence=Confidence.LOW,
                 corroborating_ids=["other"])
    score_finding(f, external_exposure_boost=0, low_confidence_penalty=10.0)
    assert f.confidence_raw == Confidence.LOW
    assert effective_confidence(f) == Confidence.MEDIUM


# ---------------------------------------------------------------------------
# Boundary tests
# ---------------------------------------------------------------------------

def test_score_never_exceeds_100():
    f = _finding(
        severity=Severity.CRITICAL,
        exposure=Exposure.EXTERNAL,
        related_ids=["a", "b", "c", "d"],
    )
    score = score_finding(f, external_exposure_boost=15.0, low_confidence_penalty=0)
    assert score <= 100.0


def test_score_never_below_zero():
    f = _finding(severity=Severity.INFO, confidence=Confidence.LOW)
    score = score_finding(f, external_exposure_boost=0, low_confidence_penalty=50.0)
    assert score >= 0.0


# ---------------------------------------------------------------------------
# score_all tests
# ---------------------------------------------------------------------------

def test_score_all_sorts_descending():
    findings = [
        _finding(severity=Severity.LOW),
        _finding(severity=Severity.CRITICAL),
        _finding(severity=Severity.MEDIUM),
    ]
    # Give each a unique location so fingerprints differ
    findings[0].location = CodeLocation(file_path="a.py", start_line=1)
    findings[1].location = CodeLocation(file_path="b.py", start_line=1)
    findings[2].location = CodeLocation(file_path="c.py", start_line=1)
    # Regenerate IDs
    from orchestrator.models import fingerprint
    for f in findings:
        f.id = fingerprint(f)

    scored = score_all(findings)
    scores = [f.risk_score for f in scored]
    assert scores == sorted(scores, reverse=True)


def test_score_all_in_range():
    findings = [_finding(sev) for sev in Severity]
    for i, f in enumerate(findings):
        f.location = CodeLocation(file_path=f"file{i}.py", start_line=i)
        from orchestrator.models import fingerprint
        f.id = fingerprint(f)
    scored = score_all(findings)
    for f in scored:
        assert 0.0 <= f.risk_score <= 100.0



# ---------------------------------------------------------------------------
# La confiance effective doit survivre au calcul
# ---------------------------------------------------------------------------
#
# Elle était calculée puis jetée : seul le score en gardait la trace. Un
# lecteur du rapport JSON voyait alors un résultat LOW dont la pénalité de
# −10 n'avait pas été appliquée, sans rien pour l'expliquer — et l'interface,
# qui lit ce même JSON, n'avait d'autre choix que de réimplémenter la règle.

def test_score_all_records_the_confidence_it_scored_with():
    f = _finding(severity=Severity.MEDIUM, confidence=Confidence.LOW,
                 corroborating_ids=["other"])
    score_all([f])
    assert f.confidence_raw == Confidence.LOW          # provenance intacte
    assert f.confidence_effective == Confidence.MEDIUM  # et ce qui a servi


def test_the_recorded_confidence_explains_the_absent_penalty():
    """La propriété qui compte : le champ rend le score reconstituable."""
    corroborated = _finding(severity=Severity.MEDIUM, confidence=Confidence.LOW,
                            corroborating_ids=["other"])
    alone = _finding(severity=Severity.MEDIUM, confidence=Confidence.LOW)
    score_all([corroborated])
    score_all([alone])

    assert corroborated.risk_score - alone.risk_score == 10.0
    assert corroborated.confidence_effective != alone.confidence_effective


def test_an_uncorroborated_finding_records_its_raw_confidence_unchanged():
    f = _finding(severity=Severity.MEDIUM, confidence=Confidence.LOW)
    score_all([f])
    assert f.confidence_effective == Confidence.LOW


def test_the_recorded_confidence_survives_serialisation():
    """C'est par le JSON que le rapport et l'interface y accèdent."""
    f = _finding(severity=Severity.MEDIUM, confidence=Confidence.LOW,
                 corroborating_ids=["other"])
    score_all([f])
    dumped = f.model_dump(mode="json")
    assert dumped["confidence_raw"] == "LOW"
    assert dumped["confidence_effective"] == "MEDIUM"
