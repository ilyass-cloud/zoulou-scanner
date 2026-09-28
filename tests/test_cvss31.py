"""Tests for the CVSS v3.1 calculator.

The reference vectors below are published scores, not values this project
chose: they are the fixed points against which the arithmetic is checked. A
calculator validated only against its own output proves nothing, which is the
gap this file closes — the audit claimed a "calculator validated against
published reference vectors" without shipping either the calculator or the
vectors.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.cvss31 import Cvss31Error, base_score, parse_vector, severity

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Published reference vectors
# ---------------------------------------------------------------------------

REFERENCE = [
    # (vector, published base score, qualitative rating)
    # Unauthenticated remote code execution, scope unchanged.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
    # Reflected cross-site scripting: the canonical scope-changed example.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "MEDIUM"),
    # Remote information disclosure, confidentiality only.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "HIGH"),
    # Local disclosure requiring low privileges.
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5, "MEDIUM"),
    # The maximum: scope changed with total impact.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
    # The minimum a well-formed vector can reach without being zero.
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "LOW"),
]


@pytest.mark.parametrize("vector,expected,rating", REFERENCE)
def test_published_reference_vectors(vector, expected, rating):
    assert base_score(vector) == expected
    assert severity(base_score(vector)) == rating


def test_no_impact_scores_zero():
    """A vector with no impact must score 0, not merely a small number."""
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert severity(0.0) == "NONE"


def test_scope_change_raises_the_score_for_identical_impact():
    unchanged = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
    changed = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N")
    assert changed > unchanged


def test_privileges_required_is_weighted_differently_under_scope_change():
    """PR:L is worth more when scope changes — the one metric that couples."""
    u = base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    c = base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    # Not merely larger: larger by more than the 1.08 scope factor alone.
    assert c > u * 1.08


# ---------------------------------------------------------------------------
# Rounding — the part that is easy to get subtly wrong
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vector", [v for v, _, _ in REFERENCE])
def test_every_score_has_at_most_one_decimal(vector):
    score = base_score(vector)
    assert round(score, 1) == score


def test_roundup_preserves_exact_tenths_and_lifts_anything_above_one():
    """The two properties Appendix A actually states."""
    from scripts.cvss31 import _roundup
    assert _roundup(4.0) == 4.0
    assert _roundup(6.7) == 6.7
    assert _roundup(0.0) == 0.0
    assert _roundup(4.02) == 4.1
    assert _roundup(9.91) == 10.0


def test_every_reachable_score_is_an_exact_tenth_in_range():
    """Exhaustif sur le groupe de métriques de base : 2592 vecteurs.

    C'est le contrôle qui vaut la peine. Une version antérieure de ce fichier
    affirmait que l'arrondi entier de la spécification diffère de
    `ceil(x * 10) / 10` sur certains scores ; l'énumération montre que non —
    les deux formes concordent sur tous les vecteurs atteignables. La propriété
    à fixer n'est donc pas une divergence jamais exhibée, mais que tout score
    que le calculateur peut produire est un score CVSS bien formé.
    """
    import itertools
    import math

    names = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    values = ("NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN")

    seen = 0
    for combo in itertools.product(*values):
        metrics = dict(zip(names, combo))
        vector = "CVSS:3.1/" + "/".join(f"{m}:{metrics[m]}" for m in names)
        score = base_score(vector)
        assert 0.0 <= score <= 10.0, vector
        assert round(score, 1) == score, vector
        assert math.isclose(score * 10, round(score * 10), abs_tol=1e-9), vector
        # Un score nul n'est atteignable qu'en l'absence totale d'impact.
        if score == 0.0:
            assert metrics["C"] == metrics["I"] == metrics["A"] == "N", vector
        seen += 1
    assert seen == 2592, seen


# ---------------------------------------------------------------------------
# A malformed vector must be refused, never scored
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vector,why", [
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "version 3.0"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "prefixe absent"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "métrique manquante"),
    ("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "valeur invalide"),
    ("CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "métrique en double"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P", "métrique temporelle"),
    ("CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "séparateur absent"),
])
def test_malformed_vectors_are_refused(vector, why):
    with pytest.raises(Cvss31Error):
        base_score(vector)


def test_metric_order_does_not_change_the_score():
    canonical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    shuffled = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"
    assert base_score(shuffled) == base_score(canonical)
    assert parse_vector(shuffled) == parse_vector(canonical)


# ---------------------------------------------------------------------------
# The audit's own ratings must be reproducible from their vectors
# ---------------------------------------------------------------------------

def _audit_findings():
    path = REPO / "docs" / "audit_findings.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_audit_file_covers_the_seventeen_findings():
    data = _audit_findings()
    ids = [f["id"] for f in data["findings"]]
    assert ids == [f"A-{n:02d}" for n in range(1, 18)]


@pytest.mark.parametrize("finding", _audit_findings()["findings"],
                         ids=lambda f: f["id"])
def test_each_audit_vector_reproduces_its_published_score(finding):
    """Table 7.1 of the thesis is verifiable, one row at a time."""
    if finding["vector"] is None:
        assert finding["base_score"] is None, finding["id"]
        assert finding["rationale"], "un constat non coté doit dire pourquoi"
        return
    assert base_score(finding["vector"]) == finding["base_score"], finding["id"]
    assert severity(finding["base_score"]) == finding["severity"], finding["id"]


def test_ratings_that_depend_on_another_finding_say_so():
    """A-10 reaches 10.0 only because A-01 left the API unauthenticated.

    Without that note the table reads as seventeen independent ratings, and the
    one attack chain that produced the highest score of the audit disappears
    from view.
    """
    a10 = next(f for f in _audit_findings()["findings"] if f["id"] == "A-10")
    assert a10["depends_on"] == ["A-01"]
    assert "PR:N" in a10["rationale"]
