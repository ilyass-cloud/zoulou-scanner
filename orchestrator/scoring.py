"""Deterministic risk scoring for normalized findings.

Formula (transparent, auditable):
  base_score        = SEVERITY_BASE[severity_raw]          (0–80)
  exposure_boost    = external_exposure_boost if exposure==EXTERNAL else 0
  confidence_penalty= low_confidence_penalty  if effective confidence==LOW else 0
  correlation_boost = 5 per risk-raising link (capped at 15)
  risk_score        = clamp(base_score + exposure_boost - confidence_penalty
                            + correlation_boost, 0, 100)

Two axes, not one. Confidence answers "is this finding real?"; risk answers
"how bad is it if it is?" Corroboration by a second tool is evidence against a
false positive and belongs to the first; a vulnerable package that is also
exposed on the network is a new fact and belongs to the second. Only the
latter therefore feeds `correlation_boost` — see :mod:`orchestrator.correlate`.

`external_exposure_boost` and `low_confidence_penalty` are configurable via
OrchestratorConfig; the correlation boost and its cap are parameters of
`score_finding` and are not currently exposed in configuration.
"""

from __future__ import annotations

import logging
from typing import List

from orchestrator.models import Confidence, Exposure, Finding, Severity

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Base severity → numeric score
# ---------------------------------------------------------------------------

SEVERITY_BASE: dict[Severity, float] = {
    Severity.CRITICAL: 80.0,
    Severity.HIGH:     60.0,
    Severity.MEDIUM:   40.0,
    Severity.LOW:      20.0,
    Severity.INFO:      5.0,
    Severity.UNKNOWN:  10.0,
}

# ---------------------------------------------------------------------------
# Scoring function
# ---------------------------------------------------------------------------


def effective_confidence(finding: Finding) -> Confidence:
    """The confidence to score with, once corroboration is taken into account.

    A finding reported by a second tool under the same CVE is no longer a
    plausible false positive, so it no longer deserves the low-confidence
    penalty. Corroboration lifts LOW to MEDIUM and nothing else: MEDIUM, HIGH
    and UNKNOWN carry no penalty already, so raising them would change no score
    while overstating what a duplicate report establishes.

    `confidence_raw` is left untouched — it is what the scanner said, and the
    report must remain able to say where a value came from.
    """
    if finding.confidence_raw == Confidence.LOW and finding.corroborating_ids:
        return Confidence.MEDIUM
    return finding.confidence_raw


def score_finding(
    finding: Finding,
    *,
    external_exposure_boost: float = 15.0,
    low_confidence_penalty: float = 10.0,
    correlation_boost_per_link: float = 5.0,
    max_correlation_boost: float = 15.0,
) -> float:
    """Compute and return a risk_score in [0, 100] for a single finding.

    Steps are logged at DEBUG level for full auditability.
    """
    base = SEVERITY_BASE.get(finding.severity_raw, 10.0)
    log.debug("score %s: base=%.1f (severity=%s)", finding.id, base, finding.severity_raw)

    boost = 0.0
    if finding.exposure == Exposure.EXTERNAL:
        boost = external_exposure_boost
        log.debug("score %s: +%.1f external exposure boost", finding.id, boost)

    confidence = effective_confidence(finding)
    if confidence != finding.confidence_raw:
        log.debug(
            "score %s: confidence %s → %s (corroborated by %d other finding(s))",
            finding.id, finding.confidence_raw.value, confidence.value,
            len(finding.corroborating_ids),
        )

    penalty = 0.0
    if confidence == Confidence.LOW:
        penalty = low_confidence_penalty
        log.debug("score %s: -%.1f low confidence penalty", finding.id, penalty)

    corr_boost = min(
        len(finding.risk_related_ids) * correlation_boost_per_link,
        max_correlation_boost,
    )
    if corr_boost:
        log.debug(
            "score %s: +%.1f correlation boost (%d risk-raising link(s))",
            finding.id, corr_boost, len(finding.risk_related_ids),
        )

    raw = base + boost - penalty + corr_boost
    score = max(0.0, min(100.0, raw))
    log.debug("score %s: final=%.1f", finding.id, score)
    return round(score, 2)


def score_all(
    findings: List[Finding],
    *,
    external_exposure_boost: float = 15.0,
    low_confidence_penalty: float = 10.0,
) -> List[Finding]:
    """Score all findings in-place and return them sorted by risk_score desc."""
    for f in findings:
        # Consigné sur le résultat, et pas seulement calculé : les consommateurs
        # qui ne peuvent pas rappeler cette fonction — le rapport JSON, et
        # l'interface qui le lit — doivent pouvoir expliquer une pénalité qui
        # n'a pas été appliquée sans réimplémenter la règle de leur côté.
        f.confidence_effective = effective_confidence(f)
        f.risk_score = score_finding(
            f,
            external_exposure_boost=external_exposure_boost,
            low_confidence_penalty=low_confidence_penalty,
        )
    findings.sort(key=lambda f: f.risk_score, reverse=True)
    log.info(
        "scoring: scored %d findings; top score=%.1f",
        len(findings),
        findings[0].risk_score if findings else 0.0,
    )
    return findings

