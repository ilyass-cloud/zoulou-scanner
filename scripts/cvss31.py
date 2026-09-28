#!/usr/bin/env python3
"""CVSS v3.1 base-score calculator.

Why this exists. The audit rates seventeen findings and the report reproduces
those ratings in table 7.1, claiming a score "calculated, not estimated". A
score is only calculated if the vector it comes from is written down and the
arithmetic can be replayed. Neither the audit report nor the thesis carried a
single vector, so the claim was unverifiable by anyone — including its author.
This module supplies the arithmetic; `docs/audit_findings.json` supplies the
vectors; `tests/test_cvss31.py` checks the arithmetic against published
reference vectors before either is trusted.

Only the base metric group is implemented. Temporal and environmental metrics
are deliberately absent: the audit rates the code as it stood, with no claim
about exploit maturity or any particular deployment, and implementing metrics
the project does not use would invite their silent misuse.

Specification: CVSS v3.1, FIRST.org, section 7.1 (base equations) and the
Appendix A rounding function.

    $ python3 scripts/cvss31.py CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    9.8 CRITICAL
"""

from __future__ import annotations

import math
import sys
from typing import Dict, Tuple

__all__ = ["base_score", "parse_vector", "severity", "Cvss31Error"]


class Cvss31Error(ValueError):
    """A vector string that is not a well-formed CVSS v3.1 base vector."""


# --- Metric weights (CVSS v3.1 §7.4) ---------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
# Privileges Required is the one metric whose weight depends on Scope.
_PR = {
    False: {"N": 0.85, "L": 0.62, "H": 0.27},   # Scope unchanged
    True:  {"N": 0.85, "L": 0.68, "H": 0.50},   # Scope changed
}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

_METRICS: Dict[str, Tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S":  ("U", "C"),
    "C":  ("H", "L", "N"),
    "I":  ("H", "L", "N"),
    "A":  ("H", "L", "N"),
}
_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str) -> Dict[str, str]:
    """Split a CVSS:3.1 base vector into its metrics, rejecting anything else.

    Strict on purpose. A calculator that quietly accepts a malformed vector, or
    a v3.0 one, would produce a number that looks authoritative and is not.
    """
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise Cvss31Error(f"vector must start with CVSS:3.1 — got {parts[0]!r}")

    seen: Dict[str, str] = {}
    for part in parts[1:]:
        if part.count(":") != 1:
            raise Cvss31Error(f"malformed metric {part!r}")
        name, value = part.split(":")
        if name not in _METRICS:
            raise Cvss31Error(f"unknown or non-base metric {name!r}")
        if name in seen:
            raise Cvss31Error(f"metric {name!r} given twice")
        if value not in _METRICS[name]:
            raise Cvss31Error(f"{name}:{value} is not a valid value")
        seen[name] = value

    missing = [m for m in _ORDER if m not in seen]
    if missing:
        raise Cvss31Error(f"missing base metric(s): {', '.join(missing)}")
    return seen


def _roundup(value: float) -> float:
    """Round up to one decimal, per CVSS v3.1 Appendix A.

    The specification gives this in integer arithmetic rather than as
    `math.ceil(x * 10) / 10`, and warns that the float form can round a value
    that is exactly a tenth in decimal but a hair above it in binary up to the
    next tenth. Honesty about what was checked: enumerating all 2592 base
    vectors, the two forms agree on every one of them, so no such divergence is
    reachable here — `tests/test_cvss31.py` pins that agreement rather than
    asserting a difference that was never exhibited. The spec's formulation is
    kept anyway, because matching the normative text costs nothing and removes
    the question.
    """
    integer = int(round(value * 100_000))
    if integer % 10_000 == 0:
        return integer / 100_000.0
    return (math.floor(integer / 10_000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Return the CVSS v3.1 base score for a base vector string."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    iss = 1 - (
        (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = (
        8.22 * _AV[m["AV"]] * _AC[m["AC"]]
        * _PR[scope_changed][m["PR"]] * _UI[m["UI"]]
    )
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return _roundup(min(raw, 10.0))


def severity(score: float) -> str:
    """Qualitative rating (CVSS v3.1 §5, table 14)."""
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} CVSS:3.1/AV:.../A:...", file=sys.stderr)
        return 2
    try:
        score = base_score(argv[1])
    except Cvss31Error as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{score:.1f} {severity(score)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
