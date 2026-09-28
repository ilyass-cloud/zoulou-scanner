#!/usr/bin/env python3
"""Mesures sur les scans de dépôts tiers : volume, déduplication, corrélation,
écart entre le classement par sévérité seule et le classement par score, et
sensibilité de ce classement aux deux coefficients configurables.

Usage : python analyse.py <dossier_scan> [<dossier_scan> …] > resultats.json

Chaque dossier est la sortie d'un ``orchestrator scan`` (report.json + raw/).
Le script ne relance aucun scanner : il relit report.json et recalcule les
scores avec ``orchestrator.scoring.score_finding``, la fonction du pipeline.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from orchestrator.models import Confidence, Exposure, Finding  # noqa: E402
from orchestrator.scoring import SEVERITY_BASE, score_finding  # noqa: E402

TOP = 20


def kendall_tau_b(a: list[float], b: list[float]) -> float:
    """Tau-b de Kendall, qui tient compte des ex æquo (nombreux ici)."""
    conc = disc = ties_a = ties_b = 0
    for i, j in combinations(range(len(a)), 2):
        da, db = a[i] - a[j], b[i] - b[j]
        if da == 0 and db == 0:
            continue
        if da == 0:
            ties_a += 1
        elif db == 0:
            ties_b += 1
        elif (da > 0) == (db > 0):
            conc += 1
        else:
            disc += 1
    n1, n2 = conc + disc + ties_a, conc + disc + ties_b
    return round((conc - disc) / (n1 * n2) ** 0.5, 4) if n1 and n2 else 1.0


def top_ids(findings: list[Finding], scores: dict[str, float], k: int = TOP) -> list[str]:
    order = sorted(findings, key=lambda f: (-scores[f.id], f.id))
    return [f.id for f in order[:k]]


def jaccard(x: list[str], y: list[str]) -> float:
    return round(len(set(x) & set(y)) / len(set(x) | set(y)), 4) if x or y else 1.0


def analyse(run_dir: Path) -> dict:
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    findings = [Finding.model_validate(f) for f in report["findings"]]
    after = Counter(f.tool for f in findings)

    base = {f.id: SEVERITY_BASE.get(f.severity_raw, 10.0) for f in findings}
    score = {f.id: f.risk_score for f in findings}
    ids = [f.id for f in findings]

    # Écart au classement par sévérité seule.
    moved = sum(1 for f in findings if score[f.id] != base[f.id])
    tau = kendall_tau_b([base[i] for i in ids], [score[i] for i in ids])

    # Sensibilité : chaque coefficient varié de ±5 autour de sa valeur.
    ref = top_ids(findings, score)
    sens = {}
    for name, values in (("low_confidence_penalty", (5.0, 15.0)),
                         ("external_exposure_boost", (10.0, 20.0))):
        for v in values:
            kw = {"low_confidence_penalty": 10.0, "external_exposure_boost": 15.0, name: v}
            alt = {f.id: score_finding(f, **kw) for f in findings}
            sens[f"{name}={v:g}"] = {
                f"jaccard_top{TOP}": jaccard(ref, top_ids(findings, alt)),
                "kendall_tau_b": kendall_tau_b([score[i] for i in ids], [alt[i] for i in ids]),
                "scores_modifies": sum(1 for i in ids if alt[i] != score[i]),
            }

    why = Counter()
    for f in findings:
        if f.confidence_raw == Confidence.LOW:
            why["confiance_basse"] += 1
        if f.corroborating_ids:
            why["corrobores"] += 1
        if f.risk_related_ids:
            why["liens_de_risque"] += 1
        if f.exposure == Exposure.EXTERNAL:
            why["exposition_externe"] += 1

    return {
        "cible": report["repo_path"],
        "outils": {a["tool"]: {"code_retour": a["exit_code"],
                               "duree_s": round(a["duration_seconds"], 1)}
                   for a in report.get("artifacts", [])},
        "resultats_apres_dedup_par_outil": dict(after),
        "total_apres_dedup": len(findings),
        "par_famille": dict(Counter(f.source.value for f in findings)),
        "par_severite": dict(Counter(f.severity_raw.value for f in findings)),
        "termes_du_score": dict(why),
        "scores_differant_de_la_base": moved,
        "kendall_tau_b_severite_vs_score": tau,
        "sensibilite": sens,
        "top10": [
            {"rang": r + 1, "score": score[f.id], "severite": f.severity_raw.value,
             "confiance": f.confidence_raw.value, "outil": f.tool, "titre": f.title[:90],
             "lieu": _where(f)}
            for r, f in enumerate(sorted(findings, key=lambda f: (-score[f.id], f.id))[:10])
        ],
    }


def _where(f: Finding) -> str:
    loc = f.location
    for attr in ("file_path", "manifest_path", "image_ref", "host"):
        v = getattr(loc, attr, None)
        if v:
            line = getattr(loc, "start_line", None) or getattr(loc, "package_name", None) or getattr(loc, "port", None)
            v = v.replace("/data/workspace/", "").replace(str(ROOT) + "/", "")
            return f"{v}:{line}" if line else v
    return "?"


if __name__ == "__main__":
    out = {Path(d).name: analyse(Path(d)) for d in sys.argv[1:]}
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    print()
