# -*- coding: utf-8 -*-
"""
Compare le classement par sévérité seule au classement par score de risque.

Le §4.5 du mémoire affirme que le moteur de scoring priorise mieux qu'une table
de correspondance de sévérité. Sur le scan du chapitre 6, cette affirmation
n'était pas démontrable : aucun résultat n'avait d'exposition, de corrélation
ni de faible confiance, de sorte que le score se réduisait à la base. Ce script
rend l'écart mesurable sur un scénario qui, lui, exerce les trois termes.

Il recalcule chaque terme depuis les champs du rapport plutôt que de les relire
d'un journal : le tableau produit est ainsi vérifiable à la main.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from orchestrator.scoring import SEVERITY_BASE  # noqa: E402
from orchestrator.models import Confidence, Exposure, Severity  # noqa: E402

REPORT = ROOT / "out_demo_scoring" / "report.json"
EXPOSURE_BOOST = 15.0
CONFIDENCE_PENALTY = 10.0
PER_LINK = 5.0
MAX_LINKS_BOOST = 15.0


def terms(f):
    """Décompose le score d'un résultat selon l'équation (4.1)."""
    base = SEVERITY_BASE.get(Severity(f["severity_raw"]), 10.0)
    boost = EXPOSURE_BOOST if f["exposure"] == Exposure.EXTERNAL.value else 0.0
    corroborated = bool(f.get("corroborating_ids"))
    low = f["confidence_raw"] == Confidence.LOW.value
    penalty = CONFIDENCE_PENALTY if (low and not corroborated) else 0.0
    corr = min(len(f.get("risk_related_ids", [])) * PER_LINK, MAX_LINKS_BOOST)
    return base, boost, penalty, corr


def label(f):
    loc = f.get("location") or {}
    for key in ("package_name", "product", "file_path"):
        if loc.get(key):
            what = loc[key]
            break
    else:
        what = f["title"][:28]
    port = f" :{loc['port']}" if loc.get("port") else ""
    text = f"{f['source']} · {what}{port}"
    return text if len(text) <= 34 else text[:31] + "…"


def main():
    if not REPORT.exists():
        raise SystemExit(f"rapport introuvable : {REPORT} — lancer run.sh d'abord")
    findings = json.loads(REPORT.read_text(encoding="utf-8"))["findings"]

    rows = []
    for f in findings:
        base, boost, penalty, corr = terms(f)
        assert abs(base + boost - penalty + corr - f["risk_score"]) < 0.01, (
            f"décomposition incohérente pour {f['id']} : "
            f"{base}+{boost}-{penalty}+{corr} != {f['risk_score']}"
        )
        rows.append({
            "label": label(f), "sev": f["severity_raw"], "conf": f["confidence_raw"],
            "base": base, "boost": boost, "penalty": penalty, "corr": corr,
            "score": f["risk_score"],
            "corroborated": bool(f.get("corroborating_ids")),
        })

    by_severity = sorted(rows, key=lambda r: (-r["base"], r["label"]))
    by_score = sorted(rows, key=lambda r: (-r["score"], r["label"]))
    rank_sev = {r["label"]: i + 1 for i, r in enumerate(by_severity)}

    print("Classement par score de risque, et rang qu'occupait chaque résultat")
    print("dans un classement par sévérité seule.\n")
    head = f"{'#':>2}  {'(sév.)':>6}  {'résultat':<34} {'base':>5} {'expo':>5} {'conf':>5} {'corr':>5} {'score':>6}"
    print(head)
    print("-" * len(head))
    for i, r in enumerate(by_score, start=1):
        was = rank_sev[r["label"]]
        moved = "↑" if was > i else ("↓" if was < i else " ")
        print(f"{i:>2}{moved} {was:>5}   {r['label']:<34} "
              f"{r['base']:>5.0f} {r['boost']:>+5.0f} {-r['penalty']:>+5.0f} {r['corr']:>+5.0f} {r['score']:>6.1f}")

    moves = [(r["label"], rank_sev[r["label"]], i + 1)
             for i, r in enumerate(by_score) if rank_sev[r["label"]] != i + 1]
    print(f"\n{len(moves)} résultat(s) changent de rang entre les deux classements.")
    for lbl, was, now in moves:
        print(f"  {lbl} : {was} → {now}")

    twins = [r for r in rows if r["sev"] == "MEDIUM" and r["conf"] == "LOW"]
    if len(twins) >= 2:
        print("\nRésultats identiques sur le papier — même sévérité, même confiance brute —")
        print("que seule la corroboration sépare :")
        for r in sorted(twins, key=lambda r: -r["score"]):
            etat = "corroboré par un second outil" if r["corroborated"] else "non corroboré"
            print(f"  {r['label']:<34} {r['score']:>5.1f}   ({etat})")


if __name__ == "__main__":
    main()
