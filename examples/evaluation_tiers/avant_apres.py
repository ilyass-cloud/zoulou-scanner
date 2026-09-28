#!/usr/bin/env python3
"""Résultats normalisés par outil, avant et après les adaptateurs de formats natifs.

Usage : python avant_apres.py <commit_avant> <dossier_scan> [<dossier_scan> …]

Les sorties brutes des scanners (les artefacts conservés dans report.json) sont
soumises aux deux normaliseurs : celui du commit indiqué, extrait par
``git show``, et celui de l'arbre de travail. Aucun scanner n'est relancé, si
bien que l'écart mesure la seule normalisation.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from orchestrator import normalize as apres  # noqa: E402
from orchestrator.correlate import deduplicate  # noqa: E402
from orchestrator.models import RawScanArtifact  # noqa: E402


def charger_avant(commit: str):
    source = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{commit}:orchestrator/normalize.py"],
        check=True, capture_output=True, text=True,
    ).stdout
    tmp = Path(tempfile.mkdtemp()) / "normalize_avant.py"
    tmp.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("normalize_avant", tmp)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def compter(module, artefacts):
    par_outil, tous = {}, []
    for a in artefacts:
        f = module.normalize_artifact(a)
        par_outil[a.tool] = len(f)
        tous.extend(f)
    return par_outil, len(deduplicate(tous))


if __name__ == "__main__":
    avant = charger_avant(sys.argv[1])
    sortie = {}
    for d in sys.argv[2:]:
        report = json.loads((Path(d) / "report.json").read_text(encoding="utf-8"))
        arts = [RawScanArtifact.model_validate(a) for a in report["artifacts"]]
        av, av_dedup = compter(avant, arts)
        ap, ap_dedup = compter(apres, arts)
        sortie[Path(d).name] = {
            "avant": av, "avant_apres_dedup": av_dedup,
            "apres": ap, "apres_apres_dedup": ap_dedup,
        }
    json.dump(sortie, sys.stdout, ensure_ascii=False, indent=1)
    print()
