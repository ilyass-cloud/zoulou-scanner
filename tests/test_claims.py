"""Les affirmations du mémoire, rendues exécutables.

Un mémoire peut diverger de son code sans que rien ne le signale ; c'est arrivé
plusieurs fois dans ce projet, et le chapitre 7 en donne le cas le plus net —
des tests au vert sur un analyseur de liste d'autorisation qui acceptait
`--script=vuln`, parce qu'ils vérifiaient une spécification fausse. Cette suite
prend le problème par l'autre bout : elle échoue lorsque le document cesse
d'être vrai du code.

Elle ne redit pas ce que d'autres suites disent déjà. `test_llm_grounding.py`
couvre la règle d'ancrage, `test_correlate.py` la corrélation,
`test_allowlist.py` le rejet des CIDR (CEL-2) et des entrées en tiret, et
`test_network_parse.py` la résolution préalable et l'appariement par
appartenance d'adresse (CEL-5). Une suite d'affirmations qui répète ce que
d'autres établissent ne prouve rien de plus et coûte à chaque modification.

Restent ici : CEL-1, CEL-3, CEL-4, les besoins fonctionnels, la
reproductibilité (BNF-2), le registre d'outils et l'expansion d'entités XML.

Le décompte du tableau 7.2 n'y figure pas : un test qui compte les tests est
circulaire et casse à chaque ajout. C'est `scripts/count_tests.sh`, appelé par
l'intégration continue, qui en répond.
"""

from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from orchestrator.config import OrchestratorConfig, ToolDefinition, load_tools_registry
from orchestrator.main import _build_parser
from orchestrator.planner import plan
from orchestrator.plugins.base import PluginContext
from orchestrator.plugins.live_plugin import build_argv
from orchestrator.plugins.network import NetworkPlugin, parse_nmap_xml

REPO = Path(__file__).resolve().parents[1]


# ===========================================================================
# CEL-1 — « En l'absence d'une telle liste, la capacité de scan réseau doit
#          demeurer désactivée par défaut. » (§3.5)
# ===========================================================================

def test_cel1_the_planner_skips_the_network_plugin_without_an_allowlist(tmp_path):
    cfg = OrchestratorConfig()
    items = plan(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        cfg=cfg,
        selected_tools=None,
        network_allowlist=None,
    )
    assert "network" not in [p.name for p, _ in items]


def test_cel1_the_plugin_itself_refuses_to_run_without_an_allowlist(tmp_path):
    """La garde est doublée : le greffon ne dépend pas du planificateur.

    Un contrôle qui n'existe qu'à un seul endroit du chemin est un contrôle
    qu'un second appelant contourne — c'est la leçon du §7.10.
    """
    artifact = NetworkPlugin().run(PluginContext(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        network_allowlist_path=None,
    ))
    assert "disabled" in artifact.stderr
    assert not artifact.stdout


def test_cel1_an_allowlist_does_put_the_plugin_in_the_plan(tmp_path):
    """Contre-épreuve : sans elle, le test précédent passerait aussi si le
    greffon réseau n'existait plus du tout."""
    allowlist = tmp_path / "allow.txt"
    allowlist.write_text("10.0.0.1\n", encoding="utf-8")
    items = plan(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        cfg=OrchestratorConfig(),
        selected_tools=None,
        network_allowlist=str(allowlist),
    )
    assert "network" in [p.name for p, _ in items]


# ===========================================================================
# CEL-3 — « Inventaire passif uniquement […] à l'exclusion de toute tentative
#          d'exploitation, d'attaque par force brute ou d'intrusion active. »
# ===========================================================================

# Drapeaux nmap qui font sortir du périmètre déclaré : moteur de script
# (exploitation), détection agressive, et les modules de force brute.
_ACTIVE_FLAGS = (
    "--script", "-sC", "-A", "--script-args", "--min-rate",
    "-sU", "--traceroute", "-O",
)


def test_cel3_the_shipped_profile_carries_no_active_flag():
    flags = OrchestratorConfig().network.default_flags
    joined = " ".join(flags)
    for bad in _ACTIVE_FLAGS:
        assert bad not in joined, f"{bad} dans le profil livré : {flags}"


def test_cel3_the_shipped_profile_is_the_conservative_one_the_thesis_describes():
    """Le §3.5 ne dit pas seulement « pas d'exploitation » : il annonce un
    profil délibérément conservateur. Un profil sans drapeau agressif mais en
    -T5 ne tiendrait pas cette promesse."""
    flags = OrchestratorConfig().network.default_flags
    assert "-sV" in flags          # détection de version : l'inventaire annoncé
    assert "--open" in flags       # ports ouverts seulement
    assert "-T2" in flags          # temporisation lente
    assert "--version-intensity" in flags
    intensity = flags[flags.index("--version-intensity") + 1]
    assert int(intensity) <= 2, f"intensité {intensity} : sondage plus insistant qu'annoncé"


def test_cel3_the_execute_mode_warning_states_the_passive_scope():
    warning = NetworkPlugin._EXECUTE_WARNING
    assert "no exploits" in warning.lower()
    assert "brute-force" in warning.lower()
    assert "written authorization" in warning.lower()   # volet information de CEL-5


# ===========================================================================
# CEL-4 — « Mode sans exécution (parse-only) […] sans déclencher aucun scan
#          actif. »
# ===========================================================================

def test_cel4_parse_only_mode_launches_no_process(tmp_path, monkeypatch):
    """L'affirmation porte sur ce qui n'arrive pas : rien ne doit être exécuté.

    Vérifier que le résultat est correct ne suffirait pas — il le serait aussi
    si un scan avait eu lieu. On rend donc tout lancement de processus fatal.
    """
    import orchestrator.plugins.network as network_mod

    def explode(*args, **kwargs):  # pragma: no cover - doit ne jamais courir
        raise AssertionError(f"un processus a été lancé en mode sans exécution : {args!r}")

    monkeypatch.setattr(network_mod.subprocess, "run", explode)
    monkeypatch.setattr(network_mod.subprocess, "Popen", explode)

    allowlist = tmp_path / "allow.txt"
    allowlist.write_text("10.0.0.1\n10.0.0.2\n", encoding="utf-8")

    artifact = NetworkPlugin().run(PluginContext(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        network_allowlist_path=str(allowlist),
        network_input_file=str(REPO / "examples" / "demo_scoring" / "nmap.xml"),
        global_cfg=OrchestratorConfig(),
    ))

    assert artifact.exit_code == 0, artifact.stderr
    assert json.loads(artifact.stdout), "le mode sans exécution doit tout de même produire des résultats"


def test_cel4_execute_mode_would_have_launched_one(tmp_path, monkeypatch):
    """Contre-épreuve du test précédent : sans `--network-input`, le greffon
    passe bien par un lancement de processus. Sans quoi le test ci-dessus
    passerait pour un greffon qui n'exécute jamais rien."""
    import orchestrator.plugins.network as network_mod
    launched = []

    def record(*args, **kwargs):
        launched.append(args)
        raise network_mod.subprocess.TimeoutExpired(cmd="nmap", timeout=1)

    # Le greffon vérifie d'abord que le binaire existe et sort en 127 sinon ;
    # sans ce leurre, le test passerait sans rien établir sur les machines —
    # dont l'intégration continue — où nmap n'est pas installé.
    monkeypatch.setattr(network_mod.shutil, "which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(network_mod.subprocess, "run", record)

    allowlist = tmp_path / "allow.txt"
    allowlist.write_text("10.0.0.1\n", encoding="utf-8")
    NetworkPlugin().run(PluginContext(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        network_allowlist_path=str(allowlist),
        network_input_file=None,
        global_cfg=OrchestratorConfig(),
    ))
    assert launched, "le mode exécution devrait lancer le scanner"


# ===========================================================================
# BF-1 à BF-5 — les sous-commandes et les options que le mémoire nomme
# ===========================================================================

def _subparsers():
    parser = _build_parser()
    action = next(a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction")
    return action.choices


def _options(subparser):
    names = set()
    for action in subparser._actions:
        names.update(action.option_strings)
    return names


@pytest.mark.parametrize("name", ["scan", "plan", "run-plan", "postprocess",
                                  "env-detect", "auto-plan"])
def test_the_subcommands_the_thesis_documents_exist(name):
    assert name in _subparsers(), f"sous-commande {name} absente"


@pytest.mark.parametrize("command,option", [
    # BF-1.1 — sélection explicite ou par détection d'environnement
    ("scan", "--tools"),
    ("scan", "--auto-scan"),
    ("env-detect", "--repo"),
    # BF-1.4 — registre d'outils déclaratif
    ("scan", "--tools-registry"),
    # BF-4.5 — désactivation complète du modèle de langage
    ("scan", "--no-llm"),
    ("postprocess", "--no-llm"),
    ("auto-plan", "--no-llm"),
    # CEL-1 et CEL-4 — liste d'autorisation, mode sans exécution
    ("scan", "--network-allowlist"),
    ("scan", "--network-input"),
    # §4.8 — l'architecture cerveau / exécuteur
    ("plan", "--runner-out"),
    ("run-plan", "--plan"),
    ("postprocess", "--run-id"),
])
def test_the_options_the_thesis_cites_exist(command, option):
    assert option in _options(_subparsers()[command]), \
        f"{command} n'expose pas {option}"


def test_bf45_no_llm_leaves_the_deterministic_steps_intact(tmp_path):
    """« le reste du pipeline demeurant pleinement fonctionnel » (BF-4.5)."""
    out = _run_demo_scan(tmp_path / "out")
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert len(report["findings"]) == 10
    for f in report["findings"]:
        assert f["risk_score"] > 0          # BF-3.1, le scoring a bien tourné
        assert f["id"]                      # BF-2.3, l'empreinte est là
        assert f["llm_justification"] is None
        assert f["llm_remediation"] is None
    # BF-2.4 : la corrélation aussi est déterministe, donc elle doit avoir eu lieu
    assert any(f["risk_related_ids"] or f["corroborating_ids"] for f in report["findings"])


# ===========================================================================
# BNF-2 — « À jeu de résultats bruts identique, le système doit produire
#          exactement les mêmes findings, empreintes, corrélations et scores. »
# ===========================================================================

def _run_demo_scan(out_dir: Path) -> Path:
    """Exécute le scénario de démonstration, greffons de substitution compris.

    Aucun binaire n'est invoqué : les greffons lisent des fichiers, et
    --network-input court-circuite le scanner réseau. --no-llm est
    indispensable — sans lui l'assertion de reproductibilité serait fausse par
    construction, et c'est exactement ce que le mémoire affirme : la partie
    mesurable est reproductible, l'interprétation ne l'est pas.
    """
    result = subprocess.run(
        [sys.executable, "-m", "orchestrator.main", "scan",
         "--repo", ".",
         "--config", "examples/demo_scoring/config.yaml",
         "--out", str(out_dir),
         "--network-allowlist", "examples/allowlist.txt",
         "--network-input", "examples/demo_scoring/nmap.xml",
         "--no-llm"],
        cwd=REPO, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return out_dir


def test_bnf2_two_runs_on_the_same_inputs_produce_the_same_report(tmp_path):
    """BNF-2 nomme exactement ce qui doit coïncider : « les mêmes findings
    normalisés, les mêmes empreintes, les mêmes corrélations et les mêmes
    scores ». On compare donc cela, et non le rapport entier — dont l'horodatage,
    l'identifiant d'exécution et les chemins de sortie varient par construction,
    et dont l'égalité ne dirait rien de plus sur la propriété énoncée.
    """
    first = json.loads((_run_demo_scan(tmp_path / "a") / "report.json").read_text(encoding="utf-8"))
    second = json.loads((_run_demo_scan(tmp_path / "b") / "report.json").read_text(encoding="utf-8"))

    assert first["findings"] == second["findings"]
    assert first["summary"] == second["summary"]
    # Nommément, et non par le seul jeu de l'égalité globale ci-dessus :
    assert [f["id"] for f in first["findings"]] == [f["id"] for f in second["findings"]]
    assert [f["risk_score"] for f in first["findings"]] == [f["risk_score"] for f in second["findings"]]
    assert [f["related_ids"] for f in first["findings"]] == [f["related_ids"] for f in second["findings"]]


def test_bnf2_the_ordering_is_reproducible_too(tmp_path):
    """Le tri par score décroissant fait partie de ce qui doit être stable :
    deux rapports aux mêmes résultats mais dans un autre ordre ne seraient pas
    « exactement les mêmes » pour un lecteur ni pour une chaîne d'intégration.
    """
    first = json.loads((_run_demo_scan(tmp_path / "e") / "report.json").read_text(encoding="utf-8"))
    scores = [f["risk_score"] for f in first["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_bnf2_the_volatile_fields_really_do_vary(tmp_path):
    """Contre-épreuve : si run_id ne changeait pas, le test précédent
    n'établirait rien sur ce qu'il prétend écarter."""
    first = json.loads((_run_demo_scan(tmp_path / "c") / "report.json").read_text(encoding="utf-8"))
    second = json.loads((_run_demo_scan(tmp_path / "d") / "report.json").read_text(encoding="utf-8"))
    assert first["run_id"] != second["run_id"]


# ===========================================================================
# §5.3.1 / BF-1.4 — « l'ajout de nouveaux outils sans modification du cœur »
# ===========================================================================

def test_a_tool_added_to_the_registry_is_planned_without_touching_the_code(tmp_path):
    registry = tmp_path / "tools_registry.yaml"
    registry.write_text(
        "tools:\n"
        "  - name: outil-fictif\n"
        "    category: sast\n"
        "    command: \"outil-fictif --format json --out {output_file} {repo_path}\"\n"
        "    output_format: json\n"
        "    install_check: \"outil-fictif --version\"\n",
        encoding="utf-8",
    )
    loaded = load_tools_registry(str(registry))
    assert [t.name for t in loaded.tools] == ["outil-fictif"]

    items = plan(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        cfg=OrchestratorConfig(),
        selected_tools=["outil-fictif"],
        tools_registry=loaded,
    )
    assert "outil-fictif" in [p.name for p, _ in items]


def test_a_registry_entry_becomes_argv_without_passing_through_a_shell():
    """Le §5.3.1 précise, depuis le correctif A-03, que le patron est découpé
    *avant* substitution : une valeur substituée reste un seul argument."""
    tool = ToolDefinition(
        name="outil-fictif", category="sast",
        command="outil-fictif --out {output_file} {repo_path}",
    )
    argv, redirect = build_argv(tool.command, {
        "output_file": "/tmp/out.json",
        "repo_path": "/srv/mon dépôt; rm -rf /",
    })
    assert argv == ["outil-fictif", "--out", "/tmp/out.json", "/srv/mon dépôt; rm -rf /"]
    assert redirect is None


# ===========================================================================
# §7.9 — l'expansion d'entités XML, seul point laissé ouvert par l'audit
# ===========================================================================
#
# L'audit a éprouvé ce point et l'a classé « non vulnérable », avec une réserve
# qu'aucun test ne gardait : « cette protection est une propriété de la version
# d'expat, pas du code ; figer une image de base avec expat < 2.4 la
# réintroduirait silencieusement ». Les deux assertions ci-dessous ferment ce
# point : l'une sur le comportement, l'autre sur la dépendance qui le porte.

def _billion_laughs(levels: int = 6, fan: int = 10) -> str:
    entities = "\n".join(
        f'  <!ENTITY a{i} "{("&a%d;" % (i - 1)) * fan}">' for i in range(1, levels + 1)
    )
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE nmaprun [\n'
        '  <!ENTITY a0 "aaaaaaaaaa">\n'
        f'{entities}\n'
        ']>\n'
        f'<nmaprun><host><address addrtype="ipv4" addr="&a{levels};"/></host></nmaprun>'
    )


def test_the_expat_amplification_guard_is_present():
    """La protection tient à la version de la bibliothèque, non au code.

    C'est précisément ce que l'audit signalait sans le garder : une image de
    base plus ancienne rouvrirait la porte sans qu'un seul test ne bouge.
    """
    import pyexpat
    assert pyexpat.version_info >= (2, 4, 0), pyexpat.version_info


def test_an_entity_amplification_payload_is_refused_not_expanded(tmp_path):
    payload = _billion_laughs()
    assert len(payload.encode()) < 600, "la charge doit rester minuscule : c'est tout le propos"

    path = tmp_path / "bomb.xml"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ET.ParseError):
        parse_nmap_xml(str(path))


def test_the_plugin_degrades_instead_of_crashing_on_such_a_payload(tmp_path):
    """« Rejetée proprement » : le pipeline rend un verdict, il ne remonte pas
    l'exception jusqu'à l'appelant."""
    path = tmp_path / "bomb.xml"
    path.write_text(_billion_laughs(), encoding="utf-8")
    allowlist = tmp_path / "allow.txt"
    allowlist.write_text("10.0.0.1\n", encoding="utf-8")

    artifact = NetworkPlugin().run(PluginContext(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        network_allowlist_path=str(allowlist),
        network_input_file=str(path),
        global_cfg=OrchestratorConfig(),
    ))
    assert artifact.exit_code == 1
    assert "parse error" in artifact.stderr.lower()


def test_a_well_formed_file_still_parses(tmp_path):
    """Contre-épreuve : la garde ne doit pas refuser tout le monde."""
    findings = parse_nmap_xml(str(REPO / "examples" / "demo_scoring" / "nmap.xml"))
    assert findings and all("host" in f and "port" in f for f in findings)
