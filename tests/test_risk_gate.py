"""Tests for the risk gate — the exit code by which a scan renders a verdict.

Two defects motivated these. The gate looked only at `severity_raw`, so a
finding driven to 100 by exposure and correlation did not trip it if its source
severity was HIGH — the pipeline's own contribution was invisible to the one
control that acts on it. And the gate lived in `cmd_scan` alone, so the
containerised plan/run-plan/postprocess path — the one the web backend uses, and
therefore the only one a CI pipeline travels — could never return non-zero.
"""

from __future__ import annotations

import argparse
import json

import pytest

from orchestrator.config import OrchestratorConfig
from orchestrator.ipc import ARTIFACTS_FILENAME
from orchestrator.main import RISK_GATE_EXIT, cmd_postprocess, risk_gate
from orchestrator.models import (
    CodeLocation,
    Confidence,
    Exposure,
    Finding,
    ScanType,
    Severity,
)


def _finding(severity=Severity.HIGH, score=0.0):
    f = Finding(
        source=ScanType.SAST,
        tool="test",
        title="Test finding",
        description="desc",
        location=CodeLocation(file_path="foo.py", start_line=1),
        severity_raw=severity,
        confidence_raw=Confidence.HIGH,
        exposure=Exposure.UNKNOWN,
    )
    f.risk_score = score
    return f


# ---------------------------------------------------------------------------
# No policy configured
# ---------------------------------------------------------------------------

def test_no_policy_never_trips():
    cfg = OrchestratorConfig()
    assert cfg.fail_on_critical is False and cfg.fail_on_score is None
    assert risk_gate(cfg, [_finding(Severity.CRITICAL, 100.0)]) == 0


def test_empty_findings_never_trip():
    cfg = OrchestratorConfig(fail_on_critical=True, fail_on_score=1.0)
    assert risk_gate(cfg, []) == 0


# ---------------------------------------------------------------------------
# fail_on_critical — raw severity
# ---------------------------------------------------------------------------

def test_critical_finding_trips_fail_on_critical():
    cfg = OrchestratorConfig(fail_on_critical=True)
    assert risk_gate(cfg, [_finding(Severity.CRITICAL, 80.0)]) == RISK_GATE_EXIT


def test_high_finding_does_not_trip_fail_on_critical():
    cfg = OrchestratorConfig(fail_on_critical=True)
    assert risk_gate(cfg, [_finding(Severity.HIGH, 60.0)]) == 0


# ---------------------------------------------------------------------------
# fail_on_score — the computed score
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,threshold,expected", [
    (70.0, 70.0, RISK_GATE_EXIT),   # le seuil est inclusif
    (69.9, 70.0, 0),
    (100.0, 70.0, RISK_GATE_EXIT),
    (0.0, 0.0, RISK_GATE_EXIT),     # un seuil de zéro attrape tout
])
def test_score_threshold_is_inclusive(score, threshold, expected):
    cfg = OrchestratorConfig(fail_on_score=threshold)
    assert risk_gate(cfg, [_finding(Severity.LOW, score)]) == expected


def test_a_score_driven_finding_trips_where_severity_alone_would_not():
    """Le défaut d'origine : un résultat HIGH porté à 100 par son exposition et
    ses corrélations échappait à une garde qui n'interroge que sa sévérité."""
    boosted = _finding(Severity.HIGH, 100.0)
    assert risk_gate(OrchestratorConfig(fail_on_critical=True), [boosted]) == 0
    assert risk_gate(OrchestratorConfig(fail_on_score=90.0), [boosted]) == RISK_GATE_EXIT


def test_both_policies_are_cumulative():
    cfg = OrchestratorConfig(fail_on_critical=True, fail_on_score=90.0)
    assert risk_gate(cfg, [_finding(Severity.CRITICAL, 10.0)]) == RISK_GATE_EXIT
    assert risk_gate(cfg, [_finding(Severity.LOW, 95.0)]) == RISK_GATE_EXIT
    assert risk_gate(cfg, [_finding(Severity.LOW, 10.0)]) == 0


# ---------------------------------------------------------------------------
# Reachability from postprocess — the path the web backend and CI travel
# ---------------------------------------------------------------------------

def _artifacts_dir(tmp_path, severity="HIGH"):
    """Un artefact de dépendances minimal, écrit à la main : pas de scanner."""
    payload = [{
        "package": "demo", "version": "1.0.0", "cve": "CVE-2000-0001",
        "severity": severity, "confidence": "HIGH",
        "description": "fixture", "evidence": "fixture",
    }]
    artifacts = {"artifacts": [{
        "plugin_name": "deps", "scan_type": "DEPS", "tool": "deps",
        "stdout": json.dumps(payload), "exit_code": 0,
    }]}
    (tmp_path / ARTIFACTS_FILENAME).write_text(json.dumps(artifacts), encoding="utf-8")
    return tmp_path


def _postprocess(out_dir, config_path=None):
    return cmd_postprocess(argparse.Namespace(
        out=str(out_dir), run_id="test-run", repo="", config=config_path,
        no_llm=True, verbose=False,
    ))


def test_postprocess_returns_zero_without_a_policy(tmp_path):
    assert _postprocess(_artifacts_dir(tmp_path)) == 0
    assert (tmp_path / "report.json").exists()


def test_postprocess_can_trip_the_gate(tmp_path, monkeypatch):
    """Régression : la garde n'existait que dans `scan`, donc le chemin
    conteneurisé — le seul qu'emprunte une chaîne d'intégration — renvoyait
    toujours zéro, quel que soit le résultat."""
    out = _artifacts_dir(tmp_path, severity="CRITICAL")
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps({"fail_on_critical": True}), encoding="utf-8")
    assert _postprocess(out, str(cfg_path)) == RISK_GATE_EXIT


def test_postprocess_writes_its_reports_before_the_gate_fires(tmp_path):
    """Un verdict n'est pas une panne : l'appelant doit trouver ses rapports."""
    out = _artifacts_dir(tmp_path, severity="CRITICAL")
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps({"fail_on_score": 1.0}), encoding="utf-8")
    assert _postprocess(out, str(cfg_path)) == RISK_GATE_EXIT
    assert (tmp_path / "report.json").exists(), "le rapport JSON doit exister malgré le verdict"
    assert (tmp_path / "report.md").exists(), "le rapport Markdown aussi"
