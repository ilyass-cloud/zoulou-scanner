"""Brain ↔ runner contract (inter-container IPC).

The orchestrator is split into two roles:

* **Brain** (web / orchestrator image, no scanners) – detects the repo
  environment, decides *which* tools to run, then post-processes the raw
  results (normalize → correlate → score → LLM → report).
* **Runner** (scanner-runner image, all scanners installed) – an ephemeral
  container that only *executes* the planned tool commands against the
  mounted target and writes raw artifacts back to a shared volume.

This module defines the two files exchanged between them on the shared
``scans`` volume:

* ``plan.json``      – a :class:`ScanPlan` produced by the brain.
* ``artifacts.json`` – the list of :class:`RawScanArtifact` produced by the
  runner.

Both payloads are self-contained: ``artifacts.json`` embeds each tool's
``stdout`` so the brain can normalise findings without needing access to the
runner's ``raw/`` output files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from pydantic import BaseModel, Field

from orchestrator.config import OrchestratorConfig, ToolDefinition
from orchestrator.models import RawScanArtifact

PLAN_FILENAME = "plan.json"
ARTIFACTS_FILENAME = "artifacts.json"


class ScanPlan(BaseModel):
    """Deterministic scan plan handed to the runner container.

    ``repo_path`` and ``output_dir`` are paths *inside the runner container*
    (e.g. ``/scan/target`` and ``/scan/out``), not host paths. Tool selection
    has already been decided by the brain; the runner does not re-plan.
    """

    run_id: str
    repo_path: str
    output_dir: str

    # Live scanner tools to execute (already selected; network category excluded).
    tools: List[ToolDefinition] = Field(default_factory=list)

    # Network inventory plugin (gated – only set when an allowlist was provided).
    include_network: bool = False
    network_allowlist_path: str | None = None
    network_input_file: str | None = None

    # Full config so the runner can rebuild plugin contexts (network settings,
    # per-plugin input files, default exposure, etc.). LLM settings are ignored
    # by the runner.
    config: OrchestratorConfig = Field(default_factory=OrchestratorConfig)


# ---------------------------------------------------------------------------
# Plan IO
# ---------------------------------------------------------------------------

def write_scan_plan(plan: ScanPlan, output_dir: str | Path) -> Path:
    """Serialise ``plan`` to ``<output_dir>/plan.json`` and return its path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / PLAN_FILENAME
    path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_scan_plan(path: str | Path) -> ScanPlan:
    """Load a :class:`ScanPlan` from ``path``."""
    text = Path(path).read_text(encoding="utf-8")
    return ScanPlan.model_validate_json(text)


# ---------------------------------------------------------------------------
# Artifact IO
# ---------------------------------------------------------------------------

def write_artifacts(artifacts: List[RawScanArtifact], output_dir: str | Path) -> Path:
    """Serialise raw artifacts to ``<output_dir>/artifacts.json``."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / ARTIFACTS_FILENAME
    payload = {"artifacts": [a.model_dump(mode="json") for a in artifacts]}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_artifacts(path: str | Path) -> List[RawScanArtifact]:
    """Load raw artifacts written by the runner."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [RawScanArtifact.model_validate(a) for a in data.get("artifacts", [])]