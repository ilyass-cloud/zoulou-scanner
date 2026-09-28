"""SAST stub plugin – reads a pre-generated SARIF or JSON findings file.

This stub is tool-agnostic: point it at any SARIF 2.1 file or a simplified
JSON array of findings via config.plugins.sast.input_file.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from orchestrator.models import RawScanArtifact, ScanType
from orchestrator.plugins.base import BasePlugin, PluginContext


class SASTStubPlugin(BasePlugin):
    name = "sast"
    scan_type = ScanType.SAST

    def run(self, context: PluginContext) -> RawScanArtifact:
        input_file: str | None = context.plugin_cfg.get("input_file")

        if not input_file:
            return self._make_artifact(
                stderr="sast: no input_file configured – skipping",
                exit_code=0,
            )

        src = Path(input_file)
        if not src.exists():
            return self._make_artifact(
                stderr=f"sast: input file not found: {input_file}",
                exit_code=1,
            )

        # Copy raw file into output dir for traceability
        raw_dir = Path(context.output_dir) / "raw" / self.name
        raw_dir.mkdir(parents=True, exist_ok=True)
        dest = raw_dir / src.name
        shutil.copy2(src, dest)

        try:
            data = json.loads(src.read_text(encoding="utf-8"))
            stdout = json.dumps(data, indent=2)
        except json.JSONDecodeError as exc:
            return self._make_artifact(
                raw_file_path=str(dest),
                stderr=f"sast: failed to parse JSON: {exc}",
                exit_code=1,
            )

        return self._make_artifact(
            raw_file_path=str(dest),
            stdout=stdout,
            exit_code=0,
        )

