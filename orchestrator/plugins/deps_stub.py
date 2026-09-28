"""Dependency scanning stub plugin – reads a pre-generated JSON findings file.

Expected JSON format: a list of objects with at minimum:
  { "package": str, "version": str, "cve": str, "severity": str,
    "description": str, "manifest": str }
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from orchestrator.models import RawScanArtifact, ScanType
from orchestrator.plugins.base import BasePlugin, PluginContext


class DepsStubPlugin(BasePlugin):
    name = "deps"
    scan_type = ScanType.DEPS

    def run(self, context: PluginContext) -> RawScanArtifact:
        input_file: str | None = context.plugin_cfg.get("input_file")

        if not input_file:
            return self._make_artifact(
                stderr="deps: no input_file configured – skipping",
                exit_code=0,
            )

        src = Path(input_file)
        if not src.exists():
            return self._make_artifact(
                stderr=f"deps: input file not found: {input_file}",
                exit_code=1,
            )

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
                stderr=f"deps: failed to parse JSON: {exc}",
                exit_code=1,
            )

        return self._make_artifact(
            raw_file_path=str(dest),
            stdout=stdout,
            exit_code=0,
        )

