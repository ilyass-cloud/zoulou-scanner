"""Base plugin interface for the Security Orchestrator."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from orchestrator.models import RawScanArtifact, ScanType


@dataclass
class PluginContext:
    """Runtime context passed to every plugin."""
    repo_path: str
    output_dir: str
    # Plugin-specific config dict (from OrchestratorConfig.plugins[name])
    plugin_cfg: Dict[str, Any] = field(default_factory=dict)
    # Network-specific extras
    network_allowlist_path: Optional[str] = None
    network_input_file: Optional[str] = None
    # Global config reference (typed as Any to avoid circular imports)
    global_cfg: Any = None


class BasePlugin(ABC):
    """Abstract base class every plugin must implement."""

    #: Human-readable plugin name (must be unique across plugins)
    name: str = ""

    #: Which scan category this plugin belongs to
    scan_type: ScanType = ScanType.SAST

    @abstractmethod
    def run(self, context: PluginContext) -> RawScanArtifact:
        """Execute the plugin and return a raw scan artifact.

        Implementations must:
        - Never raise unhandled exceptions (catch and record in stderr/exit_code).
        - Write machine-readable output to context.output_dir/raw/<name>/.
        - Return a RawScanArtifact regardless of success or failure.
        """

    # ------------------------------------------------------------------
    # Helpers available to all plugins
    # ------------------------------------------------------------------

    def _make_artifact(
        self,
        *,
        raw_file_path: Optional[str] = None,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        duration_seconds: float = 0.0,
        tool_version: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> RawScanArtifact:
        return RawScanArtifact(
            plugin_name=self.name,
            scan_type=self.scan_type,
            tool=self.name,
            tool_version=tool_version,
            raw_file_path=raw_file_path,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_seconds=duration_seconds,
            extra=extra or {},
        )

