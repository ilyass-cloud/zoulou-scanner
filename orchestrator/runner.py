"""Runner: execute planned plugins, capture outputs and timing."""

from __future__ import annotations

import logging
import time
from typing import List, Tuple

from orchestrator.models import RawScanArtifact
from orchestrator.plugins.base import BasePlugin, PluginContext

log = logging.getLogger(__name__)

# Type alias for plan items produced by planner.plan()
PlanItem = Tuple[BasePlugin, PluginContext]


def run_all(plan: List[PlanItem]) -> List[RawScanArtifact]:
    """Execute each plugin sequentially and collect raw artifacts.

    Plugins are run one at a time (sequential) to keep resource usage
    predictable and avoid race conditions on shared output directories.
    Each plugin is wrapped in a try/except so a single failure does not
    abort the entire pipeline.
    """
    artifacts: List[RawScanArtifact] = []

    for plugin, context in plan:
        log.info("runner: starting plugin '%s'", plugin.name)
        start = time.monotonic()
        try:
            artifact = plugin.run(context)
        except Exception as exc:  # noqa: BLE001
            log.exception("runner: plugin '%s' raised an unhandled exception", plugin.name)
            artifact = plugin._make_artifact(
                stderr=f"Unhandled exception in plugin '{plugin.name}': {exc}",
                exit_code=255,
                duration_seconds=time.monotonic() - start,
            )

        # Ensure duration is recorded even if plugin forgot to set it
        if artifact.duration_seconds == 0.0:
            artifact.duration_seconds = round(time.monotonic() - start, 3)

        status = "OK" if artifact.exit_code == 0 else f"FAILED (exit={artifact.exit_code})"
        log.info(
            "runner: plugin '%s' finished in %.2fs – %s",
            plugin.name,
            artifact.duration_seconds,
            status,
        )
        if artifact.stderr:
            log.debug("runner: %s stderr:\n%s", plugin.name, artifact.stderr)

        artifacts.append(artifact)

    return artifacts

