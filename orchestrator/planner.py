"""Planner: decide which plugins to run based on repo contents and config.

Supports three modes:
  1. Stub mode (default) – uses built-in stub plugins that read pre-generated files
  2. Live mode – uses tools from the tools registry to run real scanners
  3. Auto mode – detects environment, optionally asks LLM, then runs live tools
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional, Tuple

from orchestrator.config import (
    OrchestratorConfig,
    ToolDefinition,
    ToolsRegistry,
    get_plugin_config,
    load_tools_registry,
)
from orchestrator.plugins.base import BasePlugin, PluginContext
from orchestrator.plugins.container_stub import ContainerStubPlugin
from orchestrator.plugins.deps_stub import DepsStubPlugin
from orchestrator.plugins.network import NetworkPlugin
from orchestrator.plugins.sast_stub import SASTStubPlugin
from orchestrator.plugins.secrets_stub import SecretsStubPlugin

log = logging.getLogger(__name__)

# Registry of all available stub plugins (order matters for execution)
_STUB_PLUGINS: List[BasePlugin] = [
    SASTStubPlugin(),
    DepsStubPlugin(),
    SecretsStubPlugin(),
    ContainerStubPlugin(),
    NetworkPlugin(),
]


def _build_live_plugins(
    tool_defs: List[ToolDefinition],
) -> List[BasePlugin]:
    """Instantiate LivePlugin instances from tool definitions."""
    from orchestrator.plugins.live_plugin import LivePlugin

    plugins: List[BasePlugin] = []
    for td in tool_defs:
        # Network tools are still handled by the dedicated NetworkPlugin
        if td.category == "network":
            log.info("planner: network tool '%s' skipped (use NetworkPlugin)", td.name)
            continue
        plugins.append(LivePlugin(td))
    return plugins


def select_tool_defs(
    repo_path: str,
    cfg: OrchestratorConfig,
    *,
    auto_scan: bool = False,
    tools_registry: Optional[ToolsRegistry] = None,
    selected_tools: Optional[List[str]] = None,
    families: Optional[List[str]] = None,
) -> List[ToolDefinition]:
    """Resolve which live scanner tools to run (network category excluded).

    ``families`` (sast, deps, secrets, container) restricts an automatic
    selection to the families ticked in the web form; an explicit
    ``selected_tools`` list is taken as is.

    This is the deterministic "selection" step shared by the all-in-one
    ``plan()`` and the brain-side ``build_scan_plan()``. It may consult the
    LLM (auto-scan) but produces a concrete list of tool definitions.
    """
    if not (auto_scan or selected_tools):
        return []

    if tools_registry is None:
        tools_registry = load_tools_registry(cfg.tools_registry_path)

    if selected_tools:
        tool_map = {t.name: t for t in tools_registry.tools}
        tool_defs = [tool_map[n] for n in selected_tools if n in tool_map]
        log.info("planner: %d explicitly selected tools", len(tool_defs))
    else:
        from orchestrator.auto_planner import auto_plan
        from orchestrator.llm_client import build_client_from_config

        llm_client = build_client_from_config(cfg) if cfg.llm.enabled else None
        _profile, tool_defs = auto_plan(
            repo_path, tools_registry,
            llm_client=llm_client,
            use_llm=cfg.llm.enabled,
        )
        log.info("planner: auto-scan selected %d tools", len(tool_defs))

    if families is not None and not selected_tools:
        kept = [td for td in tool_defs if td.category in families]
        log.info("planner: families %s keep %d of %d tools", sorted(families), len(kept), len(tool_defs))
        tool_defs = kept

    # Network tools are handled by NetworkPlugin / include_network, not as live tools.
    return [td for td in tool_defs if td.category != "network"]


def plan(
    repo_path: str,
    cfg: OrchestratorConfig,
    output_dir: str,
    network_allowlist: Optional[str] = None,
    network_input: Optional[str] = None,
    auto_scan: bool = False,
    tools_registry: Optional[ToolsRegistry] = None,
    selected_tools: Optional[List[str]] = None,
) -> List[Tuple[BasePlugin, PluginContext]]:
    """Return a list of (plugin, context) pairs to execute.

    Args:
        auto_scan: If True, use auto-planner to detect env and select tools.
        tools_registry: Pre-loaded tools registry (avoids re-loading from disk).
        selected_tools: Explicit list of tool names to run (overrides auto).

    Selection rules:
    - A plugin is included if its config entry has enabled=True (default).
    - NetworkPlugin is only included when network_allowlist is provided.
    - Each plugin gets its own PluginContext with relevant paths.
    """
    plan_items: List[Tuple[BasePlugin, PluginContext]] = []

    # ------------------------------------------------------------------
    # Determine which plugins to run
    # ------------------------------------------------------------------
    plugins_to_run: List[BasePlugin] = []

    if selected_tools or auto_scan:
        tool_defs = select_tool_defs(
            repo_path, cfg,
            auto_scan=auto_scan,
            tools_registry=tools_registry,
            selected_tools=selected_tools,
        )
        plugins_to_run = _build_live_plugins(tool_defs)

        # Always include NetworkPlugin if allowlist is provided
        if network_allowlist:
            plugins_to_run.append(NetworkPlugin())

        # Also include any stub plugins that have input_file set
        # (user may want to mix live + pre-generated results)
        for stub in _STUB_PLUGINS:
            if stub.name == "network":
                continue  # already handled
            pcfg = get_plugin_config(cfg, stub.name)
            if pcfg.input_file and pcfg.enabled:
                # Only add if no live plugin covers this category
                live_names = {p.name for p in plugins_to_run}
                if stub.name not in live_names:
                    plugins_to_run.append(stub)
                    log.info("planner: also including stub '%s' (has input_file)", stub.name)
    else:
        # Classic stub mode
        plugins_to_run = list(_STUB_PLUGINS)

    # ------------------------------------------------------------------
    # Build plan items
    # ------------------------------------------------------------------
    for plugin in plugins_to_run:
        pcfg = get_plugin_config(cfg, plugin.name)

        if not pcfg.enabled:
            log.info("planner: skipping %s (disabled in config)", plugin.name)
            continue

        # Network plugin requires explicit allowlist
        if plugin.name == "network" and not network_allowlist:
            log.info(
                "planner: skipping network plugin – no --network-allowlist provided"
            )
            continue

        ctx = PluginContext(
            repo_path=repo_path,
            output_dir=output_dir,
            plugin_cfg={"input_file": pcfg.input_file, **pcfg.extra},
            network_allowlist_path=network_allowlist if plugin.name == "network" else None,
            network_input_file=network_input if plugin.name == "network" else None,
            global_cfg=cfg,
        )
        plan_items.append((plugin, ctx))
        log.info("planner: queued %s", plugin.name)

    return plan_items


# ---------------------------------------------------------------------------
# Two-tier (brain ↔ runner) planning
# ---------------------------------------------------------------------------

def build_scan_plan(
    run_id: str,
    cfg: OrchestratorConfig,
    *,
    plan_repo_path: str,
    runner_repo_path: str,
    runner_output_dir: str,
    auto_scan: bool = False,
    tools_registry: Optional[ToolsRegistry] = None,
    selected_tools: Optional[List[str]] = None,
    families: Optional[List[str]] = None,
    network_allowlist: Optional[str] = None,
    network_input: Optional[str] = None,
):
    """Compute a deterministic :class:`ScanPlan` for the runner container.

    Tool *selection* (env detection, optional LLM) reads ``plan_repo_path`` –
    the path visible to the brain. The emitted plan references
    ``runner_repo_path`` / ``runner_output_dir`` – the paths the runner
    container will see (e.g. ``/scan/target`` and ``/scan/out``). Likewise
    ``network_allowlist`` / ``network_input`` must already be runner-side paths.
    """
    from orchestrator.ipc import ScanPlan

    tool_defs = select_tool_defs(
        plan_repo_path, cfg,
        auto_scan=auto_scan,
        tools_registry=tools_registry,
        selected_tools=selected_tools,
        families=families,
    )
    return ScanPlan(
        run_id=run_id,
        repo_path=runner_repo_path,
        output_dir=runner_output_dir,
        tools=tool_defs,
        include_network=bool(network_allowlist),
        network_allowlist_path=network_allowlist,
        network_input_file=network_input,
        config=cfg,
    )


def plan_items_from_scan_plan(plan) -> List[Tuple[BasePlugin, PluginContext]]:
    """Rebuild executable (plugin, context) pairs from a :class:`ScanPlan`.

    Runs on the runner side: instantiates a LivePlugin per selected tool and,
    if requested, the NetworkPlugin. No re-planning happens here.
    """
    from orchestrator.plugins.live_plugin import LivePlugin

    cfg = plan.config
    items: List[Tuple[BasePlugin, PluginContext]] = []

    for td in plan.tools:
        if td.category == "network":
            continue
        plugin = LivePlugin(td)
        pcfg = get_plugin_config(cfg, plugin.name)
        ctx = PluginContext(
            repo_path=plan.repo_path,
            output_dir=plan.output_dir,
            plugin_cfg={"input_file": pcfg.input_file, **pcfg.extra},
            global_cfg=cfg,
        )
        items.append((plugin, ctx))

    if plan.include_network:
        ctx = PluginContext(
            repo_path=plan.repo_path,
            output_dir=plan.output_dir,
            plugin_cfg={},
            network_allowlist_path=plan.network_allowlist_path,
            network_input_file=plan.network_input_file,
            global_cfg=cfg,
        )
        items.append((NetworkPlugin(), ctx))

    return items

