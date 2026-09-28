"""Configuration loader for the Security Orchestrator."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from pydantic import BaseModel, Field, model_validator

# Le défaut du budget de jetons appartient au client, qui est seul à savoir ce
# qu'il envoie au serveur. L'importer évite d'en tenir deux copies.
from orchestrator.llm_client import DEFAULT_MAX_TOKENS


# ---------------------------------------------------------------------------
# Sub-config models
# ---------------------------------------------------------------------------

class LLMConfig(BaseModel):
    base_url: str = "http://localhost:1234"
    model: str = "local-model"
    timeout_seconds: int = 120
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = 0.2
    enabled: bool = True
    # Per-finding analysis: how many top findings to analyse individually,
    # and how many to process concurrently against the LLM server.
    top_findings_count: int = 10
    analysis_workers: int = 1

    @model_validator(mode="after")
    def _override_from_env(self) -> "LLMConfig":
        """Allow LLM_BASE_URL env var to override base_url (e.g. in Docker)."""
        env_url = os.environ.get("LLM_BASE_URL")
        if env_url:
            self.base_url = env_url
        return self


class NetworkScanConfig(BaseModel):
    """Configuration for the network inventory plugin."""
    # Scanner executable (must be installed separately)
    scanner_binary: str = "nmap"
    # Conservative inventory profile flags – no exploit, no brute-force
    default_flags: List[str] = Field(
        default_factory=lambda: ["-sV", "--open", "-T2", "--version-intensity", "2"]
    )
    # Allow CIDR ranges in allowlist (default: deny for safety)
    allow_cidr: bool = False
    # Default exposure label applied to network findings
    default_exposure: str = "internal"
    # Output format expected from scanner
    output_format: str = "xml"


class PluginConfig(BaseModel):
    enabled: bool = True
    input_file: Optional[str] = None   # pre-generated findings file for stubs
    extra: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Tool registry models (for live scanner integration)
# ---------------------------------------------------------------------------

class ToolDefinition(BaseModel):
    """Definition of a single external scanning tool."""
    name: str                          # unique tool id, e.g. "semgrep"
    label: str = ""                    # human-readable label
    category: str                      # sast | deps | secrets | container | network
    command: str                       # command template, e.g. "semgrep --sarif -o {output_file} {repo_path}"
    output_format: str = "sarif"       # sarif | json | xml | text
    output_file_flag: str = ""         # if tool writes to a file, the flag pattern (e.g. "-o")
    install_check: str = ""            # command to verify tool is installed, e.g. "semgrep --version"
    description: str = ""
    enabled: bool = True
    timeout_seconds: int = 300
    env: Dict[str, str] = Field(default_factory=dict)  # extra env vars
    extra_args: List[str] = Field(default_factory=list)


class ToolsRegistry(BaseModel):
    """Collection of available scanning tools."""
    tools: List[ToolDefinition] = Field(default_factory=list)


class OrchestratorConfig(BaseModel):
    """Top-level orchestrator configuration."""
    llm: LLMConfig = Field(default_factory=LLMConfig)
    network: NetworkScanConfig = Field(default_factory=NetworkScanConfig)

    # Per-plugin overrides keyed by plugin name
    plugins: Dict[str, PluginConfig] = Field(default_factory=dict)

    # Tool registry
    tools_registry_path: Optional[str] = None   # path to tools_registry.yaml
    auto_scan: bool = False                      # enable auto-detect + LLM planning

    # Paths
    output_dir: str = "out"

    # Scoring
    external_exposure_boost: float = 15.0
    low_confidence_penalty: float = 10.0

    # Misc
    fail_on_critical: bool = False
    #: Code de sortie non nul dès qu'un résultat atteint ce score de risque.
    #: Le drapeau ci-dessus ne regarde que la sévérité brute rapportée par
    #: l'outil : un résultat porté à 100 par l'exposition et la corrélation ne
    #: le déclenche pas s'il est HIGH à la source. Ce seuil porte sur le score
    #: effectivement calculé, qui est ce que le pipeline prétend prioriser.
    fail_on_score: Optional[float] = None


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_DEFAULTS: Dict[str, Any] = {}


def load_config(path: Optional[str]) -> OrchestratorConfig:
    """Load config from a YAML or JSON file; fall back to defaults."""
    if path is None:
        return OrchestratorConfig()

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw: Dict[str, Any] = {}
    suffix = config_path.suffix.lower()

    if suffix in (".yaml", ".yml"):
        if not _YAML_AVAILABLE:
            raise ImportError(
                "PyYAML is required to load YAML configs. "
                "Install it with: pip install pyyaml"
            )
        with config_path.open() as fh:
            raw = yaml.safe_load(fh) or {}
    elif suffix == ".json":
        with config_path.open() as fh:
            raw = json.load(fh)
    else:
        raise ValueError(f"Unsupported config format: {suffix}. Use .yaml or .json")

    return OrchestratorConfig.model_validate(raw)


def get_plugin_config(cfg: OrchestratorConfig, plugin_name: str) -> PluginConfig:
    """Return plugin-specific config, falling back to defaults."""
    return cfg.plugins.get(plugin_name, PluginConfig())


def load_tools_registry(path: Optional[str]) -> ToolsRegistry:
    """Load tools registry from a YAML or JSON file; fall back to empty."""
    if path is None:
        # Try default locations
        for default in ("tools_registry.yaml", "configs/tools_registry.yaml"):
            if Path(default).exists():
                path = default
                break
    if path is None:
        return ToolsRegistry()

    reg_path = Path(path)
    if not reg_path.exists():
        return ToolsRegistry()

    raw: Dict[str, Any] = {}
    suffix = reg_path.suffix.lower()

    if suffix in (".yaml", ".yml"):
        if not _YAML_AVAILABLE:
            raise ImportError("PyYAML is required to load YAML configs.")
        with reg_path.open() as fh:
            raw = yaml.safe_load(fh) or {}
    elif suffix == ".json":
        with reg_path.open() as fh:
            raw = json.load(fh)
    else:
        raise ValueError(f"Unsupported format: {suffix}")

    return ToolsRegistry.model_validate(raw)


def save_tools_registry(registry: ToolsRegistry, path: str) -> None:
    """Save tools registry to a YAML or JSON file."""
    reg_path = Path(path)
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    data = registry.model_dump()

    suffix = reg_path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        if not _YAML_AVAILABLE:
            raise ImportError("PyYAML is required to save YAML configs.")
        with reg_path.open("w") as fh:
            yaml.dump(data, fh, default_flow_style=False, sort_keys=False)
    else:
        with reg_path.open("w") as fh:
            json.dump(data, fh, indent=2)

