"""Auto-scan planner – uses environment detection + LLM to suggest tools.

Flow:
  1. Run env_detect on the repo to get an EnvProfile
  2. Filter the tools registry to only installed & enabled tools
  3. (Optional) Ask the LLM which tools are relevant given the profile
  4. Return a list of ToolDefinition objects to execute

If LLM is unavailable, falls back to a deterministic rule-based matcher.
"""

from __future__ import annotations

import json
import logging
from typing import List, Optional

from orchestrator.config import ToolDefinition, ToolsRegistry
from orchestrator.env_detect import EnvProfile, detect_environment
from orchestrator.llm_client import LMStudioClient

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Deterministic fallback rules
# ---------------------------------------------------------------------------

# Maps detected attributes → tool categories that should be enabled
_RULES = {
    # If any language is detected, run SAST
    "any_language": ["sast"],
    # Specific package manager → deps scanner
    "pip": ["deps"],
    "pip/poetry": ["deps"],
    "pipenv": ["deps"],
    "npm": ["deps"],
    "yarn": ["deps"],
    "pnpm": ["deps"],
    "cargo": ["deps"],
    "go modules": ["deps"],
    "bundler": ["deps"],
    "composer": ["deps"],
    "maven": ["deps"],
    "gradle": ["deps"],
    "nuget": ["deps"],
    # Docker → container scanning
    "docker": ["container"],
    # Always run secrets detection if there's code
    "any_code": ["secrets"],
}

# Tool name preferences per language/ecosystem
_TOOL_PREFERENCES = {
    "Python": {"sast": ["semgrep", "bandit"], "deps": ["pip-audit", "safety"]},
    "JavaScript": {"sast": ["semgrep"], "deps": ["npm-audit"]},
    "TypeScript": {"sast": ["semgrep"], "deps": ["npm-audit"]},
    "Go": {"sast": ["semgrep"], "deps": []},
    "Java": {"sast": ["semgrep"], "deps": []},
    "Ruby": {"sast": ["semgrep"], "deps": []},
    "Rust": {"sast": ["semgrep"], "deps": []},
}


def _deterministic_select(
    profile: EnvProfile,
    available_tools: List[ToolDefinition],
) -> List[ToolDefinition]:
    """Rule-based tool selection without LLM."""
    needed_categories: set = set()
    preferred_tools: set = set()

    # Any language → SAST + secrets
    if profile.languages:
        needed_categories.add("sast")
        needed_categories.add("secrets")

    # Package managers → deps
    if profile.package_managers:
        needed_categories.add("deps")

    # Docker → container
    if profile.has_dockerfile or profile.has_docker_compose:
        needed_categories.add("container")

    # Collect preferred tool names per language
    for lang in profile.languages:
        prefs = _TOOL_PREFERENCES.get(lang, {})
        for cat, tool_names in prefs.items():
            for tn in tool_names:
                preferred_tools.add(tn)

    # Build tool map by category
    by_category: dict[str, list[ToolDefinition]] = {}
    for t in available_tools:
        by_category.setdefault(t.category, []).append(t)

    selected: List[ToolDefinition] = []
    selected_names: set = set()

    # First pass: pick preferred tools
    for t in available_tools:
        if t.name in preferred_tools and t.category in needed_categories:
            if t.name not in selected_names:
                selected.append(t)
                selected_names.add(t.name)

    # Second pass: fill categories that have no tool yet
    for cat in needed_categories:
        if not any(t.category == cat for t in selected):
            candidates = by_category.get(cat, [])
            if candidates:
                selected.append(candidates[0])
                selected_names.add(candidates[0].name)

    return selected


# ---------------------------------------------------------------------------
# LLM-aided selection
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are a security engineering assistant. "
    "Given a repository environment profile and a list of available scanning tools, "
    "select which tools should be run. "
    "Respond ONLY with a JSON object: {\"selected_tools\": [\"tool_name_1\", ...], \"reasoning\": \"...\"} "
    "Do NOT invent tool names – only use names from the provided list."
)


def _build_llm_prompt(profile: EnvProfile, tools: List[ToolDefinition]) -> str:
    profile_data = profile.model_dump()
    tools_data = [
        {
            "name": t.name,
            "label": t.label,
            "category": t.category,
            "description": t.description,
        }
        for t in tools
    ]
    return (
        "## Repository Environment Profile\n"
        f"```json\n{json.dumps(profile_data, indent=2)}\n```\n\n"
        "## Available Scanning Tools\n"
        f"```json\n{json.dumps(tools_data, indent=2)}\n```\n\n"
        "Based on the detected environment, which tools from the available list "
        "should be run? Consider:\n"
        "- Languages detected → appropriate SAST tools\n"
        "- Package managers → appropriate dependency scanners\n"
        "- Docker/container presence → container scanners\n"
        "- Always include secret detection if there is source code\n"
        "- Do NOT select tools for ecosystems not present in the repo\n\n"
        "Respond with JSON: {\"selected_tools\": [...], \"reasoning\": \"...\"}"
    )


def _llm_select(
    client: LMStudioClient,
    profile: EnvProfile,
    available_tools: List[ToolDefinition],
) -> List[ToolDefinition]:
    """Ask the LLM to select tools."""
    prompt = _build_llm_prompt(profile, available_tools)

    try:
        raw = client.generate(prompt, system_prompt=_SYSTEM_PROMPT)
    except RuntimeError as exc:
        log.warning("auto_planner: LLM unavailable (%s), falling back to rules", exc)
        return _deterministic_select(profile, available_tools)

    # Parse response
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    try:
        data = json.loads(text)
        selected_names = set(data.get("selected_tools", []))
        reasoning = data.get("reasoning", "")
        log.info("auto_planner: LLM reasoning: %s", reasoning)
    except (json.JSONDecodeError, TypeError):
        log.warning("auto_planner: could not parse LLM response, falling back to rules")
        return _deterministic_select(profile, available_tools)

    # Map names back to ToolDefinition objects
    tool_map = {t.name: t for t in available_tools}
    selected = []
    for name in selected_names:
        if name in tool_map:
            selected.append(tool_map[name])
        else:
            log.warning("auto_planner: LLM suggested unknown tool '%s' – ignoring", name)

    if not selected:
        log.warning("auto_planner: LLM selected no valid tools, falling back to rules")
        return _deterministic_select(profile, available_tools)

    return selected


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def auto_plan(
    repo_path: str,
    registry: ToolsRegistry,
    llm_client: Optional[LMStudioClient] = None,
    use_llm: bool = True,
) -> tuple[EnvProfile, List[ToolDefinition]]:
    """Detect environment and select appropriate tools.

    Returns:
        (env_profile, selected_tools)
    """
    log.info("auto_planner: detecting environment for %s", repo_path)
    profile = detect_environment(repo_path)

    # Filter to enabled + installed tools
    available: List[ToolDefinition] = []
    for t in registry.tools:
        if not t.enabled:
            log.debug("auto_planner: %s disabled in registry, skipping", t.name)
            continue
        # We don't check is_installed here – that happens at execution time
        # so the LLM/rules can still suggest tools that might need installing
        available.append(t)

    if not available:
        log.warning("auto_planner: no enabled tools in registry")
        return profile, []

    # Select tools
    if use_llm and llm_client:
        selected = _llm_select(llm_client, profile, available)
    else:
        selected = _deterministic_select(profile, available)

    log.info(
        "auto_planner: selected %d tools: %s",
        len(selected),
        [t.name for t in selected],
    )
    return profile, selected

