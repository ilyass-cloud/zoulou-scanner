"""Generic live plugin – runs any external scanner tool via subprocess.

Instantiated dynamically from a ToolDefinition in the tools registry.
The command template is expanded with runtime variables and executed.
Output is captured and returned as a RawScanArtifact for normalisation.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from orchestrator.config import ToolDefinition
from orchestrator.models import RawScanArtifact, ScanType
from orchestrator.plugins.base import BasePlugin, PluginContext

log = logging.getLogger(__name__)

_CATEGORY_TO_SCAN_TYPE = {
    "sast": ScanType.SAST,
    "deps": ScanType.DEPS,
    "secrets": ScanType.SECRETS,
    "container": ScanType.CONTAINER,
    "network": ScanType.NETWORK,
}


def build_argv(template: str, template_vars: Dict[str, Any]) -> Tuple[List[str], Optional[str]]:
    """Turn a command template into an argv list plus an optional redirect target.

    The template is split *before* the variables are substituted. That ordering
    is the point: it keeps each expanded value a single argv element, so a repo
    path containing spaces or shell metacharacters cannot alter the command.
    Substituting first and splitting afterwards is what made repo_path a command
    injection vector.

    A trailing ``> file`` is recognised and returned separately, because a few
    registry entries (trufflehog, grype) rely on the shell to redirect stdout
    and we no longer run a shell.

    Returns:
        (argv, redirect_path) where redirect_path is None when unused.

    Raises:
        KeyError: a placeholder has no matching variable.
        ValueError: the template is not parseable (unbalanced quotes).
    """
    tokens = shlex.split(template)
    argv: List[str] = []
    redirect: Optional[str] = None

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == ">":
            if index + 1 >= len(tokens):
                raise ValueError("redirection '>' has no target")
            redirect = tokens[index + 1].format(**template_vars)
            index += 2
            continue
        if token.startswith(">") and len(token) > 1:
            redirect = token[1:].format(**template_vars)
            index += 1
            continue
        argv.append(token.format(**template_vars))
        index += 1

    if not argv:
        raise ValueError("command template is empty")
    return argv, redirect


class LivePlugin(BasePlugin):
    """A plugin that runs an external tool defined by a ToolDefinition."""

    def __init__(self, tool_def: ToolDefinition) -> None:
        self.tool_def = tool_def
        self.name = tool_def.name
        self.scan_type = _CATEGORY_TO_SCAN_TYPE.get(
            tool_def.category.lower(), ScanType.SAST
        )

    # ------------------------------------------------------------------
    # Install check
    # ------------------------------------------------------------------

    def _binary_name(self) -> Optional[str]:
        """The executable this tool actually invokes, or None if undeterminable."""
        for template in (self.tool_def.command, self.tool_def.install_check):
            if not template or not template.strip():
                continue
            try:
                tokens = shlex.split(template)
            except ValueError:
                continue
            if tokens:
                return tokens[0]
        return None

    def is_installed(self) -> bool:
        """Whether the tool's executable can be found on PATH.

        This resolves the binary rather than trusting the install-check's exit
        status. The check command is a weak signal — a tool whose ``--version``
        happens to exit non-zero is still installed, and running it will surface
        a real error with a real exit code. What must never happen is a missing
        scanner being reported as a clean scan, which is exactly what the old
        implementation did: it ran the check under a shell and returned True
        unless an exception fired, but a missing binary exits 127 without
        raising, so it could never return False.
        """
        binary = self._binary_name()
        if binary is None:
            return False
        return shutil.which(binary) is not None

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self, context: PluginContext) -> RawScanArtifact:
        td = self.tool_def

        # Prepare output directory
        raw_dir = Path(context.output_dir) / "raw" / self.name
        raw_dir.mkdir(parents=True, exist_ok=True)

        # Determine output file path
        ext_map = {"sarif": ".sarif.json", "json": ".json", "xml": ".xml", "text": ".txt"}
        ext = ext_map.get(td.output_format, ".out")
        output_file = str(raw_dir / f"{self.name}_output{ext}")

        # Check if tool is installed
        if not self.is_installed():
            return self._make_artifact(
                stderr=(
                    f"{self.name}: tool not found. "
                    f"Install check command: {td.install_check}\n"
                    f"Description: {td.description}"
                ),
                exit_code=127,
            )

        # Expand command template
        template_vars = {
            "repo_path": context.repo_path,
            "output_file": output_file,
            "output_dir": context.output_dir,
        }
        # Add any extra vars from plugin_cfg
        template_vars.update(context.plugin_cfg)

        try:
            argv, redirect = build_argv(td.command, template_vars)
        except KeyError as exc:
            return self._make_artifact(
                stderr=f"{self.name}: command template variable not found: {exc}",
                exit_code=1,
            )
        except ValueError as exc:
            return self._make_artifact(
                stderr=f"{self.name}: could not parse command template: {exc}",
                exit_code=1,
            )

        cmd_str = shlex.join(argv) + (f" > {redirect}" if redirect else "")
        log.info("live_plugin[%s]: executing: %s", self.name, cmd_str)

        # Build environment
        env = os.environ.copy()
        env.update(td.env)

        # Execute
        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=td.timeout_seconds,
                env=env,
                cwd=context.repo_path,
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start
            log.warning("live_plugin[%s]: FAILED – timed out after %ss", self.name, td.timeout_seconds)
            return self._make_artifact(
                stderr=f"{self.name}: timed out after {td.timeout_seconds}s",
                exit_code=124,
                duration_seconds=duration,
            )
        except OSError as exc:
            log.warning("live_plugin[%s]: FAILED – could not execute: %s", self.name, exc)
            return self._make_artifact(
                stderr=f"{self.name}: failed to execute – {exc}",
                exit_code=1,
            )

        duration = time.monotonic() - start
        log.info(
            "live_plugin[%s]: finished in %.2fs (exit=%d)",
            self.name, duration, proc.returncode,
        )

        # Perform the '>' redirection the shell used to do for us.
        if redirect:
            try:
                Path(redirect).parent.mkdir(parents=True, exist_ok=True)
                Path(redirect).write_text(proc.stdout or "", encoding="utf-8")
            except OSError as exc:
                log.warning(
                    "live_plugin[%s]: could not write redirect target %s: %s",
                    self.name, redirect, exc,
                )

        # Read output file if it exists
        stdout = proc.stdout or ""
        output_path = Path(output_file)
        if output_path.exists():
            try:
                raw_content = output_path.read_text(encoding="utf-8")
                # For SARIF/JSON, validate and use as stdout
                if td.output_format in ("sarif", "json"):
                    data = json.loads(raw_content)
                    stdout = json.dumps(data, indent=2)
                elif td.output_format == "xml":
                    stdout = raw_content
                else:
                    stdout = raw_content
            except json.JSONDecodeError as exc:
                # An empty file (nothing found) and JSON Lines (TruffleHog) are
                # both valid outputs; the normalizer reads them. Only warn when
                # the content is neither.
                lines = [ln for ln in raw_content.splitlines() if ln.strip()]
                try:
                    for ln in lines:
                        json.loads(ln)
                    stdout = raw_content
                except json.JSONDecodeError:
                    log.warning("live_plugin[%s]: failed to read output file: %s", self.name, exc)
            except UnicodeDecodeError as exc:
                log.warning("live_plugin[%s]: failed to read output file: %s", self.name, exc)
                # Fall back to proc.stdout
        elif proc.stdout:
            # Tool wrote to stdout instead of file – try to parse
            try:
                if td.output_format in ("sarif", "json"):
                    data = json.loads(proc.stdout)
                    stdout = json.dumps(data, indent=2)
                    # Also save to file for traceability
                    output_path.write_text(stdout, encoding="utf-8")
            except (json.JSONDecodeError, UnicodeDecodeError):
                stdout = proc.stdout

        return self._make_artifact(
            raw_file_path=str(output_file) if output_path.exists() else None,
            stdout=stdout,
            stderr=proc.stderr or "",
            exit_code=proc.returncode,
            duration_seconds=duration,
            tool_version=self._get_version(),
            extra={"command": cmd_str, "output_format": td.output_format},
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_version(self) -> Optional[str]:
        """Try to get tool version string."""
        if not self.tool_def.install_check:
            return None
        try:
            proc = subprocess.run(
                shlex.split(self.tool_def.install_check),
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Return first line of output as version
            out = (proc.stdout or "").strip()
            return out.splitlines()[0] if out else None
        except Exception:
            return None

