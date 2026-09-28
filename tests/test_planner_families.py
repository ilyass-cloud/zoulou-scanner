"""Families ticked in the web form restrict the automatic tool selection.

Regression: the family switches were never passed to the brain, so ticking
them without Auto-Scan planned zero tools and the scan ended with an empty
report. The server now turns ticked families into an automatic selection
restricted to them (``plan --families``); these tests pin the brain side.
"""
from orchestrator.config import OrchestratorConfig, load_tools_registry
from orchestrator.planner import select_tool_defs


def _cfg():
    cfg = OrchestratorConfig()
    cfg.llm.enabled = False
    return cfg


def _registry():
    return load_tools_registry("tools_registry.yaml")


def test_families_restrict_the_automatic_selection(tmp_path):
    (tmp_path / "app.py").write_text("import subprocess\n")
    (tmp_path / "requirements.txt").write_text("requests==2.0\n")
    tools = select_tool_defs(str(tmp_path), _cfg(), auto_scan=True,
                             tools_registry=_registry(), families=["sast"])
    assert tools, "a Python project must get at least one SAST tool"
    assert {t.category for t in tools} == {"sast"}


def test_no_family_filter_keeps_the_whole_automatic_selection(tmp_path):
    (tmp_path / "app.py").write_text("import subprocess\n")
    (tmp_path / "requirements.txt").write_text("requests==2.0\n")
    unfiltered = select_tool_defs(str(tmp_path), _cfg(), auto_scan=True, tools_registry=_registry())
    assert {"sast", "deps"} <= {t.category for t in unfiltered}


def test_explicit_tools_are_not_filtered_by_families(tmp_path):
    tools = select_tool_defs(str(tmp_path), _cfg(), tools_registry=_registry(),
                             selected_tools=["gitleaks"], families=["sast"])
    assert [t.name for t in tools] == ["gitleaks"]
