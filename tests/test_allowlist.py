"""Tests for the network allowlist parser."""

from __future__ import annotations

import textwrap
import pytest

from orchestrator.plugins.network import parse_allowlist


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write_allowlist(tmp_path, content: str) -> str:
    p = tmp_path / "allowlist.txt"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------

def test_parse_simple_ips(tmp_path):
    path = _write_allowlist(tmp_path, """\
        # Internal test hosts
        192.168.1.10
        192.168.1.11
        10.0.0.5
    """)
    targets = parse_allowlist(path, allow_cidr=False)
    assert targets == ["192.168.1.10", "192.168.1.11", "10.0.0.5"]


def test_parse_hostnames(tmp_path):
    path = _write_allowlist(tmp_path, """\
        dev.internal.example.com
        staging.example.com
    """)
    targets = parse_allowlist(path, allow_cidr=False)
    assert "dev.internal.example.com" in targets
    assert "staging.example.com" in targets


def test_comments_and_blank_lines_ignored(tmp_path):
    path = _write_allowlist(tmp_path, """\
        # This is a comment
        
        10.0.0.1
        
        # Another comment
        10.0.0.2
    """)
    targets = parse_allowlist(path, allow_cidr=False)
    assert targets == ["10.0.0.1", "10.0.0.2"]


def test_cidr_allowed_when_flag_set(tmp_path):
    path = _write_allowlist(tmp_path, """\
        10.0.0.0/24
    """)
    targets = parse_allowlist(path, allow_cidr=True)
    assert "10.0.0.0/24" in targets


# ---------------------------------------------------------------------------
# Rejection tests
# ---------------------------------------------------------------------------

def test_cidr_rejected_by_default(tmp_path):
    path = _write_allowlist(tmp_path, """\
        10.0.0.0/24
    """)
    with pytest.raises(ValueError, match="CIDR range"):
        parse_allowlist(path, allow_cidr=False)


def test_invalid_cidr_rejected_even_when_allowed(tmp_path):
    path = _write_allowlist(tmp_path, """\
        999.999.999.0/24
    """)
    with pytest.raises(ValueError):
        parse_allowlist(path, allow_cidr=True)


def test_empty_allowlist_raises(tmp_path):
    path = _write_allowlist(tmp_path, """\
        # Only comments here
        
    """)
    with pytest.raises(ValueError, match="no valid targets"):
        parse_allowlist(path, allow_cidr=False)


def test_missing_file_raises():
    with pytest.raises((FileNotFoundError, OSError)):
        parse_allowlist("/nonexistent/path/allowlist.txt")


# ---------------------------------------------------------------------------
# Argument-injection regression
#
# Entries become argv elements of the scanner invocation, so an entry that is
# not a target is an argument-injection vector. The parser used to validate
# with a single regex that rejected only slashes, which let every flag below
# through as a "target".
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flag", [
    "--script=vuln",          # turns passive inventory into exploitation
    "--script=http-enum",
    "-T5",                    # defeats the throttling the plugin promises
    "--min-rate=100000",
    "-Pn",
    "-sS",
    "--privileged",
    "-",
])
def test_flags_are_rejected_as_targets(tmp_path, flag):
    path = _write_allowlist(tmp_path, f"10.0.0.1\n{flag}\n")
    with pytest.raises(ValueError, match="command-line flag"):
        parse_allowlist(path, allow_cidr=False)


def test_flag_is_rejected_even_when_cidr_is_allowed(tmp_path):
    path = _write_allowlist(tmp_path, "10.0.0.0/24\n--script=vuln\n")
    with pytest.raises(ValueError, match="command-line flag"):
        parse_allowlist(path, allow_cidr=True)


def test_one_bad_entry_rejects_the_whole_file(tmp_path):
    """Fail closed: a partially-valid allowlist must not scan its good half."""
    path = _write_allowlist(tmp_path, "10.0.0.1\n--script=vuln\n10.0.0.2\n")
    with pytest.raises(ValueError):
        parse_allowlist(path, allow_cidr=False)


def test_every_bad_entry_is_reported(tmp_path):
    path = _write_allowlist(tmp_path, "-T5\n--script=vuln\n")
    with pytest.raises(ValueError) as exc:
        parse_allowlist(path, allow_cidr=False)
    assert "-T5" in str(exc.value)
    assert "--script=vuln" in str(exc.value)


# ---------------------------------------------------------------------------
# Target-shape validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("entry", [
    "192.168.1.10",
    "10.0.0.5",
    "::1",
    "2001:db8::1",
    "webserver.internal",
    "dev.internal.example.com",
    "host-01.example.com",
    "localhost",
])
def test_valid_targets_are_accepted(tmp_path, entry):
    path = _write_allowlist(tmp_path, f"{entry}\n")
    assert parse_allowlist(path, allow_cidr=False) == [entry]


@pytest.mark.parametrize("entry", [
    "not a hostname",          # embedded spaces
    "host;rm -rf /",           # shell metacharacters
    "host$(id)",
    "-leading-dash.com",
    "..",
    "host..double.dot",
    "a" * 300,                 # over the 253-char DNS limit
])
def test_malformed_targets_are_rejected(tmp_path, entry):
    path = _write_allowlist(tmp_path, f"{entry}\n")
    with pytest.raises(ValueError):
        parse_allowlist(path, allow_cidr=False)


def test_backslash_is_rejected(tmp_path):
    path = _write_allowlist(tmp_path, "host\\name\n")
    with pytest.raises(ValueError, match="backslash"):
        parse_allowlist(path, allow_cidr=False)


@pytest.mark.parametrize("entry", ["192.168.1.1-20", "10.0.0.1-254", "999.999.999.999"])
def test_numeric_ranges_are_rejected_in_favour_of_cidr(tmp_path, entry):
    """Authorization is resolved to concrete addresses before scanning, so a
    range this code cannot expand is a range it cannot verify."""
    path = _write_allowlist(tmp_path, f"{entry}\n")
    with pytest.raises(ValueError, match="CIDR"):
        parse_allowlist(path, allow_cidr=False)

