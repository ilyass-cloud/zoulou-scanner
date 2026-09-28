"""Tests for nmap XML parsing and network normalization."""

from __future__ import annotations

import textwrap
import pytest

from orchestrator.plugins.network import (
    AuthorizedTargets,
    parse_nmap_xml,
    _filter_to_allowlist,
)
from orchestrator.models import RawScanArtifact, ScanType
from orchestrator.normalize import normalize_artifact


# ---------------------------------------------------------------------------
# Sample nmap XML
# ---------------------------------------------------------------------------

SAMPLE_NMAP_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <hostnames>
          <hostname name="router.internal" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.9"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="nginx" version="1.24.0"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="closed" reason="reset"/>
            <service name="https"/>
          </port>
        </ports>
      </host>
      <host>
        <address addr="10.0.0.2" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="3306">
            <state state="open" reason="syn-ack"/>
            <service name="mysql" product="MySQL" version="8.0.33"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")


@pytest.fixture
def nmap_xml_file(tmp_path):
    p = tmp_path / "nmap.xml"
    p.write_text(SAMPLE_NMAP_XML, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# parse_nmap_xml tests
# ---------------------------------------------------------------------------

def test_parse_returns_only_open_ports(nmap_xml_file):
    findings = parse_nmap_xml(nmap_xml_file)
    ports = [f["port"] for f in findings]
    # Port 443 is closed – must not appear
    assert 443 not in ports


def test_parse_correct_host_count(nmap_xml_file):
    findings = parse_nmap_xml(nmap_xml_file)
    hosts = {f["host"] for f in findings}
    assert hosts == {"10.0.0.1", "10.0.0.2"}


def test_parse_open_ports(nmap_xml_file):
    findings = parse_nmap_xml(nmap_xml_file)
    ports = {(f["host"], f["port"]) for f in findings}
    assert ("10.0.0.1", 22) in ports
    assert ("10.0.0.1", 80) in ports
    assert ("10.0.0.2", 3306) in ports


def test_parse_service_metadata(nmap_xml_file):
    findings = parse_nmap_xml(nmap_xml_file)
    ssh = next(f for f in findings if f["port"] == 22)
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["product_version"] == "8.9"


def test_parse_deterministic(nmap_xml_file):
    """Parsing the same file twice must produce identical results."""
    r1 = parse_nmap_xml(nmap_xml_file)
    r2 = parse_nmap_xml(nmap_xml_file)
    assert r1 == r2


def test_parse_total_open_ports(nmap_xml_file):
    findings = parse_nmap_xml(nmap_xml_file)
    assert len(findings) == 3  # 22, 80 on host1; 3306 on host2


# ---------------------------------------------------------------------------
# _filter_to_allowlist tests
# ---------------------------------------------------------------------------

def test_filter_keeps_allowlisted(nmap_xml_file):
    findings = parse_nmap_xml(nmap_xml_file)
    filtered = _filter_to_allowlist(findings, AuthorizedTargets.resolve(["10.0.0.1"]))
    hosts = {f["host"] for f in filtered}
    assert hosts == {"10.0.0.1"}


def test_filter_removes_non_allowlisted(nmap_xml_file):
    findings = parse_nmap_xml(nmap_xml_file)
    filtered = _filter_to_allowlist(findings, AuthorizedTargets.resolve(["10.0.0.1"]))
    assert all(f["host"] != "10.0.0.2" for f in filtered)


def test_filter_empty_allowlist_returns_empty(nmap_xml_file):
    findings = parse_nmap_xml(nmap_xml_file)
    filtered = _filter_to_allowlist(findings, AuthorizedTargets.resolve([]))
    assert filtered == []


def test_filter_matches_hosts_inside_a_cidr_entry(nmap_xml_file):
    """Regression: the filter compared strings, so '10.0.0.5' never equalled
    '10.0.0.0/24' and every result from a CIDR allowlist was silently dropped."""
    findings = parse_nmap_xml(nmap_xml_file)
    filtered = _filter_to_allowlist(findings, AuthorizedTargets.resolve(["10.0.0.0/24"]))
    assert {f["host"] for f in filtered} == {"10.0.0.1", "10.0.0.2"}


def test_filter_ignores_the_hostname_field(nmap_xml_file):
    """Regression: matching on `hostname` let an uploaded XML claim an
    allowlisted name and smuggle an unauthorized host into the report."""
    findings = parse_nmap_xml(nmap_xml_file)
    for f in findings:
        f["hostname"] = "router.internal"
    filtered = _filter_to_allowlist(findings, AuthorizedTargets.resolve(["10.0.0.1"]))
    assert {f["host"] for f in filtered} == {"10.0.0.1"}


# ---------------------------------------------------------------------------
# normalize_artifact integration test
# ---------------------------------------------------------------------------

def test_normalize_network_artifact_produces_findings(nmap_xml_file):
    import json
    findings_raw = parse_nmap_xml(nmap_xml_file)
    artifact = RawScanArtifact(
        plugin_name="network",
        scan_type=ScanType.NETWORK,
        tool="nmap",
        stdout=json.dumps(findings_raw),
        exit_code=0,
    )
    findings = normalize_artifact(artifact, default_exposure="internal")
    assert len(findings) == 3
    for f in findings:
        assert f.source == ScanType.NETWORK
        assert f.tool == "nmap"
        assert f.location is not None


def test_normalize_network_finding_ids_stable(nmap_xml_file):
    """Normalizing the same artifact twice must produce the same IDs."""
    import json
    findings_raw = parse_nmap_xml(nmap_xml_file)
    artifact = RawScanArtifact(
        plugin_name="network",
        scan_type=ScanType.NETWORK,
        tool="nmap",
        stdout=json.dumps(findings_raw),
        exit_code=0,
    )
    ids1 = {f.id for f in normalize_artifact(artifact)}
    ids2 = {f.id for f in normalize_artifact(artifact)}
    assert ids1 == ids2



# ---------------------------------------------------------------------------
# AuthorizedTargets – authorization is settled before any packet is sent
# ---------------------------------------------------------------------------

def _fake_resolver(mapping):
    """Stand-in for socket.getaddrinfo so DNS behaviour is deterministic."""
    def resolve(host, _port):
        if host not in mapping:
            raise OSError(f"Name or service not known: {host}")
        return [(None, None, None, "", (addr, 0)) for addr in mapping[host]]
    return resolve


def test_ip_entries_are_authorized_and_scanned_verbatim():
    auth = AuthorizedTargets.resolve(["10.0.0.1", "192.168.1.5"])
    assert auth.scan_targets == ["10.0.0.1", "192.168.1.5"]
    assert auth.contains("10.0.0.1")
    assert not auth.contains("10.0.0.2")


def test_cidr_entry_authorizes_every_address_in_the_network():
    auth = AuthorizedTargets.resolve(["10.0.0.0/24"])
    assert auth.contains("10.0.0.1")
    assert auth.contains("10.0.0.254")
    assert not auth.contains("10.0.1.1")


def test_hostname_is_scanned_as_its_resolved_address_not_by_name():
    """The core of the fix: the name is resolved once, and the scanner is handed
    the address, so the check and the scan cannot disagree."""
    auth = AuthorizedTargets.resolve(
        ["host.internal"], resolver=_fake_resolver({"host.internal": ["10.0.0.7"]})
    )
    assert auth.scan_targets == ["10.0.0.7"], "a hostname must never reach the scanner"
    assert auth.contains("10.0.0.7")


def test_hostname_with_several_addresses_authorizes_all_of_them():
    auth = AuthorizedTargets.resolve(
        ["host.internal"],
        resolver=_fake_resolver({"host.internal": ["10.0.0.7", "10.0.0.8"]}),
    )
    assert set(auth.scan_targets) == {"10.0.0.7", "10.0.0.8"}


def test_rebinding_after_resolution_cannot_change_what_was_authorized():
    """DNS may change later, but this run is pinned to the address it checked."""
    auth = AuthorizedTargets.resolve(
        ["host.internal"], resolver=_fake_resolver({"host.internal": ["10.0.0.7"]})
    )
    assert auth.scan_targets == ["10.0.0.7"]
    assert not auth.contains("10.0.0.99"), "a later DNS answer is not authorized"


def test_unresolvable_hostname_fails_closed():
    with pytest.raises(ValueError, match="could not be resolved"):
        AuthorizedTargets.resolve(["nope.invalid"], resolver=_fake_resolver({}))


def test_every_unresolvable_entry_is_reported():
    with pytest.raises(ValueError) as exc:
        AuthorizedTargets.resolve(["a.invalid", "b.invalid"], resolver=_fake_resolver({}))
    assert "a.invalid" in str(exc.value)
    assert "b.invalid" in str(exc.value)


def test_contains_rejects_a_non_address():
    auth = AuthorizedTargets.resolve(["10.0.0.1"])
    for value in ["", "not-an-ip", None, "router.internal"]:
        assert not auth.contains(value)


# ---------------------------------------------------------------------------
# Malformed XML – must not escape the plugin's error handling
# ---------------------------------------------------------------------------

def _write_xml(tmp_path, body):
    p = tmp_path / "nmap.xml"
    p.write_text(body, encoding="utf-8")
    return str(p)


@pytest.mark.parametrize("portid", ["NOT_A_NUMBER", "", "8o80", "99999", "-1"])
def test_malformed_portid_is_skipped_not_raised(tmp_path, portid):
    """Regression: int(portid) raised ValueError, and every caller catches only
    ET.ParseError, so an uploaded XML escaped the plugin's error handling."""
    path = _write_xml(tmp_path, f"""\
<nmaprun><host><address addrtype="ipv4" addr="10.0.0.1"/><ports>
<port protocol="tcp" portid="{portid}"><state state="open"/></port>
<port protocol="tcp" portid="22"><state state="open"/></port>
</ports></host></nmaprun>""")
    findings = parse_nmap_xml(path)
    assert [f["port"] for f in findings] == [22], "the good port must survive"


def test_missing_portid_attribute_is_skipped(tmp_path):
    path = _write_xml(tmp_path, """\
<nmaprun><host><address addrtype="ipv4" addr="10.0.0.1"/><ports>
<port protocol="tcp"><state state="open"/></port>
</ports></host></nmaprun>""")
    assert parse_nmap_xml(path) == []
