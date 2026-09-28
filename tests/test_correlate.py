"""Tests for deduplication and cross-finding correlation."""

from __future__ import annotations

from orchestrator.correlate import correlate, dedup_and_correlate, deduplicate
from orchestrator.models import (
    CodeLocation,
    ContainerLocation,
    DepsLocation,
    Finding,
    NetworkLocation,
    ScanType,
    fingerprint,
)


def _dep(package: str, cve: list[str] | None = None, version: str = "1.0.0") -> Finding:
    f = Finding(
        source=ScanType.DEPS,
        tool="pip-audit",
        title=f"Vulnerability in {package}",
        description="desc",
        location=DepsLocation(
            manifest_path="requirements.txt", package_name=package, package_version=version
        ),
        cve=cve or [],
    )
    f.id = fingerprint(f)
    return f


def _net(product: str, host: str = "10.0.0.1", port: int = 443,
         cve: list[str] | None = None) -> Finding:
    f = Finding(
        source=ScanType.NETWORK,
        tool="nmap",
        title=f"{product} exposed",
        description="desc",
        location=NetworkLocation(host=host, port=port, product=product),
        cve=cve or [],
    )
    f.id = fingerprint(f)
    return f


def _container(package: str, cve: list[str] | None = None) -> Finding:
    f = Finding(
        source=ScanType.CONTAINER,
        tool="trivy",
        title=f"Vulnerability in {package}",
        description="desc",
        location=ContainerLocation(image_ref="app:latest", package_name=package),
        cve=cve or [],
    )
    f.id = fingerprint(f)
    return f


def _sast(file_path: str = "app.py", cve: list[str] | None = None) -> Finding:
    f = Finding(
        source=ScanType.SAST,
        tool="bandit",
        title="Hardcoded password",
        description="desc",
        location=CodeLocation(file_path=file_path, start_line=10),
        cve=cve or [],
    )
    f.id = fingerprint(f)
    return f


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_identical_findings_collapse_to_one():
    findings = [_dep("requests"), _dep("requests")]
    assert len(deduplicate(findings)) == 1


def test_first_occurrence_is_the_one_kept():
    first, second = _dep("requests"), _dep("requests")
    first.tool_version = "first"
    second.tool_version = "second"
    assert deduplicate([first, second])[0].tool_version == "first"


def test_distinct_findings_are_preserved():
    findings = [_dep("requests"), _dep("urllib3"), _sast()]
    assert len(deduplicate(findings)) == 3


def test_deduplicate_handles_an_empty_list():
    assert deduplicate([]) == []


# ---------------------------------------------------------------------------
# Correlation rule 1: dependency/container package ↔ network exposure
# ---------------------------------------------------------------------------

def test_dependency_links_to_network_exposure_of_the_same_product():
    dep, net = _dep("nginx"), _net("nginx")
    correlate([dep, net])
    assert net.id in dep.related_ids
    assert dep.id in net.related_ids, "links must be bidirectional"


def test_product_matching_ignores_case():
    dep, net = _dep("OpenSSL"), _net("openssl")
    correlate([dep, net])
    assert net.id in dep.related_ids


def test_container_package_links_to_network_exposure():
    container, net = _container("nginx"), _net("nginx")
    correlate([container, net])
    assert net.id in container.related_ids


def test_unrelated_products_are_not_linked():
    dep, net = _dep("requests"), _net("nginx")
    correlate([dep, net])
    assert dep.related_ids == []
    assert net.related_ids == []


def test_two_dependencies_are_not_linked_by_product_alone():
    """Rule 1 links a package to a *network exposure*, not to another package."""
    a, b = _dep("nginx"), _container("nginx")
    correlate([a, b])
    assert b.id not in a.related_ids


# ---------------------------------------------------------------------------
# Correlation rule 2: shared CVE
# ---------------------------------------------------------------------------

def test_findings_sharing_a_cve_are_linked():
    dep, sast = _dep("requests", cve=["CVE-2023-1111"]), _sast(cve=["CVE-2023-1111"])
    correlate([dep, sast])
    assert sast.id in dep.related_ids
    assert dep.id in sast.related_ids


def test_cve_matching_ignores_case():
    a = _dep("requests", cve=["cve-2023-1111"])
    b = _sast(cve=["CVE-2023-1111"])
    correlate([a, b])
    assert b.id in a.related_ids


def test_different_cves_are_not_linked():
    a = _dep("requests", cve=["CVE-2023-1111"])
    b = _sast(cve=["CVE-2023-2222"])
    correlate([a, b])
    assert a.related_ids == []


def test_a_finding_is_never_linked_to_itself():
    finding = _dep("requests", cve=["CVE-2023-1111"])
    correlate([finding])
    assert finding.id not in finding.related_ids


def test_three_findings_sharing_a_cve_all_link_to_each_other():
    a = _dep("requests", cve=["CVE-2023-1111"])
    b = _container("requests", cve=["CVE-2023-1111"])
    c = _sast(cve=["CVE-2023-1111"])
    correlate([a, b, c])
    for finding in (a, b, c):
        others = {x.id for x in (a, b, c)} - {finding.id}
        assert others.issubset(set(finding.related_ids))


# ---------------------------------------------------------------------------
# Shared behaviour
# ---------------------------------------------------------------------------

def test_related_ids_are_sorted_and_unique():
    a = _dep("nginx", cve=["CVE-2023-1111"])
    net = _net("nginx", cve=["CVE-2023-1111"])
    correlate([a, net])
    assert a.related_ids == sorted(set(a.related_ids))


def test_existing_related_ids_are_preserved():
    dep, net = _dep("nginx"), _net("nginx")
    dep.related_ids = ["preexisting-id"]
    correlate([dep, net])
    assert "preexisting-id" in dep.related_ids
    assert net.id in dep.related_ids


def test_pipeline_deduplicates_before_correlating():
    findings = [_dep("nginx"), _dep("nginx"), _net("nginx")]
    result = dedup_and_correlate(findings)
    assert len(result) == 2
    dep = next(f for f in result if f.source == ScanType.DEPS)
    assert len(dep.related_ids) == 1


# ---------------------------------------------------------------------------
# The two kinds of link are recorded separately
#
# Conflating them was a modelling error: a shared CVE means two tools saw the
# same issue, while a shared product means a vulnerable package is also exposed.
# Only the second is a new fact, so only it may raise risk.
# ---------------------------------------------------------------------------

def test_shared_product_is_recorded_as_a_risk_link():
    dep, net = _dep("nginx"), _net("nginx")
    correlate([dep, net])
    assert net.id in dep.risk_related_ids
    assert dep.id in net.risk_related_ids, "risk links must be bidirectional too"
    assert dep.corroborating_ids == []
    assert net.corroborating_ids == []


def test_shared_cve_is_recorded_as_corroboration_only():
    a = _dep("requests", cve=["CVE-2023-32681"])
    b = _container("requests-lib", cve=["CVE-2023-32681"])
    correlate([a, b])
    assert b.id in a.corroborating_ids
    assert a.id in b.corroborating_ids
    assert a.risk_related_ids == [], "a shared CVE is not a second fact"
    assert b.risk_related_ids == []


def test_related_ids_remains_the_union_of_both():
    """Whatever reads related_ids — the report, the model — keeps seeing every
    link; only their effect on the score differs."""
    dep = _dep("nginx", cve=["CVE-2023-1111"])
    net = _net("nginx", cve=["CVE-2023-1111"])
    correlate([dep, net])
    assert set(dep.related_ids) == set(dep.risk_related_ids) | set(dep.corroborating_ids)
    assert net.id in dep.related_ids


def test_a_link_can_be_both_kinds_at_once():
    """Same product and same CVE: it raises risk and settles doubt, and each
    list records it, so neither term double-counts the other."""
    dep = _dep("nginx", cve=["CVE-2023-1111"])
    net = _net("nginx", cve=["CVE-2023-1111"])
    correlate([dep, net])
    assert dep.risk_related_ids == [net.id]
    assert dep.corroborating_ids == [net.id]
    assert dep.related_ids == [net.id]
