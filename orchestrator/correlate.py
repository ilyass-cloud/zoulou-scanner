"""Deduplication and correlation of normalized findings."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from orchestrator.models import Finding, NetworkLocation, DepsLocation, ContainerLocation, ScanType

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate(findings: List[Finding]) -> List[Finding]:
    """Remove exact duplicates by fingerprint (id), keeping first occurrence."""
    seen: Set[str] = set()
    unique: List[Finding] = []
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            unique.append(f)
        else:
            log.debug("correlate: dedup – dropping duplicate %s (%s)", f.id, f.title)
    log.info("correlate: dedup %d → %d findings", len(findings), len(unique))
    return unique


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def _product_names(finding: Finding) -> Set[str]:
    """Extract normalised product/package names from a finding's location."""
    names: Set[str] = set()
    loc = finding.location
    if isinstance(loc, NetworkLocation) and loc.product:
        names.add(loc.product.lower().strip())
    elif isinstance(loc, DepsLocation):
        names.add(loc.package_name.lower().strip())
    elif isinstance(loc, ContainerLocation) and loc.package_name:
        names.add(loc.package_name.lower().strip())
    return names


def correlate(findings: List[Finding]) -> List[Finding]:
    """Link related findings, distinguishing the two kinds of link.

    Strategy (simple and explainable):
    1. Build an index: product/package name → list of finding ids.
    2. Rule 1 — a dependency or container finding whose package is also seen
       exposed by the network scan under the same product name. The two halves
       are distinct facts, and their coexistence is worse than either alone, so
       this link raises **risk**.
    3. Rule 2 — two findings citing the same CVE. This is the same issue seen
       twice, by two tools whose coverage overlaps. It is not a second fact,
       so it must not raise risk; what a second opinion establishes is that the
       first was not a false positive, so this link raises **confidence**.

    All links land in ``related_ids`` for display, and additionally in
    ``risk_related_ids`` or ``corroborating_ids`` so scoring can tell them
    apart without having to know how they were derived.
    """
    # Index: product name → finding ids
    product_index: Dict[str, List[str]] = defaultdict(list)
    # Index: CVE → finding ids
    cve_index: Dict[str, List[str]] = defaultdict(list)

    for f in findings:
        for name in _product_names(f):
            product_index[name].append(f.id)
        for cve in f.cve:
            cve_index[cve.upper()].append(f.id)

    # Separate network exposure findings
    network_ids: Set[str] = {
        f.id for f in findings if f.source == ScanType.NETWORK
    }

    # Links that raise risk, and links that raise confidence, kept apart.
    risk_links: Dict[str, Set[str]] = defaultdict(set)
    corroborations: Dict[str, Set[str]] = defaultdict(set)

    # Rule 1 — dep/container package ↔ network exposure sharing a product name.
    for f in findings:
        if f.source not in (ScanType.DEPS, ScanType.CONTAINER):
            continue
        for name in _product_names(f):
            for net_id in product_index.get(name, []):
                if net_id in network_ids and net_id != f.id:
                    risk_links[f.id].add(net_id)
                    risk_links[net_id].add(f.id)
                    log.debug(
                        "correlate: %s ↔ %s share product '%s' (raises risk)",
                        f.id, net_id, name,
                    )

    # Rule 2 — the same CVE reported by more than one tool.
    for cve, ids in cve_index.items():
        if len(ids) > 1:
            for fid in ids:
                for other in ids:
                    if other != fid:
                        corroborations[fid].add(other)
                        log.debug(
                            "correlate: %s ↔ %s share %s (raises confidence)",
                            fid, other, cve,
                        )

    # Apply back to the findings (mutate in place). `related_ids` is the union,
    # so anything that reads it keeps seeing every link.
    id_to_finding: Dict[str, Finding] = {f.id: f for f in findings}
    for fid in set(risk_links) | set(corroborations):
        f = id_to_finding.get(fid)
        if f is None:
            continue
        risk = risk_links.get(fid, set())
        corr = corroborations.get(fid, set())
        f.risk_related_ids = sorted(set(f.risk_related_ids) | risk)
        f.corroborating_ids = sorted(set(f.corroborating_ids) | corr)
        f.related_ids = sorted(set(f.related_ids) | risk | corr)

    n_risk = sum(len(v) for v in risk_links.values())
    n_corr = sum(len(v) for v in corroborations.values())
    log.info(
        "correlate: %d directional links across %d findings (%d raise risk, %d raise confidence)",
        n_risk + n_corr, len(findings), n_risk, n_corr,
    )
    return findings


# ---------------------------------------------------------------------------
# Combined pipeline
# ---------------------------------------------------------------------------

def dedup_and_correlate(findings: List[Finding]) -> List[Finding]:
    """Deduplicate then correlate findings."""
    unique = deduplicate(findings)
    correlated = correlate(unique)
    return correlated

