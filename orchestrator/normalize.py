"""Normalizers: convert raw plugin output (JSON/SARIF/XML) into Finding objects."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from orchestrator.models import (
    CodeLocation,
    Confidence,
    ContainerLocation,
    DepsLocation,
    Exposure,
    Finding,
    NetworkLocation,
    RawScanArtifact,
    ScanType,
    Severity,
    fingerprint,
)

log = logging.getLogger(__name__)

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Severity / confidence helpers
# ---------------------------------------------------------------------------

_SEV_MAP: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
}

_CONF_MAP: Dict[str, Confidence] = {
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "low": Confidence.LOW,
}


# ---------------------------------------------------------------------------
# Shape coercion
#
# Scanner output is untrusted input: it comes from third-party tools run against
# an arbitrary repository, and in parse-only mode it can be uploaded directly.
# Every accessor below therefore tolerates the wrong type rather than assuming
# the documented schema. A tool that emits `"level": 3` where a string was
# expected should cost one finding, not the whole scan.
# ---------------------------------------------------------------------------

def _as_dict(value: Any) -> Dict[str, Any]:
    """Return value if it is a dict, else an empty dict."""
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    """Return value if it is a list, else an empty list.

    Strings are deliberately not treated as iterable here: iterating one yields
    characters, which produced confusing downstream failures.
    """
    return value if isinstance(value, list) else []


def _as_str(value: Any, default: str = "") -> str:
    """Coerce a scalar to str; containers and None collapse to the default."""
    if value is None or isinstance(value, (dict, list)):
        return default
    return value if isinstance(value, str) else str(value)


def _str_list(value: Any) -> List[str]:
    """Coerce a scalar-or-list field into a list of strings."""
    if value is None:
        return []
    if isinstance(value, (str, int, float)):
        return [str(value)]
    if isinstance(value, list):
        return [_as_str(v) for v in value if not isinstance(v, (dict, list)) and v is not None]
    return []


def _sev(raw: Any) -> Severity:
    return _SEV_MAP.get(_as_str(raw).lower().strip(), Severity.UNKNOWN)


def _conf(raw: Any) -> Confidence:
    return _CONF_MAP.get(_as_str(raw).lower().strip(), Confidence.UNKNOWN)


def _first(item: Dict[str, Any], *keys: str) -> Any:
    """Return the first key present with a non-empty value, else ``None``.

    Tools spell the same field differently (``file`` / ``file_path`` / ``path``).
    """
    for key in keys:
        value = item.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


# ---------------------------------------------------------------------------
# SARIF 2.1 normalizer
# ---------------------------------------------------------------------------

def _normalize_sarif(data: Dict[str, Any], tool_name: str) -> List[Finding]:
    findings: List[Finding] = []
    for run in _as_list(data.get("runs")):
        run = _as_dict(run)
        tool_info = _as_dict(_as_dict(run.get("tool")).get("driver"))
        tool = _as_str(tool_info.get("name")) or tool_name
        version = _as_str(tool_info.get("version")) or None

        # Build rule lookup for descriptions. A rule without a usable id is
        # skipped rather than raising KeyError and losing the whole run.
        rules: Dict[str, Dict] = {}
        for entry in _as_list(tool_info.get("rules")):
            entry = _as_dict(entry)
            rule_key = _as_str(entry.get("id"))
            if rule_key:
                rules[rule_key] = entry

        for result in _as_list(run.get("results")):
            result = _as_dict(result)
            rule_id = _as_str(result.get("ruleId"))
            rule = _as_dict(rules.get(rule_id))
            title = (
                _as_str(_as_dict(rule.get("shortDescription")).get("text"))
                or _as_str(rule.get("name"))
                or rule_id
                or "Unknown SAST finding"
            )
            # Semgrep's shortDescription is a placeholder ("Semgrep Finding:
            # <rule id>"); the rule id's last segment names the problem.
            if title.startswith("Semgrep Finding") and rule_id:
                title = rule_id.rsplit(".", 1)[-1]
            description = (
                _as_str(_as_dict(result.get("message")).get("text"))
                or _as_str(_as_dict(rule.get("fullDescription")).get("text"))
                or title
            )
            sev_raw = _as_str(result.get("level"), "warning")
            sev_map = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
            severity = _sev(sev_map.get(sev_raw, sev_raw))

            # Location. SARIF allows an absent, empty, or malformed locations
            # array; none of those should cost more than the location itself.
            locs = _as_list(result.get("locations"))
            phys = _as_dict(_as_dict(locs[0]).get("physicalLocation")) if locs else {}
            art = _as_dict(phys.get("artifactLocation"))
            region = _as_dict(phys.get("region"))
            file_path = _as_str(art.get("uri")) or "unknown"
            start_line = region.get("startLine")
            if not isinstance(start_line, int):
                start_line = None

            # SARIF carries the offending source in region.snippet.text, with
            # contextRegion as the wider fallback. This was being discarded,
            # which left every SARIF finding without evidence — and the LLM
            # grounding rule keys off exactly that field, so the flagship SAST
            # tool's findings were all unassessable.
            evidence = _as_str(_as_dict(region.get("snippet")).get("text")).strip()
            if not evidence:
                context_region = _as_dict(phys.get("contextRegion"))
                evidence = _as_str(_as_dict(context_region.get("snippet")).get("text")).strip()

            cwe_list: List[str] = []
            # Tags read "CWE-89: Improper Neutralization of …"; keep the
            # identifier, which is what grouping and the report key on.
            for tag in _str_list(_as_dict(rule.get("properties")).get("tags")):
                m = _CWE_RE.match(tag.strip())
                if m and f"CWE-{m.group(1)}" not in cwe_list:
                    cwe_list.append(f"CWE-{m.group(1)}")

            loc = CodeLocation(file_path=file_path, start_line=start_line)
            f = Finding(
                source=ScanType.SAST,
                tool=tool,
                tool_version=version,
                title=title,
                description=description,
                location=loc,
                cwe=cwe_list,
                severity_raw=severity,
                confidence_raw=Confidence.MEDIUM,
                evidence=evidence or None,
            )
            findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# Bandit JSON normalizer (Bandit has no SARIF output in this version)
# ---------------------------------------------------------------------------

def _normalize_bandit(data: Dict[str, Any], tool_name: str) -> List[Finding]:
    """Normalize Bandit's native JSON output (``bandit -f json``).

    Bandit emits ``{"results": [...], "metrics": {...}, "errors": [...]}``.
    Each result carries the offending code snippet, which is kept as evidence.
    """
    findings: List[Finding] = []
    for item in _as_list(data.get("results")):
        if not isinstance(item, dict):
            log.debug("normalize: skipping non-object entry in %s output", tool_name)
            continue
        test_id = _as_str(item.get("test_id"))
        test_name = _as_str(item.get("test_name")) or test_id or "Bandit finding"
        cwe_id = _as_dict(item.get("issue_cwe")).get("id")
        cwe_list = [f"CWE-{_as_str(cwe_id)}"] if cwe_id else []

        line_number = item.get("line_number")
        loc = CodeLocation(
            file_path=_as_str(item.get("filename")) or "unknown",
            start_line=line_number if isinstance(line_number, int) else None,
        )
        title = f"{test_id} – {test_name}" if test_id else test_name
        f = Finding(
            source=ScanType.SAST,
            tool=tool_name,
            title=title,
            description=_as_str(item.get("issue_text")) or title,
            location=loc,
            cwe=cwe_list,
            severity_raw=_sev(item.get("issue_severity")),
            confidence_raw=_conf(item.get("issue_confidence")),
            evidence=_as_str(item.get("code")).strip() or None,
            references=_str_list(item.get("more_info")),
        )
        findings.append(f)
    return findings


def _normalize_generic_sast(data: List[Dict], tool_name: str) -> List[Finding]:
    """Normalize a plain JSON array emitted by a SAST tool.

    Covers tools that expose neither SARIF nor Bandit's envelope. Key names vary
    between tools, so the common spellings of each field are accepted.
    """
    findings: List[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            log.debug("normalize: skipping non-object entry in %s output", tool_name)
            continue
        file_path = _first(item, "file", "file_path", "path", "filename") or "unknown"
        line = _first(item, "line", "line_number", "start_line")
        rule = _first(item, "rule_id", "check_id", "rule", "test_id")
        title = _first(item, "title", "message", "description") or rule or "SAST finding"
        if rule and not str(title).startswith(str(rule)):
            title = f"{rule} – {title}"

        cwe_list = _str_list(_first(item, "cwe", "cwe_id"))
        cve_list = _str_list(_first(item, "cve", "cve_id"))

        f = Finding(
            source=ScanType.SAST,
            tool=tool_name,
            title=_as_str(title) or "SAST finding",
            description=_as_str(_first(item, "description", "message", "issue_text")) or _as_str(title),
            location=CodeLocation(
                file_path=_as_str(file_path) or "unknown",
                start_line=line if isinstance(line, int) else None,
            ),
            cwe=cwe_list,
            cve=cve_list,
            severity_raw=_sev(item.get("severity")),
            confidence_raw=_conf(item.get("confidence")),
            evidence=_as_str(_first(item, "evidence", "code", "snippet")) or None,
            references=_str_list(item.get("references")),
        )
        findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# Simple JSON array normalizers
# ---------------------------------------------------------------------------

def _normalize_deps(data: List[Dict], tool_name: str) -> List[Finding]:
    findings: List[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            log.debug("normalize: skipping non-object entry in %s output", tool_name)
            continue
        pkg = _as_str(item.get("package")) or "unknown"
        ver = _as_str(item.get("version"))
        cve = _as_str(item.get("cve"))
        manifest = _as_str(item.get("manifest")) or "requirements.txt"
        title = f"{pkg}@{ver} – {cve}" if cve else f"Vulnerable dependency: {pkg}@{ver}"
        loc = DepsLocation(
            manifest_path=manifest,
            package_name=pkg,
            package_version=ver,
            ecosystem=_as_str(item.get("ecosystem")) or None,
        )
        f = Finding(
            source=ScanType.DEPS,
            tool=tool_name,
            title=title,
            description=_as_str(item.get("description")) or title,
            location=loc,
            cve=[cve] if cve else [],
            severity_raw=_sev(item.get("severity")),
            confidence_raw=_conf(_first(item, "confidence") or "high"),
            evidence=_as_str(item.get("evidence")) or None,
            references=_str_list(item.get("references")),
        )
        findings.append(f)
    return findings


def _normalize_secrets(data: List[Dict], tool_name: str) -> List[Finding]:
    findings: List[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            log.debug("normalize: skipping non-object entry in %s output", tool_name)
            continue
        file_path = _as_str(item.get("file")) or "unknown"
        line = item.get("line")
        rule = _as_str(_first(item, "rule_id", "type")) or "secret"
        title = _as_str(item.get("description")) or f"Secret detected: {rule}"
        loc = CodeLocation(
            file_path=file_path,
            start_line=line if isinstance(line, int) else None,
        )
        f = Finding(
            source=ScanType.SECRETS,
            tool=tool_name,
            title=title,
            description=title,
            location=loc,
            severity_raw=_sev(_first(item, "severity") or "high"),
            confidence_raw=_conf(_first(item, "confidence") or "high"),
            evidence=_as_str(item.get("evidence")) or None,
        )
        findings.append(f)
    return findings


def _normalize_container(data: List[Dict], tool_name: str) -> List[Finding]:
    findings: List[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            log.debug("normalize: skipping non-object entry in %s output", tool_name)
            continue
        image = _as_str(item.get("image")) or "unknown"
        pkg = _as_str(item.get("package")) or "unknown"
        ver = _as_str(item.get("version"))
        cve = _as_str(item.get("cve"))
        title = f"{pkg}@{ver} in {image} – {cve}" if cve else f"Vulnerable package: {pkg}@{ver}"
        loc = ContainerLocation(
            image_ref=image,
            layer_digest=_as_str(item.get("layer")) or None,
            package_name=pkg,
            package_version=ver,
        )
        f = Finding(
            source=ScanType.CONTAINER,
            tool=tool_name,
            title=title,
            description=_as_str(item.get("description")) or title,
            location=loc,
            cve=[cve] if cve else [],
            severity_raw=_sev(item.get("severity")),
            confidence_raw=_conf(_first(item, "confidence") or "high"),
            evidence=_as_str(item.get("evidence")) or None,
            references=_str_list(item.get("references")),
        )
        findings.append(f)
    return findings


def _normalize_network(data: List[Dict], tool_name: str, default_exposure: str = "unknown") -> List[Finding]:
    findings: List[Finding] = []
    exp_map = {"internal": Exposure.INTERNAL, "external": Exposure.EXTERNAL}
    exposure = exp_map.get(default_exposure.lower(), Exposure.UNKNOWN)

    for item in data:
        if not isinstance(item, dict):
            log.debug("normalize: skipping non-object entry in %s output", tool_name)
            continue
        host = _as_str(item.get("host")) or "unknown"
        port = item.get("port")
        port = port if isinstance(port, int) else None
        proto = _as_str(item.get("protocol")) or "tcp"
        service = _as_str(item.get("service"))
        product = _as_str(item.get("product"))
        product_ver = _as_str(item.get("product_version"))

        svc_label = f"{service}/{product}" if product else service
        title = f"Open port {port}/{proto} on {host}"
        if svc_label:
            title += f" ({svc_label})"

        loc = NetworkLocation(
            host=host,
            port=port,
            protocol=proto,
            service=service,
            product=product or None,
            product_version=product_ver or None,
        )
        # The service banner is what the scanner actually observed, so it is
        # this finding's evidence. Without it every network finding was
        # unassessable under the grounding rule.
        banner = " ".join(part for part in [service, product, product_ver] if part).strip()

        f = Finding(
            source=ScanType.NETWORK,
            tool=tool_name,
            title=title,
            description=f"Open port detected: {port}/{proto} running {svc_label or 'unknown service'} on {host}",
            location=loc,
            severity_raw=Severity.INFO,
            confidence_raw=Confidence.HIGH,
            exposure=exposure,
            evidence=f"{host}:{port}/{proto} {banner}".strip() if banner else None,
        )
        findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# Native scanner formats
#
# The normalizers above read the simplified arrays the stub plugins document.
# The real tools emit their own envelopes, and until these adapters existed
# every one of them fell through to an empty list without a word: pip-audit
# reporting 109 vulnerabilities on a repository produced zero findings. Each
# adapter below reads one tool's native output, as captured from the tool
# itself (see tests/fixtures/native/).
# ---------------------------------------------------------------------------

# Package types that live in an operating-system layer rather than in an
# application manifest. Trivy and Grype report both kinds in one run.
_OS_PKG_TYPES = {
    "alpine", "amazon", "apk", "bitnami", "centos", "chainguard", "debian",
    "deb", "rpm", "redhat", "rocky", "alma", "ubuntu", "wolfi", "photon",
    "suse", "opensuse", "oracle", "mariner", "azurelinux",
}


def _cve_ids(*values: Any) -> List[str]:
    """Collect the CVE identifiers among ids and alias lists, in order, once."""
    out: List[str] = []
    for value in values:
        for v in _str_list(value):
            v = v.strip().upper()
            if v.startswith("CVE-") and v not in out:
                out.append(v)
    return out


def _redact(secret: str) -> str:
    """Keep enough of a secret to recognise it, never enough to use it."""
    secret = secret.strip()
    if not secret:
        return ""
    return f"{secret[:4]}…[{len(secret)} caractères masqués]"


def _redacted_match(match: str, secret: str) -> Optional[str]:
    """The matched line with the secret itself masked — a report is shared."""
    if not match:
        return None
    return match.replace(secret, _redact(secret)) if secret else _redact(match)


def _dep_or_container(*, pkg: str, ver: str, target: str,
                      pkg_type: str, image: Optional[str]) -> tuple:
    """Pick the family and location for a package finding.

    A package found in an application manifest is a dependency finding; one
    found in an OS layer of an image is a container finding. The scanner's own
    category says nothing about this: Trivy is registered as a container
    scanner, yet ``trivy fs`` on a repository only ever reads manifests.
    """
    if pkg_type.lower() in _OS_PKG_TYPES:
        return ScanType.CONTAINER, ContainerLocation(
            image_ref=image or target or "unknown",
            package_name=pkg, package_version=ver or None,
        )
    return ScanType.DEPS, DepsLocation(
        manifest_path=target or "unknown", package_name=pkg,
        package_version=ver or None, ecosystem=pkg_type or None,
    )


def _normalize_pip_audit(data: Dict[str, Any], tool_name: str) -> List[Finding]:
    """``pip-audit --format json``: ``{"dependencies": [{name, version, vulns}]}``.

    pip-audit reports no severity. The finding keeps UNKNOWN rather than an
    invented level; a second tool citing the same CVE corroborates it (§4.4.3).
    """
    findings: List[Finding] = []
    for dep in _as_list(data.get("dependencies")):
        dep = _as_dict(dep)
        pkg = _as_str(dep.get("name")) or "unknown"
        ver = _as_str(dep.get("version"))
        for vuln in _as_list(dep.get("vulns")):
            vuln = _as_dict(vuln)
            vid = _as_str(vuln.get("id"))
            cves = _cve_ids(vid, vuln.get("aliases"))
            fixes = ", ".join(_str_list(vuln.get("fix_versions")))
            label = cves[0] if cves else vid
            findings.append(Finding(
                source=ScanType.DEPS,
                tool=tool_name,
                title=f"{pkg}@{ver} – {label}" if label else f"Vulnerable dependency: {pkg}@{ver}",
                description=_as_str(vuln.get("description")) or f"{pkg}@{ver} – {vid}",
                location=DepsLocation(manifest_path="requirements.txt", package_name=pkg,
                                      package_version=ver or None, ecosystem="pip"),
                cve=cves,
                severity_raw=Severity.UNKNOWN,
                confidence_raw=Confidence.HIGH,
                evidence=f"{pkg}=={ver} ({vid}" + (f"; corrigé en {fixes})" if fixes else ")"),
                remediation=f"Mettre à jour {pkg} vers {fixes}" if fixes else None,
                references=[r for r in [vid] + _str_list(vuln.get("aliases")) if r],
            ))
    return findings


def _normalize_npm_audit(data: Dict[str, Any], tool_name: str) -> List[Finding]:
    """``npm audit --json`` (report version 2).

    ``vulnerabilities`` maps a package name to an entry whose ``via`` lists
    advisories (objects) and, for packages only vulnerable through a
    dependency, the names of those dependencies (strings). One finding is made
    per advisory, on the package it was filed against; the propagation entries
    would restate the same advisory once per dependent package.
    """
    findings: List[Finding] = []
    for name, entry in _as_dict(data.get("vulnerabilities")).items():
        entry = _as_dict(entry)
        nodes = _str_list(entry.get("nodes"))
        for adv in _as_list(entry.get("via")):
            if not isinstance(adv, dict):
                continue  # propagation: reported on the package that owns it
            if _as_str(adv.get("name")) and _as_str(adv.get("name")) != name:
                continue
            url = _as_str(adv.get("url"))
            ghsa = url.rsplit("/", 1)[-1] if "GHSA-" in url else ""
            title = _as_str(adv.get("title")) or f"Vulnerable dependency: {name}"
            findings.append(Finding(
                source=ScanType.DEPS,
                tool=tool_name,
                title=f"{name} – {ghsa or title}",
                description=title,
                location=DepsLocation(manifest_path="package-lock.json", package_name=name,
                                      package_version=None, ecosystem="npm"),
                cwe=_str_list(adv.get("cwe")),
                severity_raw=_sev(adv.get("severity") or entry.get("severity")),
                confidence_raw=Confidence.HIGH,
                evidence=f"{name} {_as_str(adv.get('range'))}".strip()
                         + (f" ({nodes[0]})" if nodes else ""),
                references=[url] if url else [],
            ))
    return findings


def _normalize_safety(data: Dict[str, Any], tool_name: str) -> List[Finding]:
    """``safety check --json`` / ``--save-json``: ``{"vulnerabilities": [...]}``."""
    findings: List[Finding] = []
    for v in _as_list(data.get("vulnerabilities")):
        v = _as_dict(v)
        pkg = _as_str(v.get("package_name")) or "unknown"
        ver = _as_str(v.get("analyzed_version"))
        vid = _as_str(v.get("vulnerability_id"))
        cves = _cve_ids(v.get("CVE"), v.get("cve"))
        sev = _as_dict(v.get("severity"))
        findings.append(Finding(
            source=ScanType.DEPS,
            tool=tool_name,
            title=f"{pkg}@{ver} – {cves[0] if cves else vid}",
            description=_as_str(v.get("advisory")) or f"{pkg}@{ver} – {vid}",
            location=DepsLocation(manifest_path="requirements.txt", package_name=pkg,
                                  package_version=ver or None, ecosystem="pip"),
            cve=cves,
            severity_raw=_sev(_as_dict(_first(sev, "cvssv3", "cvssv2")).get("base_severity")),
            confidence_raw=Confidence.HIGH,
            evidence=f"{pkg}=={ver} {_as_str(v.get('vulnerable_spec'))}".strip(),
            references=_str_list(v.get("more_info_url")),
        ))
    return findings


def _normalize_gitleaks(data: List[Dict], tool_name: str) -> List[Finding]:
    """``gitleaks --report-format json``: an array of capitalised records.

    The generic secrets normalizer read ``file``/``line``, which Gitleaks spells
    ``File``/``StartLine``: every finding landed at "unknown", line None, and
    deduplication then collapsed all of them into one.
    """
    findings: List[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rule = _as_str(item.get("RuleID")) or "secret"
        line = item.get("StartLine")
        findings.append(Finding(
            source=ScanType.SECRETS,
            tool=tool_name,
            title=f"Secret detected: {rule}",
            description=_as_str(item.get("Description")) or f"Secret detected: {rule}",
            location=CodeLocation(file_path=_as_str(item.get("File")) or "unknown",
                                  start_line=line if isinstance(line, int) else None),
            severity_raw=Severity.HIGH,
            confidence_raw=Confidence.HIGH,
            evidence=_redacted_match(_as_str(item.get("Match")), _as_str(item.get("Secret"))),
        ))
    return findings


def _normalize_trufflehog(data: List[Dict], tool_name: str) -> List[Finding]:
    """``trufflehog filesystem --json``: one JSON object per line.

    A verified secret was accepted by the service it belongs to; an unverified
    one only matched a pattern, so it carries medium confidence.
    """
    findings: List[Finding] = []
    for item in data:
        if not isinstance(item, dict) or "DetectorName" not in item:
            continue  # log lines share the stream
        meta = _as_dict(_as_dict(_as_dict(item.get("SourceMetadata")).get("Data")))
        fs = _as_dict(_first(meta, "Filesystem", "Git") or {})
        line = fs.get("line")
        detector = _as_str(item.get("DetectorName")) or "secret"
        verified = item.get("Verified") is True
        findings.append(Finding(
            source=ScanType.SECRETS,
            tool=tool_name,
            title=f"Secret detected: {detector}" + (" (verified)" if verified else ""),
            description=_as_str(item.get("DetectorDescription")) or f"Secret detected: {detector}",
            location=CodeLocation(file_path=_as_str(fs.get("file")) or "unknown",
                                  start_line=line if isinstance(line, int) else None),
            severity_raw=Severity.HIGH,
            confidence_raw=Confidence.HIGH if verified else Confidence.MEDIUM,
            evidence=_redact(_as_str(item.get("Raw"))) or None,
        ))
    return findings


def _normalize_trivy(data: Dict[str, Any], tool_name: str) -> List[Finding]:
    """``trivy fs|image --format json``: ``{"Results": [{Target, Class, Type, ...}]}``."""
    findings: List[Finding] = []
    image = _as_str(data.get("ArtifactName")) if _as_str(data.get("ArtifactType")) == "container_image" else None
    for res in _as_list(data.get("Results")):
        res = _as_dict(res)
        target = _as_str(res.get("Target"))
        pkg_type = _as_str(res.get("Type"))
        for v in _as_list(res.get("Vulnerabilities")):
            v = _as_dict(v)
            pkg = _as_str(v.get("PkgName")) or "unknown"
            ver = _as_str(v.get("InstalledVersion"))
            vid = _as_str(v.get("VulnerabilityID"))
            source, loc = _dep_or_container(pkg=pkg, ver=ver, target=target,
                                            pkg_type=pkg_type, image=image)
            fixed = _as_str(v.get("FixedVersion"))
            findings.append(Finding(
                source=source,
                tool=tool_name,
                title=f"{pkg}@{ver} – {vid}" if vid else f"Vulnerable package: {pkg}@{ver}",
                description=_as_str(v.get("Title")) or _as_str(v.get("Description")) or vid,
                location=loc,
                cve=_cve_ids(vid),
                cwe=_str_list(v.get("CweIDs")),
                severity_raw=_sev(v.get("Severity")),
                confidence_raw=Confidence.HIGH,
                evidence=f"{pkg}@{ver} in {target}" + (f" (corrigé en {fixed})" if fixed else ""),
                remediation=f"Mettre à jour {pkg} vers {fixed}" if fixed else None,
                references=[r for r in [_as_str(v.get("PrimaryURL"))] if r],
            ))
        for s in _as_list(res.get("Secrets")):
            s = _as_dict(s)
            line = s.get("StartLine")
            rule = _as_str(s.get("RuleID")) or "secret"
            findings.append(Finding(
                source=ScanType.SECRETS,
                tool=tool_name,
                title=f"Secret detected: {rule}",
                description=_as_str(s.get("Title")) or f"Secret detected: {rule}",
                location=CodeLocation(file_path=target or "unknown",
                                      start_line=line if isinstance(line, int) else None),
                severity_raw=_sev(s.get("Severity")),
                confidence_raw=Confidence.HIGH,
                evidence=_as_str(s.get("Match")).strip() or None,  # Trivy masks it
            ))
        for m in _as_list(res.get("Misconfigurations")):
            m = _as_dict(m)
            cause = _as_dict(m.get("CauseMetadata"))
            line = cause.get("StartLine")
            mid = _as_str(m.get("ID")) or _as_str(m.get("AVDID"))
            findings.append(Finding(
                source=ScanType.SAST,
                tool=tool_name,
                title=f"{mid} – {_as_str(m.get('Title'))}".strip(" –"),
                description=_as_str(m.get("Description")) or _as_str(m.get("Message")) or mid,
                location=CodeLocation(file_path=target or "unknown",
                                      start_line=line if isinstance(line, int) else None),
                severity_raw=_sev(m.get("Severity")),
                confidence_raw=Confidence.HIGH,
                evidence=_as_str(m.get("Message")) or None,
                remediation=_as_str(m.get("Resolution")) or None,
                references=_str_list(m.get("References")),
            ))
    return findings


def _normalize_grype(data: Dict[str, Any], tool_name: str) -> List[Finding]:
    """``grype -o json``: ``{"matches": [{vulnerability, artifact, relatedVulnerabilities}]}``."""
    findings: List[Finding] = []
    src = _as_dict(data.get("source"))
    image = _as_str(_as_dict(src.get("target")).get("userInput")) if _as_str(src.get("type")) == "image" else None
    for m in _as_list(data.get("matches")):
        m = _as_dict(m)
        vuln = _as_dict(m.get("vulnerability"))
        art = _as_dict(m.get("artifact"))
        pkg = _as_str(art.get("name")) or "unknown"
        ver = _as_str(art.get("version"))
        locs = _as_list(art.get("locations"))
        target = _as_str(_as_dict(locs[0]).get("path")) if locs else ""
        vid = _as_str(vuln.get("id"))
        related = [_as_dict(r).get("id") for r in _as_list(m.get("relatedVulnerabilities"))]
        source, loc = _dep_or_container(pkg=pkg, ver=ver, target=target,
                                        pkg_type=_as_str(art.get("type")), image=image)
        fixes = ", ".join(_str_list(_as_dict(vuln.get("fix")).get("versions")))
        findings.append(Finding(
            source=source,
            tool=tool_name,
            title=f"{pkg}@{ver} – {vid}" if vid else f"Vulnerable package: {pkg}@{ver}",
            description=_as_str(vuln.get("description")) or vid,
            location=loc,
            cve=_cve_ids(vid, related),
            severity_raw=_sev(vuln.get("severity")),
            confidence_raw=Confidence.HIGH,
            evidence=f"{pkg}@{ver} in {target}".strip() + (f" (corrigé en {fixes})" if fixes else ""),
            remediation=f"Mettre à jour {pkg} vers {fixes}" if fixes else None,
            references=_str_list(vuln.get("urls")),
        ))
    return findings


def _json_lines(text: str) -> Optional[List[Any]]:
    """Parse JSON Lines (one document per line), or return None if it is not."""
    rows: List[Any] = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rows.append(json.loads(raw))
        except (ValueError, RecursionError):
            return None
    return rows or None


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def normalize_artifact(artifact: RawScanArtifact, default_exposure: str = "unknown") -> List[Finding]:
    """Dispatch to the correct normalizer based on scan_type."""
    if not artifact.stdout:
        log.debug("normalize: no stdout for %s – returning empty", artifact.plugin_name)
        return []

    try:
        data = json.loads(artifact.stdout)
    except (ValueError, RecursionError) as exc:
        # JSONDecodeError is a ValueError; RecursionError is what deeply nested
        # input raises, and it is not a ValueError, so it needs naming here.
        # TruffleHog writes JSON Lines, which is not one JSON document.
        data = _json_lines(artifact.stdout)
        if data is None:
            log.warning("normalize: JSON parse failed for %s: %s", artifact.plugin_name, exc)
            return []

    tool = artifact.tool or artifact.plugin_name

    # Native envelopes first, recognised by shape rather than by tool name, so
    # a renamed registry entry still parses. A family's native format may hold
    # findings of other families (Trivy reports packages and secrets together);
    # each adapter assigns the family finding by finding.
    if isinstance(data, dict):
        if "Results" in data and ("SchemaVersion" in data or "ArtifactName" in data):
            return _normalize_trivy(data, tool)
        if "matches" in data and isinstance(data.get("matches"), list):
            return _normalize_grype(data, tool)
        if isinstance(data.get("dependencies"), list):
            return _normalize_pip_audit(data, tool)
        if isinstance(data.get("vulnerabilities"), dict):
            return _normalize_npm_audit(data, tool)
        if isinstance(data.get("vulnerabilities"), list):
            return _normalize_safety(data, tool)
    if isinstance(data, list) and data and all(isinstance(d, dict) for d in data):
        if "RuleID" in data[0] and "File" in data[0]:
            return _normalize_gitleaks(data, tool)
        if any("DetectorName" in d for d in data):
            return _normalize_trufflehog(data, tool)

    if artifact.scan_type == ScanType.SAST:
        # Detect SARIF vs Bandit JSON vs plain array
        if isinstance(data, dict) and "runs" in data:
            return _normalize_sarif(data, tool)
        if isinstance(data, dict) and "results" in data:
            # Bandit native JSON ({"results": [...], "metrics": {...}})
            return _normalize_bandit(data, tool)
        if isinstance(data, list):
            # Plain array of SAST findings (the sast stub's documented input).
            return _normalize_generic_sast(data, tool)
        return []

    if artifact.scan_type == ScanType.DEPS:
        return _normalize_deps(data if isinstance(data, list) else [], tool)

    if artifact.scan_type == ScanType.SECRETS:
        return _normalize_secrets(data if isinstance(data, list) else [], tool)

    if artifact.scan_type == ScanType.CONTAINER:
        return _normalize_container(data if isinstance(data, list) else [], tool)

    if artifact.scan_type == ScanType.NETWORK:
        return _normalize_network(data if isinstance(data, list) else [], tool, default_exposure)

    log.warning("normalize: unknown scan_type %s", artifact.scan_type)
    return []


def normalize_all(artifacts: List[RawScanArtifact], default_exposure: str = "unknown") -> List[Finding]:
    """Normalize all artifacts and return a flat list of findings.

    Each artifact is isolated. One scanner emitting output this code cannot
    parse must not discard the findings of every other scanner in the run —
    which is what used to happen, since a single malformed entry propagated out
    of here and aborted post-processing entirely.
    """
    all_findings: List[Finding] = []
    for artifact in artifacts:
        try:
            findings = normalize_artifact(artifact, default_exposure)
        except Exception as exc:  # noqa: BLE001 – one tool must not sink the run
            log.exception(
                "normalize: %s produced output that could not be normalized (%s); "
                "skipping this artifact and keeping the rest",
                artifact.plugin_name, exc,
            )
            continue
        log.info("normalize: %s → %d findings", artifact.plugin_name, len(findings))
        all_findings.extend(findings)
    return all_findings

