"""Report generation: report.json and report.md."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from orchestrator.models import Finding, ScanResult, Severity
from orchestrator.scoring import effective_confidence

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity badge for Markdown
# ---------------------------------------------------------------------------

_SEV_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH:     "🟠 HIGH",
    Severity.MEDIUM:   "🟡 MEDIUM",
    Severity.LOW:      "🔵 LOW",
    Severity.INFO:     "⚪ INFO",
    Severity.UNKNOWN:  "❓ UNKNOWN",
}


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def write_json_report(result: ScanResult, out_dir: str) -> str:
    """Write report.json and return its path."""
    path = Path(out_dir) / "report.json"
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "run_id": result.run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo_path": result.repo_path,
        "config_path": result.config_path,
        "errors": result.errors,
        "summary": {
            "total_findings": len(result.findings),
            "by_severity": _count_by_severity(result.findings),
            "by_source": _count_by_source(result.findings),
        },
        "findings": [f.model_dump() for f in result.findings],
        "executive_summary": result.executive_summary,
        "top_findings_analysis": result.top_findings_analysis,
        "artifacts": [a.model_dump() for a in result.artifacts],
    }

    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)

    log.info("report: wrote %s", path)
    return str(path)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def write_markdown_report(result: ScanResult, out_dir: str) -> str:
    """Write report.md and return its path."""
    path = Path(out_dir) / "report.md"
    path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Header
    lines += [
        "# Security Scan Report",
        "",
        f"**Run ID:** `{result.run_id}`  ",
        f"**Generated:** {ts}  ",
        f"**Repository:** `{result.repo_path}`  ",
        "",
        "---",
        "",
    ]

    # Executive summary
    lines += [
        "## Executive Summary",
        "",
        result.executive_summary or "_LLM analysis was not available or was disabled._",
        "",
        "---",
        "",
    ]

    # Summary table
    by_sev = _count_by_severity(result.findings)
    lines += [
        "## Finding Counts by Severity",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.UNKNOWN]:
        count = by_sev.get(sev.value, 0)
        if count:
            lines.append(f"| {_SEV_BADGE[sev]} | {count} |")
    lines += ["", "---", ""]

    # Top risks table
    top = result.findings[:15]
    lines += [
        "## Top Risks",
        "",
        "| # | Score | Severity | Source | Title | Tool |",
        "|---|-------|----------|--------|-------|------|",
    ]
    for i, f in enumerate(top, 1):
        badge = _SEV_BADGE.get(f.severity_raw, "❓")
        title_short = f.title[:60] + "…" if len(f.title) > 60 else f.title
        lines.append(
            f"| {i} | {f.risk_score:.0f} | {badge} | {f.source.value} "
            f"| {title_short} | {f.tool} |"
        )
    lines += ["", "---", ""]

    # Per-finding details
    lines += ["## Finding Details", ""]
    for i, f in enumerate(result.findings, 1):
        lines += _finding_section(i, f)

    # Errors
    if result.errors:
        lines += ["---", "", "## Errors During Scan", ""]
        for err in result.errors:
            lines.append(f"- {err}")
        lines.append("")

    content = "\n".join(lines)
    with path.open("w", encoding="utf-8") as fh:
        fh.write(content)

    log.info("report: wrote %s", path)
    return str(path)


def _confidence_cell(f: Finding) -> str:
    """Confiance brute, et confiance effective quand la corroboration l'a levée.

    Le rapport doit continuer de dire ce que l'outil a rapporté : n'afficher que
    la valeur effective masquerait sa provenance, n'afficher que la brute
    rendrait le score inexplicable.
    """
    raw = f.confidence_raw.value
    effective = effective_confidence(f)
    if effective == f.confidence_raw:
        return raw
    n = len(f.corroborating_ids)
    return f"{raw} → {effective.value} (corroborated by {n} other finding)" if n == 1 \
        else f"{raw} → {effective.value} (corroborated by {n} other findings)"


def _finding_section(idx: int, f: Finding) -> List[str]:
    badge = _SEV_BADGE.get(f.severity_raw, "❓")
    loc = f.location.model_dump()
    loc_str = ", ".join(f"{k}: {v}" for k, v in loc.items() if v and k != "kind")

    lines = [
        f"### {idx}. {f.title}",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **ID** | `{f.id}` |",
        f"| **Severity** | {badge} |",
        f"| **Risk Score** | {f.risk_score:.0f} / 100 |",
        f"| **Source** | {f.source.value} |",
        f"| **Tool** | {f.tool} |",
        f"| **Confidence** | {_confidence_cell(f)} |",
        f"| **Exposure** | {f.exposure.value} |",
        f"| **Location** | `{loc_str}` |",
    ]
    if f.cve:
        lines.append(f"| **CVE(s)** | {', '.join(f.cve)} |")
    if f.cwe:
        lines.append(f"| **CWE(s)** | {', '.join(f.cwe)} |")
    # Les deux natures de lien sont montrées séparément : l'une pèse sur le
    # score, l'autre sur le crédit accordé au résultat, et un lecteur qui ne
    # voit que leur réunion ne peut pas savoir laquelle a joué.
    if f.risk_related_ids:
        lines.append(
            f"| **Exposed via** | {', '.join(f'`{r}`' for r in f.risk_related_ids)} |"
        )
    if f.corroborating_ids:
        lines.append(
            f"| **Corroborated by** | {', '.join(f'`{r}`' for r in f.corroborating_ids)} |"
        )
    typed = set(f.risk_related_ids) | set(f.corroborating_ids)
    other = [r for r in f.related_ids if r not in typed]
    if other:
        lines.append(f"| **Related** | {', '.join(f'`{r}`' for r in other)} |")

    lines += ["", f"**Description:** {f.description}", ""]

    if f.evidence:
        lines += [f"**Evidence:** `{f.evidence}`", ""]

    # Remediation: prefer LLM-generated, fall back to static
    remediation = f.llm_remediation or f.remediation
    if remediation:
        lines += ["**Remediation:**", "", remediation, ""]
    elif f.llm_justification:
        lines += [f"**Analysis:** {f.llm_justification}", ""]

    if f.references:
        lines += ["**References:**"]
        for ref in f.references:
            lines.append(f"- {ref}")
        lines.append("")

    lines += ["---", ""]
    return lines


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_by_severity(findings: List[Finding]) -> dict:
    counts: dict = {}
    for f in findings:
        key = f.severity_raw.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _count_by_source(findings: List[Finding]) -> dict:
    counts: dict = {}
    for f in findings:
        key = f.source.value
        counts[key] = counts.get(key, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Combined writer
# ---------------------------------------------------------------------------

def write_reports(result: ScanResult, out_dir: str) -> tuple[str, str]:
    """Write both reports and return (json_path, md_path)."""
    json_path = write_json_report(result, out_dir)
    md_path = write_markdown_report(result, out_dir)
    return json_path, md_path

