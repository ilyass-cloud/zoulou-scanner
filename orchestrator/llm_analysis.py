"""LLM-powered triage, prioritisation, and report text generation.

The LLM is fed ONLY normalised, scored findings.  It does NOT replace
scanners – it interprets structured data and produces human-readable output.

Grounding rule: if a finding's evidence field is empty/None, the LLM is
instructed to respond with "insufficient evidence to assess this finding."
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Optional, Tuple

from orchestrator.llm_client import LMStudioClient
from orchestrator.models import Finding

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

_GROUNDING_RULE = (
    "GROUNDING RULE: Base every statement strictly on the provided finding data. "
    "If the 'evidence' field is null or empty for a finding, you MUST write: "
    "'insufficient evidence to assess this finding.' "
    "Do NOT invent CVE details, exploit paths, or package names not present in the data."
)

#: The response the grounding rule mandates for a finding with no evidence.
INSUFFICIENT_EVIDENCE = "insufficient evidence to assess this finding."

#: Cap on free-text salvaged from an unparseable response, so a model that
#: returns its entire reasoning transcript cannot bloat the report.
_MAX_SALVAGED_CHARS = 2000


def is_grounded(finding: Finding) -> bool:
    """Whether a finding carries evidence the model may reason from."""
    return bool((finding.evidence or "").strip())


def _finding_summary(f: Finding) -> dict:
    """Compact dict representation of a finding for LLM consumption."""
    loc = f.location.model_dump()
    return {
        "id": f.id,
        "source": f.source.value,
        "tool": f.tool,
        "title": f.title,
        "description": f.description,
        "location": loc,
        "cve": f.cve,
        "cwe": f.cwe,
        "severity": f.severity_raw.value,
        "confidence": f.confidence_raw.value,
        # Celle qui a servi au score, à côté de celle qu'a rapportée
        # l'outil : sans elle, le modèle lit « LOW » en regard d'un score
        # dont la pénalité de faible confiance a été levée.
        "confidence_effective": (f.confidence_effective or f.confidence_raw).value,
        "exposure": f.exposure.value,
        "risk_score": f.risk_score,
        "evidence": f.evidence or None,
        # Les deux natures de lien sont distinguées : le modèle doit pouvoir
        # justifier une priorité en disant ce qui l'a élevée — une exposition
        # constatée, ou un second outil qui confirme.
        "related_ids": f.related_ids,
        "exposed_via_ids": f.risk_related_ids,
        "corroborated_by_ids": f.corroborating_ids,
        "references": f.references,
    }


def _build_executive_summary_prompt(findings: List[Finding]) -> str:
    top = findings[:20]  # limit context size
    data = [_finding_summary(f) for f in top]
    return (
        f"{_GROUNDING_RULE}\n\n"
        "You are writing an executive summary for a security scan report.\n"
        "Below are the top findings (JSON), sorted by risk score descending.\n"
        "Write a concise executive summary (3–5 paragraphs) covering:\n"
        "  1. Overall risk posture\n"
        "  2. Most critical issues and their business impact\n"
        "  3. Recommended immediate actions\n\n"
        f"FINDINGS:\n{json.dumps(data, indent=2)}"
    )


# JSON schema for a single finding's structured analysis.  Passed to the LLM
# server's structured-output mode so the response is reliably parseable.
_FINDING_ANALYSIS_SCHEMA = {
    "name": "finding_analysis",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "justification": {"type": "string"},
            "remediation": {"type": "string"},
        },
        "required": ["justification", "remediation"],
        "additionalProperties": False,
    },
}


def _build_single_finding_prompt(f: Finding) -> str:
    data = _finding_summary(f)
    return (
        f"{_GROUNDING_RULE}\n\n"
        "Analyse the single security finding below (JSON).\n"
        "Provide:\n"
        "  - justification: one sentence on why this finding has its assigned "
        "priority/risk score.\n"
        "  - remediation: concrete remediation steps grounded in the finding's "
        "evidence and location.\n"
        "If the 'evidence' field is null or empty, both fields MUST be: "
        "'insufficient evidence to assess this finding.'\n\n"
        'Respond as a JSON object: { "justification": "...", "remediation": "..." }\n\n'
        f"FINDING:\n{json.dumps(data, indent=2)}"
    )


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def generate_executive_summary(
    client: LMStudioClient,
    findings: List[Finding],
) -> str:
    """Ask the LLM to produce an executive summary."""
    if not findings:
        return "No findings were produced by any scanner."
    prompt = _build_executive_summary_prompt(findings)
    log.info("llm_analysis: requesting executive summary (%d findings)", len(findings))
    try:
        return client.generate(prompt)
    except RuntimeError as exc:
        log.warning("llm_analysis: executive summary failed – %s", exc)
        return f"[LLM unavailable – executive summary could not be generated: {exc}]"


def analyze_finding(client: LMStudioClient, finding: Finding) -> Finding:
    """Run LLM analysis for a single finding, populating its llm_* fields.

    Mutates and returns the same Finding instance so it can be used directly
    as a worker task.  Failures are recorded in-band on the finding rather
    than raised, so one bad finding never aborts the whole batch.

    The grounding rule is enforced here rather than merely requested in the
    prompt. A finding with no evidence is never sent to the model at all: the
    mandated response is written directly. Asking a model not to speculate is
    not a control — small local models, which is what this project targets,
    routinely answer anyway, and the fabricated line numbers and remediation
    steps then appear in the report indistinguishable from grounded ones.
    Skipping the call also removes one round-trip per ungrounded finding.
    """
    if not is_grounded(finding):
        log.info(
            "llm_analysis: %s has no evidence – applying the grounding rule without calling the model",
            finding.id,
        )
        finding.llm_justification = INSUFFICIENT_EVIDENCE
        finding.llm_remediation = INSUFFICIENT_EVIDENCE
        return finding

    prompt = _build_single_finding_prompt(finding)
    try:
        raw = client.generate(prompt, json_schema=_FINDING_ANALYSIS_SCHEMA)
    except RuntimeError as exc:
        log.warning("llm_analysis: analysis failed for %s – %s", finding.id, exc)
        finding.llm_justification = f"[LLM unavailable: {exc}]"
        finding.llm_remediation = None
        return finding

    try:
        text = (raw or "").strip()
        # Strip markdown code fences if the model wrapped the JSON.
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        item = json.loads(text)
        if not isinstance(item, dict):
            raise TypeError("expected JSON object")
        finding.llm_justification = _clean_field(item.get("justification"))
        finding.llm_remediation = _clean_field(item.get("remediation"))
    except (json.JSONDecodeError, TypeError, ValueError):
        # Salvage the free text as the justification, but leave remediation
        # unset: a response we could not parse is not a remediation plan, and
        # presenting it as one is exactly the failure mode being guarded here.
        log.debug("llm_analysis: could not parse JSON for %s; storing raw text", finding.id)
        finding.llm_justification = _clean_field(raw)
        finding.llm_remediation = None

    return finding


def _clean_field(value: Any) -> Optional[str]:
    """Coerce a model-supplied field to bounded text, or None."""
    if value is None or isinstance(value, (dict, list)):
        return None
    text = (value if isinstance(value, str) else str(value)).strip()
    if not text:
        return None
    if len(text) > _MAX_SALVAGED_CHARS:
        text = text[:_MAX_SALVAGED_CHARS] + "… [truncated]"
    return text


def analyze_findings(
    client: LMStudioClient,
    findings: List[Finding],
    top_n: int = 10,
    max_workers: int = 4,
) -> Tuple[str, List[Finding]]:
    """Analyse the top-N findings independently, in parallel.

    Each finding is processed by its own LLM call (see :func:`analyze_finding`),
    so the per-finding llm_justification / llm_remediation fields are populated
    even when other findings fail.

    Returns:
        (aggregated_markdown_text, findings)  – ``findings`` is the same list
        passed in, with the top-N entries' llm_* fields populated.
    """
    if not findings:
        return "No findings to analyse.", findings

    top = findings[:top_n]
    workers = max(1, min(max_workers, len(top)))
    log.info(
        "llm_analysis: analysing top %d findings (%d workers)", len(top), workers
    )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(analyze_finding, client, f): f for f in top}
        for fut in as_completed(futures):
            f = futures[fut]
            try:
                fut.result()
            except Exception as exc:  # defensive – analyze_finding handles its own errors
                log.warning("llm_analysis: unexpected error for %s – %s", f.id, exc)
                f.llm_justification = f"[analysis error: {exc}]"

    return _render_top_findings(top), findings


def _render_top_findings(findings: List[Finding]) -> str:
    """Build a human-readable markdown block from analysed findings."""
    blocks: List[str] = []
    for rank, f in enumerate(findings, start=1):
        blocks.append(
            f"### {rank}. {f.title}  \n"
            f"`{f.id}` · risk {f.risk_score:.1f} · {f.severity_raw.value}\n\n"
            f"**Justification:** {f.llm_justification or 'n/a'}\n\n"
            f"**Remediation:** {f.llm_remediation or 'n/a'}"
        )
    return "\n\n".join(blocks)


def run_llm_analysis(
    client: LMStudioClient,
    findings: List[Finding],
    enabled: bool = True,
    top_n: int = 10,
    max_workers: int = 4,
) -> Tuple[Optional[str], Optional[str]]:
    """Run full LLM analysis pipeline.

    The executive summary is a single holistic call; the top findings are then
    processed independently and in parallel (one LLM call per finding).

    Returns:
        (executive_summary, top_findings_text)
    """
    if not enabled:
        log.info("llm_analysis: LLM disabled in config – skipping")
        return None, None

    summary = generate_executive_summary(client, findings)
    top_text, _ = analyze_findings(client, findings, top_n=top_n, max_workers=max_workers)
    return summary, top_text

