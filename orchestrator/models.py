"""Pydantic data models for the Security Orchestrator."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ScanType(str, Enum):
    SAST = "SAST"
    DEPS = "DEPS"
    SECRETS = "SECRETS"
    CONTAINER = "CONTAINER"
    NETWORK = "NETWORK"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Exposure(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Location models (union-like via discriminated field)
# ---------------------------------------------------------------------------

class CodeLocation(BaseModel):
    """Location within source code."""
    kind: str = "code"
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    snippet: Optional[str] = None


class DepsLocation(BaseModel):
    """Location within a dependency manifest."""
    kind: str = "deps"
    manifest_path: str
    package_name: str
    package_version: Optional[str] = None
    ecosystem: Optional[str] = None


class ContainerLocation(BaseModel):
    """Location within a container image."""
    kind: str = "container"
    image_ref: str
    layer_digest: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None


class NetworkLocation(BaseModel):
    """Location on the network (host + port)."""
    kind: str = "network"
    host: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    product_version: Optional[str] = None


Location = Union[CodeLocation, DepsLocation, ContainerLocation, NetworkLocation]


# ---------------------------------------------------------------------------
# Core Finding model
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """Normalised security finding produced by any plugin."""

    id: str = Field(default="", description="Deterministic fingerprint (SHA-256 prefix)")
    source: ScanType
    tool: str
    tool_version: Optional[str] = None

    title: str
    description: str

    location: Location

    # Identifiers
    cve: List[str] = Field(default_factory=list)
    cwe: List[str] = Field(default_factory=list)

    severity_raw: Severity = Severity.UNKNOWN
    confidence_raw: Confidence = Confidence.UNKNOWN

    #: La confiance effectivement retenue par le scoring, une fois la
    #: corroboration prise en compte (voir `scoring.effective_confidence`).
    #: Elle est distincte de `confidence_raw`, qui reste ce que le scanner a
    #: rapporté ; sans ce champ, un lecteur du rapport JSON voit une pénalité
    #: de faible confiance disparaître sans pouvoir dire pourquoi, et le §4.5
    #: promet que tout score est reconstituable. Vaut None tant que le scoring
    #: n'a pas eu lieu.
    confidence_effective: Optional[Confidence] = None

    evidence: Optional[str] = None
    exposure: Exposure = Exposure.UNKNOWN

    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)

    # Correlation.
    #
    # A link between two findings can mean two different things, and conflating
    # them was a modelling error: two tools reporting the SAME issue is
    # redundancy of tooling, whereas a vulnerable package that is ALSO exposed
    # on the network is a new fact. The first speaks to whether a finding is
    # real (confidence), the second to how bad it is if real (risk). They are
    # therefore recorded separately and consumed by different terms of the
    # score; `related_ids` remains their union, which is what the report shows
    # and what the model is given.
    related_ids: List[str] = Field(default_factory=list)

    #: Links that raise risk: a dependency or image package that a network scan
    #: shows exposed under the same product name (correlation rule 1).
    risk_related_ids: List[str] = Field(default_factory=list)

    #: Links that raise confidence: another tool reporting the same CVE
    #: (correlation rule 2). Corroboration is evidence against a false
    #: positive, not evidence of greater severity.
    corroborating_ids: List[str] = Field(default_factory=list)

    # LLM-generated fields (populated after analysis)
    llm_remediation: Optional[str] = None
    llm_justification: Optional[str] = None

    @model_validator(mode="after")
    def _auto_fingerprint(self) -> "Finding":
        if not self.id:
            self.id = fingerprint(self)
        return self


def fingerprint(finding: Finding) -> str:
    """Deterministic SHA-256 fingerprint based on stable finding fields."""
    loc = finding.location
    loc_key: str
    if isinstance(loc, CodeLocation):
        loc_key = f"code:{loc.file_path}:{loc.start_line}"
    elif isinstance(loc, DepsLocation):
        loc_key = f"deps:{loc.manifest_path}:{loc.package_name}:{loc.package_version}"
    elif isinstance(loc, ContainerLocation):
        loc_key = f"container:{loc.image_ref}:{loc.package_name}:{loc.package_version}"
    elif isinstance(loc, NetworkLocation):
        loc_key = f"network:{loc.host}:{loc.port}:{loc.protocol}"
    else:
        loc_key = "unknown"

    payload = "|".join([
        finding.source.value,
        finding.tool,
        finding.title,
        loc_key,
        ",".join(sorted(finding.cve)),
        ",".join(sorted(finding.cwe)),
    ])
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return digest[:16]


# ---------------------------------------------------------------------------
# Raw scan artifact (plugin output before normalisation)
# ---------------------------------------------------------------------------

class RawScanArtifact(BaseModel):
    """Raw output from a plugin run."""
    plugin_name: str
    scan_type: ScanType
    tool: str
    tool_version: Optional[str] = None
    raw_file_path: Optional[str] = None   # path to output file
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_code: int = 0
    duration_seconds: float = 0.0
    extra: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Aggregated scan result
# ---------------------------------------------------------------------------

class ScanResult(BaseModel):
    """Full result of an orchestration run."""
    run_id: str
    repo_path: str
    config_path: str
    artifacts: List[RawScanArtifact] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    executive_summary: Optional[str] = None
    top_findings_analysis: Optional[str] = None
    errors: List[str] = Field(default_factory=list)

