"""
Data models for AetherSec Security Audit Framework.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
import time


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AuditTarget:
    base_url: str
    ws_url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StateNode:
    id: str
    name: str
    path: str
    auth_required: bool = False
    parameters: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StateEdge:
    source_id: str
    target_id: str
    action: str  # GET, POST, WS_SEND, etc.
    parameters: Dict[str, Any] = field(default_factory=dict)
    delta_timing_ms: float = 0.0


@dataclass
class ASTArtifact:
    file_name: str
    unlinked_endpoints: List[str] = field(default_factory=list)
    hidden_parameters: List[str] = field(default_factory=list)
    signing_functions: List[str] = field(default_factory=list)
    sourcemap_found: bool = False


@dataclass
class SchemaAttribute:
    name: str
    inferred_type: str
    is_documented: bool
    is_privileged: bool = False
    confidence: float = 1.0


@dataclass
class ProtocolEvent:
    protocol: str  # HTTP, WS, GRPC
    event_type: str
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class RemediationPatch:
    description: str
    code_snippet: str
    language: str = "python"
    sigma_rule: Optional[str] = None
    owasp_category: str = "OWASP Top 10"


@dataclass
class Finding:
    title: str
    severity: Severity
    engine: str
    description: str
    evidence: Dict[str, Any]
    cvss_score: float
    cwe_id: str
    poc_steps: List[str]
    remediation: RemediationPatch
    timestamp: float = field(default_factory=time.time)


@dataclass
class ChainFinding:
    title: str
    severity: Severity
    combined_cvss: float
    component_findings: List[Finding]
    chain_description: str
    full_poc: List[str]
    remediation: RemediationPatch
