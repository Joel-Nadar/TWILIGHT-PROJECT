"""
Frozen contracts for Twilight Gateway.
Single source of truth for all API models and enums.
"""
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
import uuid


class Verdict(str, Enum):
    """Verdict enum - frozen values only"""
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    HOLD = "HOLD"
    THROTTLE = "THROTTLE"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"


class AgentStatus(str, Enum):
    """Agent status enum - frozen values only"""
    HEALTHY = "HEALTHY"
    FLAGGED = "FLAGGED"
    THROTTLED = "THROTTLED"
    QUARANTINED = "QUARANTINED"
    HALTED = "HALTED"


class Severity(str, Enum):
    """Severity enum - frozen values only"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AgentRegistration(BaseModel):
    """Agent registration request"""
    agent_id: str = Field(..., description="Unique agent identifier")
    public_key: str = Field(..., description="Ed25519 public key in hex or base64")
    policy: str = Field(..., description="Policy YAML content")
    manifest: str = Field(..., description="Signed manifest JSON")
    config_path: str = Field(..., description="Path to agent config file")


class ActionEvent(BaseModel):
    """Action event submitted by agent"""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique event ID")
    ts: str = Field(..., description="ISO-8601 UTC timestamp")
    agent_id: str = Field(..., description="Agent identifier")
    type: str = Field(default="tool_call", description="Event type")
    tool: str = Field(..., description="Tool name")
    args: Dict[str, Any] = Field(..., description="Tool arguments")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional context")
    nonce: str = Field(..., description="Fresh nonce for replay protection")
    signature: str = Field(..., description="Ed25519 signature of canonical JSON (excluding signature field)")

    @field_validator("ts")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        """Ensure timestamp is ISO-8601 format"""
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError:
            raise ValueError("Timestamp must be ISO-8601 format")


class Decision(BaseModel):
    """Decision returned by pipeline"""
    verdict: Verdict
    response: str = Field(..., description="allow, held, throttled, blocked, halted")
    reason: str = Field(..., description="Plain language explanation")
    rule: Optional[str] = Field(None, description="Rule ID that triggered this decision")
    severity: Optional[Severity] = Field(None, description="Incident severity if applicable")
    trust_before: Optional[int] = Field(None, description="Trust score before this action")
    trust_after: Optional[int] = Field(None, description="Trust score after this action")
    status: Optional[AgentStatus] = Field(None, description="Agent status after this action")
    evidence: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional evidence")
    latency_ms: Optional[float] = Field(None, description="Pipeline latency in milliseconds")


class HeartbeatRequest(BaseModel):
    """Heartbeat request from agent - can be empty to get a challenge, or with nonce+signature to respond"""
    nonce: Optional[str] = Field(None, description="Challenge nonce from gateway (if responding)")
    signature: Optional[str] = Field(None, description="Signed response to challenge (if responding)")


class HeartbeatResponse(BaseModel):
    """Heartbeat response from gateway"""
    challenge_nonce: Optional[str] = Field(None, description="Fresh challenge nonce (if requesting)")
    config_hash: Optional[str] = Field(None, description="Gateway-computed config hash (if verification succeeded)")


class TrustHistoryEntry(BaseModel):
    """Trust history entry"""
    ts: str
    score: int
    reason: str


class RestoreStepResult(BaseModel):
    """Result of a single restore step"""
    step: str = Field(..., description="Step name")
    success: bool = Field(..., description="Whether step succeeded")
    details: Optional[str] = Field(None, description="Additional details")


class RestoreResult(BaseModel):
    """Result of restore operation"""
    agent_id: str
    steps: List[RestoreStepResult]
    overall_success: bool


class RuntimeMode(BaseModel):
    """Runtime mode for gateway"""
    mode: str = Field(..., description="off, dry-run, or on")


class AdminApproval(BaseModel):
    """Admin approval for held action"""
    approved: bool = Field(..., description="True to approve, False to reject")
    reason: Optional[str] = Field(None, description="Optional reason for decision")


class AuditRecord(BaseModel):
    """Audit record in hash chain"""
    seq: int = Field(..., description="Sequence number")
    timestamp: str = Field(..., description="ISO-8601 UTC timestamp")
    agent_id: str = Field(..., description="Agent identifier")
    record_json: str = Field(..., description="Redacted canonical JSON of the record")
    prev_hash: str = Field(..., description="Previous record hash (64 zeros for genesis)")
    record_hash: str = Field(..., description="SHA-256 hash of prev_hash + record_json")
    signature: Optional[str] = Field(None, description="Gateway signature for checkpoints")


class Incident(BaseModel):
    """Security incident record"""
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique incident ID")
    ts: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z", description="ISO-8601 UTC timestamp")
    agent_id: str = Field(..., description="Agent identifier")
    severity: Severity = Field(..., description="Incident severity")
    summary: str = Field(..., description="Incident summary")
    resolved: bool = Field(default=False, description="Whether incident is resolved")


class AgentInfo(BaseModel):
    """Agent information for GET /agents"""
    agent_id: str
    status: AgentStatus
    trust_score: int
    last_seen: Optional[str] = None
    current_rate_limit: Optional[int] = None
    config_hash_ok: bool = Field(..., description="Whether config hash matches manifest")
    probation_until: Optional[str] = None
    trust_history: List[TrustHistoryEntry] = Field(default_factory=list)


class TrustHistoryEntry(BaseModel):
    """Trust history entry"""
    ts: str
    score: int
    reason: str


class VerifyChainResult(BaseModel):
    """Audit chain verification result"""
    valid: bool
    records_checked: int = 0
    first_broken_seq: Optional[int] = None
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    reason: Optional[str] = None
    checkpoints_checked: int = 0


class WebSocketMessage(BaseModel):
    """WebSocket message envelope"""
    type: str = Field(..., description="decision, incident, trust, or status")
    ts: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z", description="ISO-8601 UTC timestamp")
    data: Dict[str, Any] = Field(..., description="Message payload (redacted)")


class PolicyConfig(BaseModel):
    """Validated policy configuration"""
    agent: str
    version: int
    allow_tools: List[str]
    can_talk_to: List[str]
    risk: Dict[str, str]
    constraints: Dict[str, Dict[str, Any]]
    rate: Dict[str, int]
    sequence_rules: List[Dict[str, Any]]
    trust_penalties: Dict[str, int]

    @field_validator("risk")
    @classmethod
    def validate_risk_levels(cls, v: Dict[str, str]) -> Dict[str, str]:
        """Ensure risk levels are valid"""
        valid_levels = {"low", "medium", "high"}
        for tool, level in v.items():
            if level.lower() not in valid_levels:
                raise ValueError(f"Invalid risk level '{level}' for tool '{tool}'. Must be one of {valid_levels}")
        return {k: v.lower() for k, v in v.items()}


def canonical_json(data: Dict[str, Any]) -> str:
    """
    Convert data to canonical JSON for signing/hashing.
    Sorted keys, compact separators, UTF-8, no extra whitespace.
    """
    import json
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
