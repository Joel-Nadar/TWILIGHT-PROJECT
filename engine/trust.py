"""
Trust score management for Twilight Gateway.
Handles penalties, recovery, tier transitions, and probation.
"""
from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone
from gateway.config import settings
from gateway.db import db
from gateway.schemas import AgentStatus


def apply_penalty(score: int, reason: str, policy: Dict[str, Any]) -> int:
    """
    Apply a penalty to the trust score based on the policy.
    Clamps to 0-100.
    """
    trust_penalties = policy.get("trust_penalties", {})
    
    # Default penalties
    default_penalties = {
        "tool_not_allowed": 40,
        "sequence_violation": 40,
        "constraint_violated": 25,
        "rate_exceeded": 15,
        "drift_anomaly": 10
    }
    
    # Determine penalty amount
    penalty = None
    reason_lower = reason.lower()
    
    if "not allowed" in reason_lower:
        penalty = trust_penalties.get("tool_not_allowed", default_penalties["tool_not_allowed"])
    elif "sequence" in reason_lower:
        penalty = trust_penalties.get("sequence_violation", default_penalties["sequence_violation"])
    elif "constraint" in reason_lower:
        penalty = trust_penalties.get("constraint_violated", default_penalties["constraint_violated"])
    elif "rate" in reason_lower:
        penalty = trust_penalties.get("rate_exceeded", default_penalties["rate_exceeded"])
    elif "drift" in reason_lower:
        penalty = trust_penalties.get("drift_anomaly", default_penalties["drift_anomaly"])
    
    if penalty is None:
        penalty = default_penalties["tool_not_allowed"]  # Default for unknown reasons
    
    new_score = max(0, score - penalty)
    return new_score


def status_for_score(score: int, prev_status: Optional[str] = None) -> AgentStatus:
    """
    Determine agent status based on trust score with hysteresis.
    Moving UP a tier requires TRUST_HYSTERESIS points above the threshold.
    """
    if prev_status is None:
        prev_status = "HEALTHY"
    
    # Thresholds
    healthy_min = settings.trust_healthy_min
    flag_min = settings.trust_flag_min
    throttle_min = settings.trust_throttle_min
    
    # Critical override: if prev_status is QUARANTINED or HALTED, stay there
    # (only admin resume can release)
    if prev_status in ["QUARANTINED", "HALTED"]:
        return AgentStatus(prev_status)
    
    # Moving DOWN: immediate
    if score < throttle_min:
        return AgentStatus.QUARANTINED
    elif score < flag_min:
        return AgentStatus.THROTTLED
    elif score < healthy_min:
        return AgentStatus.FLAGGED
    
    # Moving UP: requires hysteresis
    if prev_status == "THROTTLED":
        # Need to be flag_min + hysteresis to move to FLAGGED
        if score >= flag_min + settings.trust_hysteresis:
            return AgentStatus.FLAGGED
        return AgentStatus.THROTTLED
    
    elif prev_status == "FLAGGED":
        # Need to be healthy_min + hysteresis to move to HEALTHY
        if score >= healthy_min + settings.trust_hysteresis:
            return AgentStatus.HEALTHY
        return AgentStatus.FLAGGED
    
    else:
        # Already HEALTHY or below throttle_min
        return AgentStatus.HEALTHY


def recover_clean_agent(agent_id: str, score: int, is_on_probation: bool = False) -> int:
    """
    Recover trust score for an agent with clean behaviour.
    +TRUST_RECOVERY_PER_MIN per clean minute, respecting hysteresis and PROBATION_CAP.
    QUARANTINED and HALTED agents never auto-recover.
    """
    agent = db.get_agent(agent_id)
    if not agent:
        return score
    
    # QUARANTINED and HALTED never auto-recover
    if agent["status"] in ["QUARANTINED", "HALTED"]:
        return score
    
    # Apply recovery
    new_score = min(100, score + settings.trust_recovery_per_min)
    
    # Respect probation cap
    if is_on_probation:
        new_score = min(new_score, settings.probation_cap)
    
    return new_score


def apply_trust_update(agent_id: str, new_score: int, new_status: AgentStatus, reason: str):
    """
    Persist trust score and status update to database and trust history.
    Uses transaction for atomicity.
    """
    with db.transaction() as conn:
        # Update agent
        conn.execute("""
            UPDATE agents SET trust_score = ?, status = ?, last_seen = datetime('now')
            WHERE agent_id = ?
        """, (new_score, new_status.value, agent_id))
        
        # Insert trust history
        conn.execute("""
            INSERT INTO trust_history (agent_id, ts, score, reason)
            VALUES (?, datetime('now'), ?, ?)
        """, (agent_id, new_score, reason))


def get_trust_history(agent_id: str, limit: int = 50) -> list:
    """Get trust history for an agent"""
    return db.get_trust_history(agent_id, limit)


def is_on_probation(agent_id: str) -> bool:
    """Check if agent is on probation"""
    agent = db.get_agent(agent_id)
    if not agent:
        return False
    
    if agent.get("probation_until"):
        probation_until = datetime.fromisoformat(agent["probation_until"])
        return datetime.now(timezone.utc) < probation_until
    
    return False
