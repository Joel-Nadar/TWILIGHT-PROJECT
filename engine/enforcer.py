"""
Enforcement and response ladder for Twilight Gateway.
Maps policy results to verdicts, handles risk-tier holds, and manages status transitions.
"""
from typing import Dict, Any, Optional, Tuple
from gateway.schemas import Verdict, AgentStatus, Severity
from gateway.db import db
from gateway.config import settings
from gateway.websocket import manager
from engine.trust import apply_penalty, status_for_score, apply_trust_update
from datetime import datetime, timedelta, timezone


def check_status(agent: Dict[str, Any]) -> tuple[bool, str, str]:
    """
    Check agent status. Returns (should_reject, response, reason).
    QUARANTINED -> blocked (agent_quarantined)
    HALTED -> halted
    """
    status = agent.get("status")
    
    if status == "QUARANTINED":
        return True, "blocked", "agent_quarantined"
    elif status == "HALTED":
        return True, "halted", "agent_halted"
    
    return False, None, None


def decide(
    policy_result: Dict[str, Any],
    agent: Dict[str, Any],
    tool: str,
    policy: Dict[str, Any]
) -> tuple[Verdict, str, Optional[Severity]]:
    """
    Map policy result to verdict and response using frozen mapping.
    Returns (verdict, response, severity).
    
    Mapping:
    - ALLOW/FLAG -> allow
    - HOLD -> held
    - THROTTLE -> throttled
    - BLOCK/QUARANTINE -> blocked
    - HALTED agent -> halted
    """
    if not policy_result.get("allowed"):
        # Policy rejected
        rule = policy_result.get("rule", "")
        severity_str = policy_result.get("severity")
        
        # Check for sequence rule that should HOLD
        if rule.startswith("sequence.") and severity_str == "HIGH":
            # Check if this should be HOLD based on context
            # For now, sequence violations are BLOCK unless explicitly HOLD
            return Verdict.BLOCK, "blocked", Severity.HIGH
        
        return Verdict.BLOCK, "blocked", Severity(severity_str) if severity_str else None
    
    # Policy allowed - check risk-tier holds
    agent_status = agent.get("status")
    risk = policy.get("risk", {}).get(tool, "low")
    
    # FLAGGED agent + high-risk tool -> HOLD
    if agent_status == "FLAGGED" and risk == "high":
        return Verdict.HOLD, "held", Severity.HIGH
    
    # THROTTLED agent + medium/high-risk tool -> HOLD
    if agent_status == "THROTTLED" and risk in ["medium", "high"]:
        return Verdict.HOLD, "held", Severity.HIGH
    
    # Default: ALLOW
    return Verdict.ALLOW, "allow", None


def check_sustained_rate_violations(agent_id: str) -> bool:
    """
    Check if agent has sustained rate violations that should trigger HALT.
    Returns True if RATE_HALT_AFTER_VIOLATIONS violations in the window.
    """
    window_start = datetime.now(timezone.utc) - timedelta(seconds=settings.rate_window_sec)
    
    conn = db.get_connection()
    rows = conn.execute("""
        SELECT COUNT(*) as count FROM events
        WHERE agent_id = ? AND ts > ?
        AND reason LIKE '%rate limit exceeded%'
    """, (agent_id, window_start.isoformat() + "Z")).fetchone()
    
    return rows["count"] >= settings.rate_halt_after_violations


def apply_response_ladder(
    agent_id: str,
    verdict: Verdict,
    response: str,
    agent: Dict[str, Any],
    policy: Dict[str, Any],
    reason: str,
    rule: str
) -> tuple[int, AgentStatus]:
    """
    Update agent status based on verdict.
    Returns (new_score, new_status).
    
    - BLOCK stops one action only
    - QUARANTINE and HALT cut off the whole agent
    """
    # Fetch fresh agent state from database
    fresh_agent = db.get_agent(agent_id)
    if fresh_agent:
        agent = fresh_agent
    
    current_score = agent.get("trust_score", 100)
    current_status = AgentStatus(agent.get("status", "HEALTHY"))
    
    new_score = current_score
    new_status = current_status
    
    # Apply penalty for BLOCK
    if verdict == Verdict.BLOCK:
        new_score = apply_penalty(current_score, reason, policy)
        new_status = status_for_score(new_score, current_status.value)
    
    # Apply response ladder
    if verdict == Verdict.QUARANTINE:
        new_status = AgentStatus.QUARANTINED
        # Trust score unchanged (critical override)
    elif verdict == Verdict.BLOCK and response == "halted":
        new_status = AgentStatus.HALTED
    
    # Persist updates
    apply_trust_update(agent_id, new_score, new_status, reason)
    
    return new_score, new_status


def write_incident(
    agent_id: str,
    severity: str,
    summary: str,
    rule: str
):
    """Write an incident to the database"""
    from gateway.schemas import Incident
    
    incident = Incident(
        agent_id=agent_id,
        severity=Severity(severity),
        summary=summary
    )
    
    db.insert_incident(incident.model_dump())
    
    # Publish incident to WebSocket
    try:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(manager.publish("incident", {
                "agent_id": agent_id,
                "severity": severity,
                "summary": summary,
                "rule": rule
            }))
        except RuntimeError:
            pass
    except Exception:
        pass


def publish_trust_change(agent_id: str, score_before: int, score_after: int, reason: str):
    """Publish trust change to WebSocket"""
    try:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(manager.publish("trust", {
                "agent_id": agent_id,
                "score_before": score_before,
                "score_after": score_after,
                "reason": reason
            }))
        except RuntimeError:
            pass
    except Exception:
        pass


def publish_status_change(agent_id: str, status_before: str, status_after: str, reason: str):
    """Publish status change to WebSocket"""
    try:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(manager.publish("status", {
                "agent_id": agent_id,
                "status_before": status_before,
                "status_after": status_after,
                "reason": reason
            }))
        except RuntimeError:
            pass
    except Exception:
        pass
