"""
Policy checking for Twilight Gateway.
Deterministic and explainable policy evaluation.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, timezone
from gateway.config import settings
from gateway.db import db


def check_policy(event: Dict[str, Any], policy: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Check if an event complies with the agent's policy.
    Returns a dict with: {allowed: bool, reason: str, rule: str, severity: str}
    """
    tool = event.get("tool")
    args = event.get("args", {})
    context = event.get("context", {})
    agent_id = event.get("agent_id")
    
    # 1. Tool in allow_tools
    allow_tools = policy.get("allow_tools", [])
    if tool not in allow_tools:
        return {
            "allowed": False,
            "reason": f"Tool '{tool}' not allowed for this agent",
            "rule": "allow_tools",
            "severity": "HIGH"
        }
    
    # 2. Argument constraints
    constraints = policy.get("constraints", {}).get(tool, {})
    
    if tool == "send_email":
        # Check to_domain
        allowed_domains = constraints.get("to_domain", [])
        if allowed_domains:
            to = args.get("to", "")
            if not any(to.endswith(domain) for domain in allowed_domains):
                return {
                    "allowed": False,
                    "reason": f"Email to domain '{to}' not allowed (allowed: {allowed_domains})",
                    "rule": "constraints.send_email.to_domain",
                    "severity": "MEDIUM"
                }
        
        # Check max_body_chars
        max_body = constraints.get("max_body_chars")
        if max_body:
            body = args.get("body", "")
            if len(body) > max_body:
                return {
                    "allowed": False,
                    "reason": f"Email body too long: {len(body)} > {max_body} chars",
                    "rule": "constraints.send_email.max_body_chars",
                    "severity": "MEDIUM"
                }
    
    elif tool == "make_payment":
        # Check amount cap
        max_amount = constraints.get("max_amount")
        if max_amount:
            amount = args.get("amount", 0)
            if amount > max_amount:
                return {
                    "allowed": False,
                    "reason": f"Payment amount {amount} exceeds cap {max_amount}",
                    "rule": "constraints.make_payment.max_amount",
                    "severity": "HIGH"
                }
    
    # 3. can_talk_to for send_message
    if tool == "send_message":
        can_talk_to = policy.get("can_talk_to", [])
        to_agent = args.get("to_agent", "")
        if to_agent and to_agent not in can_talk_to:
            return {
                "allowed": False,
                "reason": f"Agent '{to_agent}' not in can_talk_to list",
                "rule": "can_talk_to",
                "severity": "MEDIUM"
            }
    
    # 4. Rate limit (sliding window)
    rate_limit = policy.get("rate", {}).get("max_per_minute")
    if rate_limit:
        if exceeds_rate_limit(agent_id, rate_limit):
            return {
                "allowed": False,
                "reason": f"Rate limit exceeded: {rate_limit} per {settings.rate_window_sec}s",
                "rule": "rate.max_per_minute",
                "severity": "MEDIUM"
            }
    
    # 5. Sequence rules
    sequence_rules = policy.get("sequence_rules", [])
    for rule in sequence_rules:
        rule_name = rule.get("name", "")
        rule_action = rule.get("action", "BLOCK")  # BLOCK or HOLD
        
        # Check "after" trigger
        after_tool = rule.get("after")
        if after_tool:
            recent_tools = history.get("recent_tools", [])
            if after_tool in recent_tools:
                return {
                    "allowed": False,
                    "reason": f"Sequence violation: '{tool}' after '{after_tool}'",
                    "rule": f"sequence.{rule_name}",
                    "severity": "HIGH"
                }
        
        # Check "when_context" trigger
        when_context = rule.get("when_context", {})
        if when_context:
            if context.get("input_taint") == when_context.get("input_taint"):
                return {
                    "allowed": False,
                    "reason": f"Sequence violation: '{tool}' with untrusted input",
                    "rule": f"sequence.{rule_name}",
                    "severity": "HIGH"
                }
    
    # All checks passed
    return {
        "allowed": True,
        "reason": "Policy check passed",
        "rule": "policy.passed",
        "severity": None
    }


def exceeds_rate_limit(agent_id: str, max_per_minute: int) -> bool:
    """
    Check if agent has exceeded rate limit in the sliding window.
    """
    window_start = datetime.now(timezone.utc) - timedelta(seconds=settings.rate_window_sec)
    
    conn = db.get_connection()
    rows = conn.execute("""
        SELECT COUNT(*) as count FROM events
        WHERE agent_id = ? AND ts > ?
        AND verdict IN ('ALLOW', 'FLAG')
    """, (agent_id, window_start.isoformat() + "Z")).fetchone()
    
    return rows["count"] >= max_per_minute


def get_recent_history(agent_id: str, limit: int = 10) -> Dict[str, Any]:
    """
    Get recent tool history for an agent for sequence rule checking.
    """
    conn = db.get_connection()
    rows = conn.execute("""
        SELECT tool FROM events
        WHERE agent_id = ? AND verdict IN ('ALLOW', 'FLAG')
        ORDER BY ts DESC
        LIMIT ?
    """, (agent_id, limit)).fetchall()
    
    recent_tools = [row["tool"] for row in rows]
    return {"recent_tools": recent_tools}
