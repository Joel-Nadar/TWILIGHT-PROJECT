"""
Mock tool implementations for Twilight Gateway.
All tool execution must go through the gateway.
Requires gateway API key, redacts sensitive args, records effects, and guards idempotency.
"""
from typing import Dict, Any, Optional
from gateway.config import settings
import hashlib


# In-memory effect recording (in production, use a table)
executed_events: set = set()
tool_effects: Dict[str, list] = {
    "search_web": [],
    "fetch_webpage": [],
    "send_email": [],
    "read_inbox": [],
    "make_payment": [],
    "send_message": []
}

# Agent inboxes for send_message
agent_inboxes: Dict[str, list] = {
    "researcher": [],
    "emailer": [],
    "payments": []
}


# Sensitive arguments to redact
SENSITIVE_FIELDS = ["body", "to_account", "content", "token", "key", "password", "secret"]


def redact_args(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact sensitive arguments. Centralised function used by chain.py, websocket.py, and events persistence.
    Always redacts: body, to_account, content, tokens, keys.
    """
    redacted = args.copy()
    
    for field in SENSITIVE_FIELDS:
        if field in redacted:
            redacted[field] = "***"
    
    return redacted


def verify_api_key(api_key: Optional[str]) -> bool:
    """Verify the gateway API key"""
    return api_key == settings.gateway_api_key


def check_idempotency(event_id: str) -> bool:
    """Check if this event has already been executed"""
    return event_id in executed_events


def mark_executed(event_id: str):
    """Mark an event as executed"""
    executed_events.add(event_id)


def execute_tool(
    tool: str,
    args: Dict[str, Any],
    event_id: str,
    api_key: Optional[str]
) -> Dict[str, Any]:
    """
    Execute a tool (mock implementation).
    Returns: {"success": bool, "result": Any, "redacted_args": Dict}
    """
    # Verify API key
    if not verify_api_key(api_key):
        return {
            "success": False,
            "result": "Unauthorized: Invalid or missing API key",
            "redacted_args": redact_args(tool, args)
        }
    
    # Check idempotency
    if check_idempotency(event_id):
        return {
            "success": False,
            "result": "Idempotency guard: Event already executed",
            "redacted_args": redact_args(tool, args)
        }
    
    # Execute the tool
    try:
        result = _execute_tool_impl(tool, args)
        mark_executed(event_id)
        
        # Record effect
        effect = {
            "event_id": event_id,
            "tool": tool,
            "args": redact_args(tool, args),
            "result": result
        }
        tool_effects[tool].append(effect)
        
        return {
            "success": True,
            "result": result,
            "redacted_args": redact_args(tool, args)
        }
    except Exception as e:
        return {
            "success": False,
            "result": f"Tool execution error: {str(e)}",
            "redacted_args": redact_args(tool, args)
        }


def _execute_tool_impl(tool: str, args: Dict[str, Any]) -> Any:
    """Internal tool implementation (mock)"""
    if tool == "search_web":
        query = args.get("query", "")
        return {
            "results": [
                {"title": f"Result 1 for {query}", "url": "https://example.com/1"},
                {"title": f"Result 2 for {query}", "url": "https://example.com/2"}
            ],
            "count": 2
        }
    
    elif tool == "fetch_webpage":
        url = args.get("url", "")
        return {
            "url": url,
            "content": f"Mock content from {url}",
            "status_code": 200
        }
    
    elif tool == "send_email":
        to = args.get("to", "")
        subject = args.get("subject", "")
        body = args.get("body", "")
        return {
            "message_id": f"msg-{hashlib.sha256((to + subject).encode()).hexdigest()[:8]}",
            "to": to,
            "subject": subject,
            "status": "sent"
        }
    
    elif tool == "read_inbox":
        limit = args.get("limit", 10)
        return {
            "messages": [
                {"id": "1", "from": "user@example.com", "subject": "Hello", "body": "Hi there"},
                {"id": "2", "from": "admin@company.com", "subject": "Update", "body": "System update"}
            ][:limit],
            "count": min(2, limit)
        }
    
    elif tool == "make_payment":
        to_account = args.get("to_account", "")
        amount = args.get("amount", 0)
        memo = args.get("memo", "")
        return {
            "transaction_id": f"txn-{hashlib.sha256((to_account + str(amount)).encode()).hexdigest()[:8]}",
            "to_account": to_account,
            "amount": amount,
            "memo": memo,
            "status": "completed"
        }
    
    elif tool == "send_message":
        to_agent = args.get("to_agent", "")
        content = args.get("content", "")
        
        # Deliver to recipient's inbox
        if to_agent in agent_inboxes:
            agent_inboxes[to_agent].append({
                "from": "gateway",
                "content": content,
                "timestamp": "2026-10-01T12:00:00Z"
            })
            return {
                "delivered": True,
                "to_agent": to_agent,
                "timestamp": "2026-10-01T12:00:00Z"
            }
        else:
            return {
                "delivered": False,
                "reason": f"Agent {to_agent} not found"
            }
    
    else:
        raise ValueError(f"Unknown tool: {tool}")


def get_tool_effects(tool: Optional[str] = None) -> Dict[str, list]:
    """Get recorded tool effects (for testing)"""
    if tool:
        return {tool: tool_effects.get(tool, [])}
    return tool_effects.copy()


def get_agent_inbox(agent_id: str) -> list:
    """Get messages in an agent's inbox"""
    return agent_inboxes.get(agent_id, []).copy()


def clear_effects():
    """Clear all recorded effects (for testing)"""
    global executed_events, tool_effects, agent_inboxes
    executed_events.clear()
    tool_effects = {k: [] for k in tool_effects.keys()}
    agent_inboxes = {k: [] for k in agent_inboxes.keys()}
