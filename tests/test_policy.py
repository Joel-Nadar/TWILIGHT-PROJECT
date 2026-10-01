"""
Tests for policy checking.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.policy import check_policy
from gateway.tools import clear_effects


def test_allowed_tool():
    """Test that allowed tool passes policy check"""
    clear_effects()
    
    policy = {
        "allow_tools": ["search_web", "fetch_webpage"],
        "constraints": {},
        "can_talk_to": [],
        "rate": {"max_per_minute": 30},
        "sequence_rules": []
    }
    
    event = {
        "agent_id": "researcher",
        "tool": "search_web",
        "args": {"query": "test"},
        "context": {}
    }
    
    result = check_policy(event, policy, {})
    assert result["allowed"] == True
    assert result["rule"] == "policy.passed"


def test_forbidden_tool():
    """Test that forbidden tool is blocked"""
    clear_effects()
    
    policy = {
        "allow_tools": ["search_web"],
        "constraints": {},
        "can_talk_to": [],
        "rate": {"max_per_minute": 30},
        "sequence_rules": []
    }
    
    event = {
        "agent_id": "researcher",
        "tool": "send_email",
        "args": {"to": "test@example.com"},
        "context": {}
    }
    
    result = check_policy(event, policy, {})
    assert result["allowed"] == False
    assert result["rule"] == "allow_tools"
    assert result["severity"] == "HIGH"


def test_send_email_to_evil_domain():
    """Test that email to disallowed domain is blocked"""
    clear_effects()
    
    policy = {
        "allow_tools": ["send_email"],
        "constraints": {
            "send_email": {
                "to_domain": ["company.com"]
            }
        },
        "can_talk_to": [],
        "rate": {"max_per_minute": 30},
        "sequence_rules": []
    }
    
    event = {
        "agent_id": "emailer",
        "tool": "send_email",
        "args": {"to": "test@evil.com"},
        "context": {}
    }
    
    result = check_policy(event, policy, {})
    assert result["allowed"] == False
    assert result["rule"] == "constraints.send_email.to_domain"
    assert result["severity"] == "MEDIUM"


def test_payment_above_cap():
    """Test that payment above cap is blocked"""
    clear_effects()
    
    policy = {
        "allow_tools": ["make_payment"],
        "constraints": {
            "make_payment": {
                "max_amount": 500
            }
        },
        "can_talk_to": [],
        "rate": {"max_per_minute": 30},
        "sequence_rules": []
    }
    
    event = {
        "agent_id": "payments",
        "tool": "make_payment",
        "args": {"to_account": "ACC-123", "amount": 1000},
        "context": {}
    }
    
    result = check_policy(event, policy, {})
    assert result["allowed"] == False
    assert result["rule"] == "constraints.make_payment.max_amount"
    assert result["severity"] == "HIGH"


def test_body_too_long():
    """Test that email body too long is blocked"""
    clear_effects()
    
    policy = {
        "allow_tools": ["send_email"],
        "constraints": {
            "send_email": {
                "max_body_chars": 100
            }
        },
        "can_talk_to": [],
        "rate": {"max_per_minute": 30},
        "sequence_rules": []
    }
    
    event = {
        "agent_id": "emailer",
        "tool": "send_email",
        "args": {"to": "test@company.com", "body": "x" * 200},
        "context": {}
    }
    
    result = check_policy(event, policy, {})
    assert result["allowed"] == False
    assert result["rule"] == "constraints.send_email.max_body_chars"
    assert result["severity"] == "MEDIUM"


def test_can_talk_to_violation():
    """Test that can_talk_to violation is blocked"""
    clear_effects()
    
    policy = {
        "allow_tools": ["send_message"],
        "can_talk_to": ["researcher"],
        "constraints": {},
        "rate": {"max_per_minute": 30},
        "sequence_rules": []
    }
    
    event = {
        "agent_id": "emailer",
        "tool": "send_message",
        "args": {"to_agent": "payments"},
        "context": {}
    }
    
    result = check_policy(event, policy, {})
    assert result["allowed"] == False
    assert result["rule"] == "can_talk_to"
    assert result["severity"] == "MEDIUM"


def test_sequence_rule_untrusted_taint():
    """Test sequence rule with untrusted taint"""
    clear_effects()
    
    policy = {
        "allow_tools": ["send_email"],
        "constraints": {},
        "can_talk_to": [],
        "rate": {"max_per_minute": 30},
        "sequence_rules": [
            {
                "name": "no_email_when_input_untrusted",
                "when_context": {"input_taint": "untrusted"},
                "then": "send_email",
                "action": "HOLD"
            }
        ]
    }
    
    event = {
        "agent_id": "emailer",
        "tool": "send_email",
        "args": {"to": "test@company.com"},
        "context": {"input_taint": "untrusted"}
    }
    
    result = check_policy(event, policy, {})
    assert result["allowed"] == False
    assert result["rule"] == "sequence.no_email_when_input_untrusted"
    assert result["severity"] == "HIGH"


def test_sequence_rule_after_tool():
    """Test sequence rule with 'after' trigger"""
    clear_effects()
    
    policy = {
        "allow_tools": ["send_email", "fetch_webpage"],
        "constraints": {},
        "can_talk_to": [],
        "rate": {"max_per_minute": 30},
        "sequence_rules": [
            {
                "name": "no_email_after_fetch",
                "after": "fetch_webpage",
                "then": "send_email",
                "action": "BLOCK"
            }
        ]
    }
    
    history = {"recent_tools": ["fetch_webpage"]}
    
    event = {
        "agent_id": "emailer",
        "tool": "send_email",
        "args": {"to": "test@company.com"},
        "context": {}
    }
    
    result = check_policy(event, policy, history)
    assert result["allowed"] == False
    assert result["rule"] == "sequence.no_email_after_fetch"
    assert result["severity"] == "HIGH"


def test_malformed_args_no_crash():
    """Test that malformed args don't crash"""
    clear_effects()
    
    policy = {
        "allow_tools": ["send_email"],
        "constraints": {},
        "can_talk_to": [],
        "rate": {"max_per_minute": 30},
        "sequence_rules": []
    }
    
    event = {
        "agent_id": "emailer",
        "tool": "send_email",
        "args": None,  # Malformed
        "context": {}
    }
    
    # Should not crash
    result = check_policy(event, policy, {})
    # Result depends on implementation, but should not raise exception


def test_rate_limit():
    """Test rate limit check"""
    clear_effects()
    
    policy = {
        "allow_tools": ["search_web"],
        "constraints": {},
        "can_talk_to": [],
        "rate": {"max_per_minute": 5},  # Low limit for testing
        "sequence_rules": []
    }
    
    event = {
        "agent_id": "researcher",
        "tool": "search_web",
        "args": {"query": "test"},
        "context": {}
    }
    
    # Insert 6 events in the last minute (exceeds limit of 5)
    from gateway.db import db
    from datetime import datetime, timedelta, timezone
    
    conn = db.get_connection()
    for i in range(6):
        ts = (datetime.now(timezone.utc) - timedelta(seconds=i * 5)).isoformat().replace("+00:00", "Z")
        conn.execute("""
            INSERT INTO events (event_id, ts, agent_id, type, tool, args_json, nonce, signature, verdict, response)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (f"rate-test-{i}", ts, "researcher", "tool_call", "search_web", '{"query":"test"}', f"nonce-{i}", "sig", "ALLOW", "allow"))
    conn.commit()
    
    # Now check if rate limit is exceeded
    result = check_policy(event, policy, {})
    assert result["allowed"] == False
    assert result["rule"] == "rate.max_per_minute"
    assert result["severity"] == "MEDIUM"
    
    # Clean up
    conn.execute("DELETE FROM events WHERE event_id LIKE 'rate-test-%'")
    conn.commit()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
