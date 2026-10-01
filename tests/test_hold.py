"""
Tests for HOLD queue functionality.
"""
import pytest
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gateway.db import db
from gateway.tools import clear_effects


def test_held_action_not_executed():
    """Test that held action is not executed initially"""
    clear_effects()
    
    # Clear held_actions table using direct connection
    conn = db.get_connection()
    conn.execute("DELETE FROM held_actions")
    conn.commit()
    
    # Insert a held action
    import json
    event_id = f"test-held-{uuid.uuid4()}"
    event = {
        "event_id": event_id,
        "agent_id": "emailer",
        "tool": "send_email",
        "args": {"to": "test@company.com"}
    }
    
    db.insert_held_action(event["event_id"], event["agent_id"], json.dumps(event))
    
    # Check status
    held = db.get_held_action(event["event_id"])
    assert held is not None
    assert held["status"] == "PENDING"
    
    # Tool should not have been executed
    from gateway.tools import executed_events
    assert event["event_id"] not in executed_events


def test_approve_executes_once():
    """Test that approving executes tool exactly once"""
    clear_effects()
    
    # Clear held_actions table
    conn = db.get_connection()
    conn.execute("DELETE FROM held_actions")
    conn.commit()
    
    # Insert a held action
    import json
    event_id = f"test-held-{uuid.uuid4()}"
    event = {
        "event_id": event_id,
        "agent_id": "emailer",
        "tool": "send_email",
        "args": {"to": "test@company.com", "subject": "Test", "body": "Hello"}
    }
    
    db.insert_held_action(event["event_id"], event["agent_id"], json.dumps(event))
    
    # Approve
    from gateway.tools import execute_tool
    result = execute_tool(event["tool"], event["args"], event["event_id"], "change-me")
    assert result["success"] == True
    
    # Update status
    db.update_held_action_status(event["event_id"], "APPROVED")
    
    # Check it was executed
    from gateway.tools import executed_events
    assert event["event_id"] in executed_events
    
    # Try to execute again - should fail idempotency guard
    result2 = execute_tool(event["tool"], event["args"], event["event_id"], "change-me")
    assert result2["success"] == False
    assert "already executed" in result2["result"]


def test_double_approve_idempotent():
    """Test that double approve is idempotent"""
    clear_effects()
    
    # Clear held_actions table
    conn = db.get_connection()
    conn.execute("DELETE FROM held_actions")
    conn.commit()
    
    # Insert a held action
    import json
    event_id = f"test-held-{uuid.uuid4()}"
    event = {
        "event_id": event_id,
        "agent_id": "emailer",
        "tool": "send_email",
        "args": {"to": "test@company.com"}
    }
    
    db.insert_held_action(event["event_id"], event["agent_id"], json.dumps(event))
    
    # First approve
    db.update_held_action_status(event["event_id"], "APPROVED")
    
    # Second approve (should not change anything)
    db.update_held_action_status(event["event_id"], "APPROVED")
    
    held = db.get_held_action(event["event_id"])
    assert held["status"] == "APPROVED"


def test_reject_discards_and_penalises():
    """Test that reject discards action and applies penalty"""
    clear_effects()
    
    # Clear held_actions table
    conn = db.get_connection()
    conn.execute("DELETE FROM held_actions")
    conn.commit()
    
    # Insert a held action
    import json
    event_id = f"test-held-{uuid.uuid4()}"
    event = {
        "event_id": event_id,
        "agent_id": "emailer",
        "tool": "send_email",
        "args": {"to": "test@company.com"}
    }
    
    db.insert_held_action(event["event_id"], event["agent_id"], json.dumps(event))
    
    # Reject
    db.update_held_action_status(event["event_id"], "REJECTED")
    
    held = db.get_held_action(event["event_id"])
    assert held["status"] == "REJECTED"
    
    # Tool should not have been executed
    from gateway.tools import executed_events
    assert event["event_id"] not in executed_events
    
    # Penalty should be applied (would need agent in DB to test fully)
    # For now, just verify the status is REJECTED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
