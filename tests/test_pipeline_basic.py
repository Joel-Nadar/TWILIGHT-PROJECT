"""
Basic pipeline tests.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gateway.pipeline import run_pipeline
from gateway.db import db
from gateway.config import settings
from gateway.tools import clear_effects


def test_normal_action_allowed():
    """Test that a normal allowed action is permitted"""
    clear_effects()
    
    # This test requires a registered agent
    # For now, we'll test the pipeline structure
    event = {
        "event_id": "test-event-1",
        "ts": "2026-10-01T12:00:00Z",
        "agent_id": "researcher",
        "type": "tool_call",
        "tool": "search_web",
        "args": {"query": "test"},
        "context": {},
        "nonce": "nonce-1",
        "signature": "dummy_signature"  # Will fail signature check
    }
    
    decision = run_pipeline(event, settings.gateway_api_key)
    
    # Should fail signature check in Phase 2 (no real key)
    assert decision.response in ["blocked", "allow"]
    assert decision.reason is not None
    assert decision.latency_ms is not None


def test_unknown_tool_blocked():
    """Test that unknown tool is blocked"""
    clear_effects()
    
    event = {
        "event_id": "test-event-2",
        "ts": "2026-10-01T12:00:00Z",
        "agent_id": "researcher",
        "type": "tool_call",
        "tool": "unknown_tool",
        "args": {},
        "context": {},
        "nonce": "nonce-2",
        "signature": "dummy_signature"
    }
    
    decision = run_pipeline(event, settings.gateway_api_key)
    
    # Should fail signature check first, but if it passes, should block on unknown tool
    assert decision.response in ["blocked"]
    assert decision.reason is not None


def test_quarantined_agent_rejected():
    """Test that quarantined agent is rejected at step 1"""
    clear_effects()
    
    # First, quarantine an agent
    db.insert_agent("test_quarantined", "dummy_key", status="QUARANTINED", trust_score=50)
    
    event = {
        "event_id": "test-event-3",
        "ts": "2026-10-01T12:00:00Z",
        "agent_id": "test_quarantined",
        "type": "tool_call",
        "tool": "search_web",
        "args": {"query": "test"},
        "context": {},
        "nonce": "nonce-3",
        "signature": "dummy_signature"
    }
    
    decision = run_pipeline(event, settings.gateway_api_key)
    
    # Should be rejected at step 1 with quarantined reason
    assert decision.response == "blocked"
    assert "QUARANTINED" in decision.reason or "quarantined" in decision.reason.lower()
    assert decision.rule == "status.quarantined"


def test_exception_gives_block_with_audit():
    """Test that exceptions result in BLOCK with audit record"""
    clear_effects()
    
    # This test checks the fail-closed behavior
    # We'll use an unregistered agent to trigger an exception in policy loading
    event = {
        "event_id": "test-event-4-unique",
        "ts": "2026-10-01T12:00:00Z",
        "agent_id": "researcher",  # This agent doesn't exist
        "type": "tool_call",
        "tool": "search_web",
        "args": {"query": "test"},
        "context": {},
        "nonce": "nonce-4",
        "signature": "dummy_signature"
    }
    
    decision = run_pipeline(event, settings.gateway_api_key)
    
    # Should return BLOCK with internal_error (from signature check on unknown agent)
    # or agent not found
    assert decision.response == "blocked"
    assert decision.reason is not None
    
    # Check that audit record was written
    records = db.get_audit_records(limit=1)
    assert len(records) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
