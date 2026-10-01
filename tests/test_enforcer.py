"""
Tests for enforcement and response ladder.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.enforcer import check_status, decide, apply_response_ladder, write_incident
from gateway.schemas import Verdict, AgentStatus
from gateway.tools import clear_effects


def test_verdict_to_response_mapping():
    """Test verdict to response mapping"""
    clear_effects()
    
    agent = {"status": "HEALTHY", "trust_score": 100}
    policy = {"risk": {}}
    
    # ALLOW -> allow
    policy_result = {"allowed": True}
    verdict, response, severity = decide(policy_result, agent, "search_web", policy)
    assert verdict == Verdict.ALLOW
    assert response == "allow"
    
    # BLOCK -> blocked
    policy_result = {"allowed": False, "rule": "allow_tools", "severity": "HIGH"}
    verdict, response, severity = decide(policy_result, agent, "send_email", policy)
    assert verdict == Verdict.BLOCK
    assert response == "blocked"
    assert severity.value == "HIGH"


def test_risk_tier_hold():
    """Test risk-tier HOLD: FLAGGED agent + high-risk tool"""
    clear_effects()
    
    agent = {"status": "FLAGGED", "trust_score": 50}
    policy = {"risk": {"send_email": "high"}}
    
    policy_result = {"allowed": True}
    verdict, response, severity = decide(policy_result, agent, "send_email", policy)
    assert verdict == Verdict.HOLD
    assert response == "held"
    assert severity.value == "HIGH"


def test_throttled_medium_high_risk_hold():
    """Test THROTTLED agent + medium/high-risk tool -> HOLD"""
    clear_effects()
    
    agent = {"status": "THROTTLED", "trust_score": 30}
    policy = {"risk": {"send_email": "medium"}}
    
    policy_result = {"allowed": True}
    verdict, response, severity = decide(policy_result, agent, "send_email", policy)
    assert verdict == Verdict.HOLD
    assert response == "held"


def test_check_status_quarantined():
    """Test QUARANTINED status check"""
    clear_effects()
    
    agent = {"status": "QUARANTINED"}
    should_reject, response, reason = check_status(agent)
    assert should_reject == True
    assert response == "blocked"
    assert reason == "agent_quarantined"


def test_check_status_halted():
    """Test HALTED status check"""
    clear_effects()
    
    agent = {"status": "HALTED"}
    should_reject, response, reason = check_status(agent)
    assert should_reject == True
    assert response == "halted"
    assert reason == "agent_halted"


def test_check_status_healthy():
    """Test HEALTHY status check"""
    clear_effects()
    
    agent = {"status": "HEALTHY"}
    should_reject, response, reason = check_status(agent)
    assert should_reject == False
    assert response is None


def test_apply_response_ladder():
    """Test response ladder updates status"""
    clear_effects()
    
    # This test requires database setup, so we'll test the logic
    # BLOCK should apply penalty and may change status
    # QUARANTINE should set status to QUARANTINED
    # HALT should set status to HALTED
    
    # For now, just verify the function exists and handles the case
    # This would need a real agent in the database
    # Skipping for now as it requires DB setup
    pass


def test_sustained_spike_to_halted():
    """Test that sustained rate violations lead to HALT"""
    clear_effects()
    
    # This test requires database setup to insert rate violation events
    # For now, just verify the function exists
    from engine.enforcer import check_sustained_rate_violations
    assert callable(check_sustained_rate_violations)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
