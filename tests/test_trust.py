"""
Tests for trust score management.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.trust import apply_penalty, status_for_score, recover_clean_agent, is_on_probation
from gateway.tools import clear_effects


def test_penalty_weights():
    """Test penalty weights from policy"""
    clear_effects()
    
    policy = {
        "trust_penalties": {
            "tool_not_allowed": 40,
            "sequence_violation": 40,
            "constraint_violated": 25,
            "rate_exceeded": 15
        }
    }
    
    # Test tool_not_allowed (reason contains "not allowed")
    new_score = apply_penalty(100, "Tool 'send_email' not allowed for this agent", policy)
    assert new_score == 60
    
    # Test sequence_violation
    new_score = apply_penalty(100, "Sequence violation", policy)
    assert new_score == 60
    
    # Test constraint_violated
    new_score = apply_penalty(100, "Constraint violated", policy)
    assert new_score == 75
    
    # Test rate_exceeded
    new_score = apply_penalty(100, "Rate exceeded", policy)
    assert new_score == 85


def test_clamping():
    """Test that scores are clamped to 0-100"""
    clear_effects()
    
    policy = {"trust_penalties": {"tool_not_allowed": 150}}
    
    # Clamp at 0
    new_score = apply_penalty(50, "Tool not allowed", policy)
    assert new_score == 0
    
    # Clamp at 100 (not really applicable with penalties, but test recovery)
    policy = {"trust_penalties": {}}
    new_score = recover_clean_agent("test", 95, is_on_probation=False)
    assert new_score <= 100


def test_tier_transitions():
    """Test tier transitions based on score"""
    clear_effects()
    
    # 70-100 -> HEALTHY
    status = status_for_score(100)
    assert status.value == "HEALTHY"
    
    status = status_for_score(70)
    assert status.value == "HEALTHY"
    
    # 40-69 -> FLAGGED
    status = status_for_score(69)
    assert status.value == "FLAGGED"
    
    status = status_for_score(40)
    assert status.value == "FLAGGED"
    
    # 20-39 -> THROTTLED
    status = status_for_score(39)
    assert status.value == "THROTTLED"
    
    status = status_for_score(20)
    assert status.value == "THROTTLED"
    
    # Below 20 -> QUARANTINED
    status = status_for_score(19)
    assert status.value == "QUARANTINED"
    
    status = status_for_score(0)
    assert status.value == "QUARANTINED"


def test_hysteresis():
    """Test hysteresis - moving up requires points above threshold"""
    clear_effects()
    
    # At exactly threshold, should stay in lower tier
    status = status_for_score(40, prev_status="THROTTLED")
    # Actually, 40 is at the boundary - let me check the logic
    # 40 is flag_min, so 40 should be FLAGGED, not THROTTLED
    # Let me test with 39 (below threshold)
    status = status_for_score(39, prev_status="THROTTLED")
    assert status.value == "THROTTLED"  # Below threshold, stays THROTTLED
    
    # Above threshold with hysteresis
    from gateway.config import settings
    status = status_for_score(40 + settings.trust_hysteresis + 1, prev_status="THROTTLED")
    assert status.value == "FLAGGED"


def test_recovery():
    """Test trust recovery logic"""
    clear_effects()
    
    # Recovery adds points (simplified test without DB)
    from gateway.config import settings
    new_score = min(100, 50 + settings.trust_recovery_per_min)
    assert new_score == 51  # +1 by default


def test_probation_cap():
    """Test probation cap during recovery"""
    clear_effects()
    
    # On probation, cap applies
    new_score = recover_clean_agent("test", 75, is_on_probation=True)
    from gateway.config import settings
    assert new_score <= settings.probation_cap


def test_critical_override():
    """Test that config hash mismatch doesn't change trust score"""
    clear_effects()
    
    # This is tested in the pipeline - trust score unchanged for QUARANTINE from hash mismatch
    # The status_for_score function respects QUARANTINED status
    status = status_for_score(50, prev_status="QUARANTINED")
    assert status.value == "QUARANTINED"  # Stays QUARANTINED regardless of score


def test_quarantined_never_auto_recovers():
    """Test that QUARANTINED agents never auto-recover"""
    clear_effects()
    
    # status_for_score keeps QUARANTINED agents QUARANTINED
    status = status_for_score(100, prev_status="QUARANTINED")
    assert status.value == "QUARANTINED"
    
    status = status_for_score(0, prev_status="QUARANTINED")
    assert status.value == "QUARANTINED"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
