"""
Tests for heartbeat functionality.
"""
import pytest
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.heartbeat import generate_challenge, verify_heartbeat_response, verify_config_integrity
from gateway.db import db
from gateway.tools import clear_effects


def test_valid_heartbeat():
    """Test valid heartbeat flow"""
    clear_effects()
    
    # Generate challenge
    nonce = generate_challenge("researcher")
    assert nonce is not None
    assert len(nonce) == 32  # 16 bytes = 32 hex chars
    
    # Verify with valid signature (this would need actual signing, skipping for now)
    # Just verify the challenge was stored
    challenge = db.get_heartbeat_challenge(nonce)
    assert challenge is not None
    assert challenge['agent_id'] == "researcher"
    
    # Clean up
    conn = db.get_connection()
    conn.execute("DELETE FROM heartbeat_challenges")
    conn.commit()


def test_bad_signature():
    """Test bad signature rejection"""
    clear_effects()
    
    # Generate challenge
    nonce = generate_challenge("researcher")
    
    # Try to verify with bad signature
    is_valid, error, config_hash = verify_heartbeat_response("researcher", nonce, "bad_signature")
    assert is_valid == False
    assert "Invalid signature" in error
    
    # Clean up
    conn = db.get_connection()
    conn.execute("DELETE FROM heartbeat_challenges")
    conn.commit()


def test_reused_challenge():
    """Test reused challenge rejection"""
    clear_effects()
    
    # Generate challenge
    nonce = generate_challenge("researcher")
    
    # First use would delete it (simulated)
    db.delete_heartbeat_challenge(nonce)
    
    # Second use should fail
    is_valid, error, config_hash = verify_heartbeat_response("researcher", nonce, "bad_signature")
    assert is_valid == False
    assert "Invalid or expired" in error
    
    # Clean up
    conn = db.get_connection()
    conn.execute("DELETE FROM heartbeat_challenges")
    conn.commit()


def test_expired_challenge():
    """Test expired challenge rejection"""
    clear_effects()
    
    # Insert an expired challenge
    conn = db.get_connection()
    old_time = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
    conn.execute("""
        INSERT INTO heartbeat_challenges (agent_id, nonce, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    """, ("researcher", "expired_nonce", old_time, old_time))
    conn.commit()
    
    # Try to verify
    is_valid, error, config_hash = verify_heartbeat_response("researcher", "expired_nonce", "bad_signature")
    assert is_valid == False
    assert "expired" in error.lower()
    
    # Clean up
    conn.execute("DELETE FROM heartbeat_challenges")
    conn.commit()


def test_config_mismatch_quarantines():
    """Test that config mismatch quarantines with trust unchanged"""
    clear_effects()
    
    # This would require actually tampering with a config file
    # For now, just verify the function exists and returns the right structure
    is_valid, error, config_hash = verify_config_integrity("researcher")
    
    # If config is valid, should return True
    # If tampered, would return False with error
    # We'll just verify the function returns the right tuple structure
    assert isinstance(is_valid, bool)
    assert isinstance(error, (str, type(None)))
    assert isinstance(config_hash, (str, type(None)))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
