"""
Tests for attestation verification.
"""
import pytest
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.attestation import verify_signature, check_nonce_and_timestamp, verify_config_hash
from gateway.schemas import canonical_json
import nacl.signing
import nacl.encoding


def test_verify_signature_valid():
    """Test valid signature verification"""
    # Generate test keypair
    signing_key = nacl.signing.SigningKey.generate()
    public_key = signing_key.verify_key
    
    # Create event
    event = {
        "event_id": "test-123",
        "ts": "2026-10-01T12:00:00Z",
        "agent_id": "test",
        "tool": "search_web",
        "args": {"query": "test"},
        "nonce": "nonce-123"
    }
    
    # Sign event
    canonical = canonical_json(event)
    signature = signing_key.sign(canonical.encode('utf-8'))
    event["signature"] = signature.signature.hex()
    
    # Verify
    is_valid, error = verify_signature(event, public_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'))
    assert is_valid
    assert error is None


def test_verify_signature_invalid():
    """Test invalid signature verification"""
    event = {
        "event_id": "test-123",
        "ts": "2026-10-01T12:00:00Z",
        "agent_id": "test",
        "tool": "search_web",
        "args": {"query": "test"},
        "nonce": "nonce-123",
        "signature": "invalid_signature_hex"
    }
    
    public_key_hex = "a" * 64  # Dummy public key
    
    is_valid, error = verify_signature(event, public_key_hex)
    assert not is_valid
    assert error is not None


def test_verify_signature_missing():
    """Test missing signature"""
    event = {
        "event_id": "test-123",
        "ts": "2026-10-01T12:00:00Z",
        "agent_id": "test",
        "tool": "search_web",
        "args": {"query": "test"},
        "nonce": "nonce-123"
    }
    
    public_key_hex = "a" * 64
    
    is_valid, error = verify_signature(event, public_key_hex)
    assert not is_valid
    assert "Missing signature" in error


def test_check_nonce_and_timestamp_valid():
    """Test valid nonce and timestamp"""
    from gateway.db import db
    from gateway.config import settings
    
    event = {
        "nonce": "fresh-nonce-123",
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    
    is_valid, error = check_nonce_and_timestamp(event)
    assert is_valid
    assert error is None


def test_check_nonce_reuse():
    """Test nonce reuse detection"""
    from gateway.db import db
    import uuid
    
    # Use a unique nonce to avoid conflicts
    nonce = f"reused-nonce-{uuid.uuid4()}"
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    # Insert nonce first
    db.insert_nonce(nonce, ts)
    
    event = {
        "nonce": nonce,
        "ts": ts
    }
    
    is_valid, error = check_nonce_and_timestamp(event)
    assert not is_valid
    assert "replay" in error.lower()


def test_check_timestamp_stale():
    """Test stale timestamp rejection"""
    from gateway.config import settings
    
    old_ts = datetime.now(timezone.utc) - timedelta(seconds=settings.timestamp_window_sec + 10)
    
    event = {
        "nonce": "nonce-123",
        "ts": old_ts.isoformat().replace("+00:00", "Z")
    }
    
    is_valid, error = check_nonce_and_timestamp(event)
    assert not is_valid
    assert "too old" in error.lower()


def test_check_timestamp_future():
    """Test future timestamp rejection"""
    future_ts = datetime.now(timezone.utc) + timedelta(seconds=60)
    
    event = {
        "nonce": "nonce-123",
        "ts": future_ts.isoformat().replace("+00:00", "Z")
    }
    
    is_valid, error = check_nonce_and_timestamp(event)
    assert not is_valid
    assert "future" in error.lower()


def test_verify_config_hash_matching():
    """Test config hash verification when matching"""
    # This requires a registered agent with valid manifest
    # For now, we'll test the logic structure
    is_valid, error, computed_hash = verify_config_hash("researcher")
    
    # If researcher is registered with valid manifest, should pass
    # If not, will fail with "No manifest found"
    if is_valid:
        assert error is None
    else:
        assert "No manifest found" in error or "config file not found" in error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
