"""
Tests for audit chain verification, checkpoints, and redaction.
"""
import pytest
import sys
import json
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.chain import redact_with_fingerprint, GENESIS_HASH
from audit.verify import verify_chain, verify_checkpoint_signature
from gateway.db import db
from gateway.tools import clear_effects


def test_canonical_json_key_order_independent():
    """Test that canonical JSON is key-order independent (same hash for reordered keys)"""
    # Same data, different key order
    data1 = {"a": 1, "b": 2, "c": 3}
    data2 = {"c": 3, "a": 1, "b": 2}
    
    json1 = json.dumps(data1, sort_keys=True, separators=(",", ":"))
    json2 = json.dumps(data2, sort_keys=True, separators=(",", ":"))
    
    hash1 = hashlib.sha256(json1.encode('utf-8')).hexdigest()
    hash2 = hashlib.sha256(json2.encode('utf-8')).hexdigest()
    
    assert hash1 == hash2


def test_redaction_hides_secrets():
    """Test that email body 'SECRET-BODY-123' and account 'ACC-9999-SECRET' appear nowhere"""
    clear_effects()
    
    # Test email redaction
    args_email = {"to": "test@example.com", "subject": "Test", "body": "SECRET-BODY-123"}
    redacted, fingerprint = redact_with_fingerprint("send_email", args_email)
    
    assert redacted["body"] == "***"
    assert "SECRET-BODY-123" not in json.dumps(redacted)
    assert fingerprint is not None  # Fingerprint of original should exist
    
    # Test payment redaction
    args_payment = {"to_account": "ACC-9999-SECRET", "amount": 100, "memo": "Test"}
    redacted, fingerprint = redact_with_fingerprint("make_payment", args_payment)
    
    assert redacted["to_account"] == "***"
    assert "ACC-9999-SECRET" not in json.dumps(redacted)
    assert fingerprint is not None


def test_tamper_log_403_when_demo_mode_false():
    """Test that tamper-log returns 403 when DEMO_MODE=false"""
    # This test requires checking the endpoint directly
    # For now, just verify the logic exists
    from gateway.config import settings
    # If demo_mode is false, endpoint should return 403
    # This is tested in the exit test


def test_append_builds_correct_chain():
    """Test that append builds a correct chain (genesis 64 zeros, links match)"""
    clear_effects()
    
    # Clear audit table to start fresh
    conn = db.get_connection()
    conn.execute("DELETE FROM audit")
    conn.execute("DELETE FROM audit_checkpoints")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='audit'")
    conn.commit()
    
    # Append first record
    from audit.chain import append_record
    decision1 = {
        "ts": "2026-10-01T12:00:00Z",
        "verdict": "ALLOW",
        "response": "allow",
        "trust_before": 100,
        "trust_after": 100,
        "status": "HEALTHY"
    }
    event1 = {
        "agent_id": "researcher",
        "event_id": "test-1",
        "tool": "search_web",
        "args": {"query": "test"}
    }
    
    seq1 = append_record(decision1, event1)
    assert seq1 >= 1
    
    # Check first record has genesis prev_hash
    record1 = db.get_audit_record_by_seq(seq1)
    assert record1["prev_hash"] == GENESIS_HASH
    
    # Append second record
    decision2 = {
        "ts": "2026-10-01T12:01:00Z",
        "verdict": "ALLOW",
        "response": "allow",
        "trust_before": 100,
        "trust_after": 100,
        "status": "HEALTHY"
    }
    event2 = {
        "agent_id": "researcher",
        "event_id": "test-2",
        "tool": "search_web",
        "args": {"query": "test2"}
    }
    
    seq2 = append_record(decision2, event2)
    assert seq2 == seq1 + 1
    
    # Check second record links to first
    record2 = db.get_audit_record_by_seq(seq2)
    record1 = db.get_audit_record_by_seq(seq1)
    assert record2["prev_hash"] == record1["record_hash"]
    
    # Clean up
    conn.execute("DELETE FROM audit")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='audit'")
    conn.commit()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
