"""
Phase 1 tests: Verify schemas import and DB creates cleanly.
"""
import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_schemas_import():
    """Test that all schema models can be imported"""
    from gateway.schemas import (
        Verdict, AgentStatus, Severity,
        AgentRegistration, ActionEvent, Decision,
        HeartbeatRequest, HeartbeatResponse,
        AdminApproval, AuditRecord, Incident,
        AgentInfo, TrustHistoryEntry,
        VerifyChainResult, WebSocketMessage,
        PolicyConfig, canonical_json
    )
    
    # Test enum values
    assert Verdict.ALLOW.value == "ALLOW"
    assert Verdict.BLOCK.value == "BLOCK"
    assert AgentStatus.HEALTHY.value == "HEALTHY"
    assert AgentStatus.QUARANTINED.value == "QUARANTINED"
    assert Severity.CRITICAL.value == "CRITICAL"
    
    # Test canonical JSON
    data = {"b": 2, "a": 1}
    canonical = canonical_json(data)
    assert canonical == '{"a":1,"b":2}'


def test_config_import():
    """Test that config module imports"""
    from gateway.config import settings
    
    assert settings.gateway_host == "127.0.0.1"
    assert settings.gateway_port == 8000
    assert settings.db_path == "data/twilight.db"
    assert settings.fail_mode == "closed"
    assert settings.demo_mode == True


def test_db_create_schema():
    """Test that database schema creates cleanly"""
    from gateway.db import Database
    import tempfile
    import os
    
    # Use temp database
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = Database(db_path)
        
        # Create schema
        db.create_schema()
        
        # Verify tables exist
        conn = db.get_connection()
        tables = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
        """).fetchall()
        
        table_names = [t["name"] for t in tables]
        
        expected_tables = [
            "agents", "manifests", "events", "audit", "audit_checkpoints",
            "incidents", "nonces", "trust_history", "held_actions", "baselines"
        ]
        
        for table in expected_tables:
            assert table in table_names, f"Table {table} not found"
        
        # Verify indexes exist
        indexes = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='index'
        """).fetchall()
        index_names = [i["name"] for i in indexes]
        
        # Check a few key indexes
        assert "idx_events_agent_id" in index_names
        assert "idx_events_ts" in index_names
        assert "idx_audit_agent_id" in index_names
        
        db.close()


def test_pydantic_validation():
    """Test Pydantic model validation"""
    from gateway.schemas import ActionEvent, AgentRegistration
    from datetime import datetime
    
    # Test valid ActionEvent
    event = ActionEvent(
        ts="2026-10-01T12:00:00Z",
        agent_id="researcher",
        tool="search_web",
        args={"query": "test"},
        nonce="abc123",
        signature="xyz789"
    )
    assert event.agent_id == "researcher"
    assert event.tool == "search_web"
    
    # Test invalid timestamp
    with pytest.raises(ValueError):
        ActionEvent(
            ts="invalid-timestamp",
            agent_id="researcher",
            tool="search_web",
            args={"query": "test"},
            nonce="abc123",
            signature="xyz789"
        )
    
    # Test valid AgentRegistration
    reg = AgentRegistration(
        agent_id="researcher",
        public_key="abc123",
        policy="agent: researcher\nversion: 1",
        manifest="{}",
        config_path="agents/configs/researcher.json"
    )
    assert reg.agent_id == "researcher"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
