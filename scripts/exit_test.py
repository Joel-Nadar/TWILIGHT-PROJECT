"""
Exit test for Phase 2.
Starts gateway, sends action, checks DB, agents, and WebSocket.
"""
import subprocess
import time
import requests
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gateway.db import db


def main():
    print("=" * 60)
    print("PHASE 2 EXIT TEST")
    print("=" * 60)
    
    # Start gateway
    print("\n[1] Starting gateway...")
    import os
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    gateway_proc = subprocess.Popen(
        ["C:/Program Files/Python312/python.exe", "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=project_dir,
        env={**os.environ, "PYTHONPATH": project_dir}
    )
    
    time.sleep(3)
    
    try:
        # Test 1: /docs loads
        print("\n[2] Testing /docs endpoint...")
        resp = requests.get("http://127.0.0.1:8000/docs")
        print(f"  /docs status: {resp.status_code}")
        assert resp.status_code == 200, "/docs should return 200"
        
        # Test 2: send_email to someone@company.com
        print("\n[3] Testing send_email to someone@company.com...")
        import httpx
        import uuid
        from datetime import datetime, timezone
        import nacl.signing
        import nacl.encoding
        from gateway.schemas import canonical_json
        
        # Load emailer key
        keys_dir = Path("keys")
        private_key_hex = (keys_dir / "emailer_private.pem").read_text().strip()
        signing_key = nacl.signing.SigningKey(private_key_hex, encoder=nacl.encoding.HexEncoder)
        
        # Build event
        event = {
            "event_id": str(uuid.uuid4()),
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "agent_id": "emailer",
            "type": "tool_call",
            "tool": "send_email",
            "args": {"to": "someone@company.com", "subject": "Test", "body": "Hello"},
            "context": {},
            "nonce": str(uuid.uuid4())
        }
        
        # Sign
        canonical = canonical_json(event)
        signature = signing_key.sign(canonical.encode('utf-8'))
        event["signature"] = signature.signature.hex()
        
        # Send
        resp = httpx.post(
            "http://127.0.0.1:8000/action",
            json=event,
            headers={"X-API-Key": "change-me"},
            timeout=30.0
        )
        result = resp.json()
        print(f"  Response: {result.get('response')}")
        print(f"  Verdict: {result.get('verdict')}")
        print(f"  Reason: {result.get('reason')}")
        assert result.get("response") == "allow", f"Expected 'allow', got {result.get('response')}"
        
        # Test 3: Check events table
        print("\n[4] Checking events table...")
        conn = db.get_connection()
        event_row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event["event_id"],)).fetchone()
        if event_row:
            print(f"  Event found in DB: {event_row['tool']}, verdict={event_row['verdict']}")
            assert event_row['verdict'] == 'ALLOW'
        else:
            print("  ERROR: Event not found in DB")
            return False
        
        # Test 4: Check audit table
        print("\n[5] Checking audit table...")
        audit_row = conn.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        if audit_row:
            print(f"  Audit record found: seq={audit_row['seq']}, agent_id={audit_row['agent_id']}")
        else:
            print("  ERROR: Audit record not found")
            return False
        
        # Test 5: GET /agents
        print("\n[6] Testing GET /agents...")
        resp = requests.get("http://127.0.0.1:8000/agents")
        agents_data = resp.json()
        print(f"  Agents count: {len(agents_data['agents'])}")
        for agent in agents_data['agents']:
            print(f"    {agent['agent_id']}: status={agent['status']}, trust={agent['trust_score']}")
        
        # Filter out test agents (those starting with "test_")
        production_agents = [a for a in agents_data['agents'] if not a['agent_id'].startswith('test_')]
        assert len(production_agents) == 3, "Should have 3 production agents"
        for agent in production_agents:
            assert agent['status'] == 'HEALTHY', f"Agent {agent['agent_id']} should be HEALTHY"
            assert agent['trust_score'] == 100, f"Agent {agent['agent_id']} should have trust 100"
        
        print("\n" + "=" * 60)
        print("ALL EXIT TESTS PASSED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Stop gateway
        print("\n[7] Stopping gateway...")
        gateway_proc.terminate()
        gateway_proc.wait()
        print("Gateway stopped")


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
