"""
Audit demo script for Twilight Gateway.
Runs normal actions, verifies audit chain, demonstrates tamper detection.
"""
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import httpx
import json
import time
from datetime import datetime, timezone


def sign_event(event: dict, agent_id: str) -> dict:
    """Sign an event with agent private key"""
    from gateway.schemas import canonical_json
    import nacl.signing
    import nacl.encoding
    from pathlib import Path
    
    # Load agent private key
    key_file = Path(f"keys/{agent_id}_private.pem")
    if not key_file.exists():
        raise FileNotFoundError(f"Key file not found: {key_file}")
    
    private_key = key_file.read_text().strip()
    signing_key = nacl.signing.SigningKey(private_key, encoder=nacl.encoding.HexEncoder)
    
    # Canonical JSON and sign
    canonical = canonical_json(event)
    signature = signing_key.sign(canonical.encode('utf-8'))
    event["signature"] = signature.signature.hex()
    
    return event


def send_action(agent_id: str, tool: str, args: dict) -> dict:
    """Send an action to the gateway"""
    event = {
        "event_id": f"demo-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent_id": agent_id,
        "tool": tool,
        "args": args,
        "nonce": f"nonce-{datetime.now(timezone.utc).timestamp()}",
        "type": "tool_call"
    }
    
    # Sign event
    event = sign_event(event, agent_id)
    
    # Send to gateway
    try:
        response = httpx.post(
            "http://127.0.0.1:8000/action",
            json=event,
            headers={"X-API-Key": "change-me"},
            timeout=5.0
        )
        return response.json()
    except Exception as e:
        return {"error": str(e), "response": "error"}


def main():
    """Run audit demo"""
    print("=" * 60)
    print("AUDIT DEMO")
    print("=" * 60)
    
    # Step 1: Run 10 normal actions
    print("\nStep 1: Running 10 normal actions...")
    for i in range(10):
        result = send_action("researcher", "search_web", {"query": f"test-{i}"})
        print(f"  Action {i+1}: {result.get('response', 'error')}")
        time.sleep(0.1)
    
    # Step 2: Verify audit chain (should be valid)
    print("\nStep 2: Verifying audit chain...")
    response = httpx.get("http://127.0.0.1:8000/audit/verify")
    verify_result = response.json()
    print(f"  Valid: {verify_result.get('valid')}")
    print(f"  Records checked: {verify_result.get('records_checked')}")
    print(f"  Checkpoints checked: {verify_result.get('checkpoints_checked')}")
    
    if not verify_result.get('valid'):
        print(f"  ERROR: Chain should be valid!")
        print(f"  Reason: {verify_result.get('reason')}")
        return
    
    # Step 3: Tamper with audit record at seq 5
    print("\nStep 3: Tampering with audit record at seq 5...")
    response = httpx.post("http://127.0.0.1:8000/admin/tamper-log/5")
    tamper_result = response.json()
    print(f"  Message: {tamper_result.get('message')}")
    print(f"  Original verdict: {tamper_result.get('original_verdict')}")
    print(f"  New verdict: {tamper_result.get('new_verdict')}")
    
    # Step 4: Verify audit chain (should be invalid)
    print("\nStep 4: Verifying audit chain after tampering...")
    response = httpx.get("http://127.0.0.1:8000/audit/verify")
    verify_result = response.json()
    print(f"  Valid: {verify_result.get('valid')}")
    print(f"  First broken seq: {verify_result.get('first_broken_seq')}")
    
    if verify_result.get('expected_hash'):
        print(f"  Expected hash: {verify_result.get('expected_hash')[:16]}...")
    if verify_result.get('actual_hash'):
        print(f"  Actual hash: {verify_result.get('actual_hash')[:16]}...")
    print(f"  Reason: {verify_result.get('reason')}")
    
    if verify_result.get('valid'):
        print(f"  WARNING: Chain should be invalid after tampering!")
    else:
        print(f"  SUCCESS: Tampering detected!")
    
    print("\n" + "=" * 60)
    print("AUDIT DEMO COMPLETE")
    print("=" * 60)
    print("\nTo reset the tampered audit chain, run:")
    print("  python scripts/reset_db.py")


if __name__ == "__main__":
    main()
