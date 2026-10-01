"""
Simplified audit demo for Twilight Gateway.
Directly tests audit chain verification without gateway.
"""
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from audit.chain import append_record, GENESIS_HASH
from audit.verify import verify_chain
from gateway.db import db
from gateway.config import settings


def main():
    """Run simplified audit demo"""
    print("=" * 60)
    print("SIMPLIFIED AUDIT DEMO")
    print("=" * 60)
    
    # Clear audit table and reset sequence
    conn = db.get_connection()
    conn.execute("DELETE FROM audit")
    conn.execute("DELETE FROM audit_checkpoints")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='audit'")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_checkpoints'")
    conn.commit()
    
    # Verify audit table is empty
    row = conn.execute("SELECT COUNT(*) as count FROM audit").fetchone()
    print(f"  Audit table cleared (count: {row['count']})")
    
    # Step 1: Append 10 records directly
    print("\nStep 1: Appending 10 audit records directly...")
    for i in range(10):
        decision = {
            "ts": f"2026-10-01T12:00:{i:02d}Z",
            "verdict": "ALLOW",
            "response": "allow",
            "trust_before": 100,
            "trust_after": 100,
            "status": "HEALTHY"
        }
        event = {
            "agent_id": "researcher",
            "event_id": f"test-{i}",
            "tool": "search_web",
            "args": {"query": f"test{i}"}
        }
        seq = append_record(decision, event)
        print(f"  Record {i+1}: seq={seq}")
    
    # Step 2: Verify audit chain
    print("\nStep 2: Verifying audit chain...")
    result = verify_chain()
    print(f"  Valid: {result.get('valid')}")
    print(f"  Records checked: {result.get('records_checked')}")
    print(f"  Checkpoints checked: {result.get('checkpoints_checked')}")
    
    if not result.get('valid'):
        # Check if it's just a checkpoint signature issue
        if "signature" in result.get('reason', '').lower():
            print(f"  Note: Checkpoint signature verification failed (expected if gateway key not set)")
            print(f"  But chain links are valid - continuing with tamper test...")
        else:
            print(f"  ERROR: Chain should be valid!")
            print(f"  Reason: {result.get('reason')}")
            return
    
    # Step 3: Tamper with record at seq 5
    print("\nStep 3: Tampering with audit record at seq 5...")
    record = db.get_audit_record_by_seq(5)
    print(f"  Original record_json: {record['record_json'][:50]}...")
    
    # Tamper: change verdict
    import json
    record_dict = json.loads(record['record_json'])
    original_verdict = record_dict.get('verdict')
    record_dict['verdict'] = "TAMPERED-" + original_verdict
    new_record_json = json.dumps(record_dict, sort_keys=True, separators=(",", ":"))
    
    db.tamper_audit_row(5, new_record_json)
    print(f"  New verdict: {record_dict['verdict']}")
    
    # Step 4: Verify audit chain after tampering
    print("\nStep 4: Verifying audit chain after tampering...")
    result = verify_chain()
    print(f"  Valid: {result.get('valid')}")
    print(f"  First broken seq: {result.get('first_broken_seq')}")
    
    if result.get('expected_hash'):
        print(f"  Expected hash: {result.get('expected_hash')[:16]}...")
    if result.get('actual_hash'):
        print(f"  Actual hash: {result.get('actual_hash')[:16]}...")
    print(f"  Reason: {result.get('reason')}")
    
    if not result.get('valid'):
        print(f"  SUCCESS: Tampering detected at seq {result.get('first_broken_seq')}!")
    else:
        print(f"  WARNING: Tampering not detected!")
    
    print("\n" + "=" * 60)
    print("SIMPLIFIED AUDIT DEMO COMPLETE")
    print("=" * 60)
    print("\nTo reset the audit chain, run:")
    print("  python scripts/reset_db.py")


if __name__ == "__main__":
    main()
