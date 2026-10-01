"""
Test secret redaction in audit records.
"""
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from audit.chain import append_record
from gateway.db import db


def main():
    """Test secret redaction"""
    print("=" * 60)
    print("SECRET REDACTION TEST")
    print("=" * 60)
    
    # Clear audit table
    conn = db.get_connection()
    conn.execute("DELETE FROM audit")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='audit'")
    conn.commit()
    
    # Append email with secret body
    print("\nStep 1: Appending email with SECRET-BODY-123...")
    decision = {
        "ts": "2026-10-01T12:00:00Z",
        "verdict": "ALLOW",
        "response": "allow",
        "trust_before": 100,
        "trust_after": 100,
        "status": "HEALTHY"
    }
    event = {
        "agent_id": "emailer",
        "event_id": "test-secret-1",
        "tool": "send_email",
        "args": {"to": "test@example.com", "subject": "Test", "body": "SECRET-BODY-123"}
    }
    seq = append_record(decision, event)
    print(f"  Record appended: seq={seq}")
    
    # Append payment with secret account
    print("\nStep 2: Appending payment with ACC-9999-SECRET...")
    event = {
        "agent_id": "payments",
        "event_id": "test-secret-2",
        "tool": "make_payment",
        "args": {"to_account": "ACC-9999-SECRET", "amount": 100, "memo": "Test"}
    }
    seq = append_record(decision, event)
    print(f"  Record appended: seq={seq}")
    
    # Search for secrets in database
    print("\nStep 3: Searching for SECRET-BODY-123 in audit table...")
    rows = conn.execute("SELECT * FROM audit WHERE record_json LIKE '%SECRET-BODY-123%'").fetchall()
    if rows:
        print(f"  ERROR: Found {len(rows)} records with SECRET-BODY-123 (should be redacted!)")
        for row in rows:
            print(f"    Seq {row['seq']}: {row['record_json'][:100]}...")
    else:
        print(f"  SUCCESS: SECRET-BODY-123 not found (properly redacted)")
    
    print("\nStep 4: Searching for ACC-9999-SECRET in audit table...")
    rows = conn.execute("SELECT * FROM audit WHERE record_json LIKE '%ACC-9999-SECRET%'").fetchall()
    if rows:
        print(f"  ERROR: Found {len(rows)} records with ACC-9999-SECRET (should be redacted!)")
        for row in rows:
            print(f"    Seq {row['seq']}: {row['record_json'][:100]}...")
    else:
        print(f"  SUCCESS: ACC-9999-SECRET not found (properly redacted)")
    
    # Show what the redacted records look like
    print("\nStep 5: Showing redacted audit records...")
    records = conn.execute("SELECT seq, record_json FROM audit ORDER BY seq").fetchall()
    for record in records:
        print(f"  Seq {record['seq']}: {record['record_json'][:80]}...")
    
    print("\n" + "=" * 60)
    print("SECRET REDACTION TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
