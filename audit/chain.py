"""
Audit chain for Twilight Gateway.
Basic append_record implementation (verifier and checkpoints in Phase 4).
"""
import json
import hashlib
from datetime import datetime
from datetime import timezone
from typing import Dict, Any
from gateway.schemas import canonical_json
from gateway.db import db


GENESIS_HASH = "0" * 64


def append_record(decision: Dict[str, Any], event: Dict[str, Any]) -> int:
    """
    Append an audit record to the chain.
    Returns the sequence number.
    
    Record contains: ts, agent_id, event_id, tool, redacted args,
    verdict, response, reason, rule, severity, trust_before, trust_after, status.
    """
    # Get previous hash
    last_seq = db.get_last_audit_seq()
    if last_seq == 0:
        prev_hash = GENESIS_HASH
    else:
        # Get the last record's hash
        last_records = db.get_audit_records(limit=1)
        if last_records:
            prev_hash = last_records[0]["record_hash"]
        else:
            prev_hash = GENESIS_HASH
    
    # Build redacted record
    from gateway.tools import redact_args
    redacted_args = redact_args(event.get("tool", ""), event.get("args", {}))
    
    record = {
        "ts": decision.get("ts", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
        "agent_id": event.get("agent_id"),
        "event_id": event.get("event_id"),
        "tool": event.get("tool"),
        "args": redacted_args,
        "verdict": decision.get("verdict"),
        "response": decision.get("response"),
        "reason": decision.get("reason"),
        "rule": decision.get("rule"),
        "severity": decision.get("severity"),
        "trust_before": decision.get("trust_before"),
        "trust_after": decision.get("trust_after"),
        "status": decision.get("status")
    }
    
    # Canonical JSON
    record_json = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    
    # Compute hash: SHA-256(prev_hash + record_json)
    record_hash = hashlib.sha256((prev_hash + record_json).encode("utf-8")).hexdigest()
    
    # Append to database
    seq = db.append_audit_record({
        "timestamp": record["ts"],
        "agent_id": record["agent_id"],
        "record_json": record_json,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
        "signature": None  # Checkpoints in Phase 4
    })
    
    return seq
