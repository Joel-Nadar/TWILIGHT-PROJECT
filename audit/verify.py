"""
Audit chain verification for Twilight Gateway.
Detects tampering, breaks in chain, invalid checkpoints.
"""
import json
import hashlib
from typing import Dict, Any, Optional
from pathlib import Path
import nacl.signing
import nacl.encoding
from gateway.db import db


GENESIS_HASH = "0" * 64


def verify_chain() -> Dict[str, Any]:
    """
    Verify the audit chain from genesis.
    Returns verification result with details.
    
    Detects:
    - edited record_json (hash mismatch)
    - altered prev_hash or broken link
    - wrong genesis
    - missing or reordered sequence numbers (gaps)
    - invalid checkpoint signature
    - checkpoint seq/record_hash mismatch
    - truncation (checkpoint beyond last record)
    """
    # Get all audit records (sort by seq ASC for verification)
    records = db.get_audit_records()
    records = sorted(records, key=lambda r: r["seq"])
    
    if not records:
        return {
            "valid": True,
            "records_checked": 0,
            "first_broken_seq": None,
            "expected_hash": None,
            "actual_hash": None,
            "reason": "No records to verify (empty chain)",
            "checkpoints_checked": 0
        }
    
    # Get checkpoints
    checkpoints = db.get_checkpoints()
    checkpoint_map = {cp["seq"]: cp for cp in checkpoints}
    
    # Verify genesis
    first_record = records[0]
    if first_record["prev_hash"] != GENESIS_HASH:
        return {
            "valid": False,
            "records_checked": 1,
            "first_broken_seq": first_record["seq"],
            "expected_hash": GENESIS_HASH,
            "actual_hash": first_record["prev_hash"],
            "reason": "Genesis hash mismatch",
            "checkpoints_checked": 0
        }
    
    # Walk the chain
    prev_hash = GENESIS_HASH
    prev_seq = 0
    
    for record in records:
        seq = record["seq"]
        record_json = record["record_json"]
        stored_hash = record["record_hash"]
        
        # Check sequence continuity
        if seq != prev_seq + 1:
            return {
                "valid": False,
                "records_checked": seq,
                "first_broken_seq": seq,
                "expected_hash": None,
                "actual_hash": None,
                "reason": f"Sequence gap: expected {prev_seq + 1}, got {seq}",
                "checkpoints_checked": len([cp for cp in checkpoints if cp["seq"] < seq])
            }
        
        # Verify hash chain
        computed_hash = hashlib.sha256((prev_hash + record_json).encode("utf-8")).hexdigest()
        if computed_hash != stored_hash:
            return {
                "valid": False,
                "records_checked": seq,
                "first_broken_seq": seq,
                "expected_hash": computed_hash,
                "actual_hash": stored_hash,
                "reason": f"Hash mismatch at seq {seq}",
                "checkpoints_checked": len([cp for cp in checkpoints if cp["seq"] < seq])
            }
        
        # Verify prev_hash link
        if record["prev_hash"] != prev_hash:
            return {
                "valid": False,
                "records_checked": seq,
                "first_broken_seq": seq,
                "expected_hash": prev_hash,
                "actual_hash": record["prev_hash"],
                "reason": f"Broken chain link at seq {seq}",
                "checkpoints_checked": len([cp for cp in checkpoints if cp["seq"] < seq])
            }
        
        # Verify checkpoint if exists for this seq
        if seq in checkpoint_map:
            checkpoint = checkpoint_map[seq]
            
            # Verify checkpoint record_hash matches
            if checkpoint["record_hash"] != stored_hash:
                return {
                    "valid": False,
                    "records_checked": seq,
                    "first_broken_seq": seq,
                    "expected_hash": stored_hash,
                    "actual_hash": checkpoint["record_hash"],
                    "reason": f"Checkpoint hash mismatch at seq {seq}",
                    "checkpoints_checked": len([cp for cp in checkpoints if cp["seq"] <= seq])
                }
            
            # Verify checkpoint signature
            if not verify_checkpoint_signature(seq, checkpoint["record_hash"], checkpoint["signature"]):
                return {
                    "valid": False,
                    "records_checked": seq,
                    "first_broken_seq": seq,
                    "expected_hash": None,
                    "actual_hash": None,
                    "reason": f"Invalid checkpoint signature at seq {seq}",
                    "checkpoints_checked": len([cp for cp in checkpoints if cp["seq"] <= seq])
                }
        
        prev_hash = stored_hash
        prev_seq = seq
    
    # Check for truncation (checkpoint beyond last record)
    last_seq = records[-1]["seq"]
    for checkpoint in checkpoints:
        if checkpoint["seq"] > last_seq:
            return {
                "valid": False,
                "records_checked": last_seq,
                "first_broken_seq": checkpoint["seq"],
                "expected_hash": f"Record at seq {checkpoint['seq']}",
                "actual_hash": "No record (truncation)",
                "reason": f"Checkpoint beyond last record: checkpoint seq {checkpoint['seq']} > last seq {last_seq}",
                "checkpoints_checked": len(checkpoints)
            }
    
    return {
        "valid": True,
        "records_checked": len(records),
        "first_broken_seq": None,
        "expected_hash": None,
        "actual_hash": None,
        "reason": None,
        "checkpoints_checked": len(checkpoints)
    }


def verify_checkpoint_signature(seq: int, record_hash: str, signature: str) -> bool:
    """
    Verify checkpoint signature with gateway public key.
    Returns True if valid, False otherwise.
    """
    from pathlib import Path
    
    # Load gateway public key
    keys_dir = Path("keys")
    gateway_public = (keys_dir / "gateway_public.pem").read_text().strip()
    verify_key = nacl.signing.VerifyKey(gateway_public, encoder=nacl.encoding.HexEncoder)
    
    # Build checkpoint data
    checkpoint_data = {"seq": seq, "record_hash": record_hash}
    checkpoint_json = json.dumps(checkpoint_data, sort_keys=True, separators=(",", ":"))
    
    # Verify signature
    try:
        verify_key.verify(signature.encode('utf-8') + checkpoint_json.encode('utf-8'))
        return True
    except Exception:
        return False
