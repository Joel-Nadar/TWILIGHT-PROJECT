"""
Attestation verification for Twilight Gateway.
Verifies signatures, nonces, timestamps, and config hashes.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple
import nacl.signing
import nacl.encoding
from gateway.schemas import canonical_json
from gateway.config import settings
from gateway.db import db


def verify_signature(event: dict, public_key_hex: str) -> Tuple[bool, Optional[str]]:
    """
    Verify Ed25519 signature of an event.
    Returns (is_valid, error_message)
    """
    try:
        # Load public key
        public_key = nacl.signing.VerifyKey(public_key_hex, encoder=nacl.encoding.HexEncoder)
        
        # Extract signature
        signature_hex = event.get("signature")
        if not signature_hex:
            return False, "Missing signature"
        
        # Create canonical JSON of event excluding signature field
        event_copy = event.copy()
        event_copy.pop("signature", None)
        canonical = canonical_json(event_copy)
        
        # Verify signature
        try:
            public_key.verify(canonical.encode('utf-8'), bytes.fromhex(signature_hex))
            return True, None
        except nacl.exceptions.BadSignatureError:
            return False, "Invalid signature"
    except Exception as e:
        return False, f"Signature verification error: {str(e)}"


def check_nonce_and_timestamp(event: dict) -> Tuple[bool, Optional[str]]:
    """
    Check nonce uniqueness and timestamp freshness.
    Returns (is_valid, error_message)
    """
    # Check nonce
    nonce = event.get("nonce")
    if not nonce:
        return False, "Missing nonce"
    
    if db.nonce_exists(nonce):
        return False, "Nonce already used (replay attack)"
    
    # Check timestamp
    ts_str = event.get("ts")
    if not ts_str:
        return False, "Missing timestamp"
    
    try:
        # Parse ISO-8601 timestamp
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        
        # Check if timestamp is in the future
        if ts > now:
            return False, "Timestamp in the future"
        
        # Calculate age in seconds
        age = (now - ts).total_seconds()
        
        if age > settings.timestamp_window_sec:
            return False, f"Timestamp too old: {age}s > {settings.timestamp_window_sec}s window"
        
        return True, None
    except ValueError as e:
        return False, f"Invalid timestamp format: {str(e)}"


def verify_config_hash(agent_id: str) -> Tuple[bool, Optional[str], str]:
    """
    Verify agent config hash against the admin-signed manifest.
    The GATEWAY hashes the config file itself and compares to the manifest.
    Returns (is_valid, error_message, computed_hash)
    """
    try:
        # Get manifest from database
        manifest = db.get_manifest(agent_id)
        if not manifest:
            return False, f"No manifest found for agent {agent_id}", ""
        
        manifest_json = json.loads(manifest["manifest_json"])
        expected_hash = manifest_json.get("config_hash")
        admin_signature = manifest_json.get("admin_signature")
        
        if not expected_hash or not admin_signature:
            return False, "Invalid manifest format", ""
        
        # Hash the config file ourselves (don't trust agent's claim)
        config_path = Path(f"agents/configs/{agent_id}.json")
        if not config_path.exists():
            return False, f"Config file not found: {config_path}", ""
        
        config_content = config_path.read_text()
        computed_hash = hashlib.sha256(config_content.encode('utf-8')).hexdigest()
        
        # Compare hashes
        if computed_hash != expected_hash:
            return False, f"Config hash mismatch: expected {expected_hash}, got {computed_hash}", computed_hash
        
        # Verify admin signature on manifest
        # Load admin public key
        admin_public_key_path = Path("keys/admin_public.pem")
        if not admin_public_key_path.exists():
            return False, "Admin public key not found", computed_hash
        
        admin_public_key_hex = admin_public_key_path.read_text().strip()
        admin_verify_key = nacl.signing.VerifyKey(admin_public_key_hex, encoder=nacl.encoding.HexEncoder)
        
        # Create canonical manifest for verification
        manifest_copy = manifest_json.copy()
        manifest_copy.pop("admin_signature", None)
        canonical_manifest = canonical_json(manifest_copy)
        
        try:
            admin_verify_key.verify(
                canonical_manifest.encode('utf-8'),
                bytes.fromhex(admin_signature)
            )
        except nacl.exceptions.BadSignatureError:
            return False, "Invalid admin signature on manifest", computed_hash
        
        return True, None, computed_hash
    except Exception as e:
        return False, f"Config hash verification error: {str(e)}", ""


def insert_nonce(event: dict):
    """Insert nonce into database after successful verification"""
    nonce = event.get("nonce")
    ts = event.get("ts")
    if nonce and ts:
        db.insert_nonce(nonce, ts)
