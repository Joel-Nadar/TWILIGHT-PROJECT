"""
Heartbeat verification for Twilight Gateway.
Challenge-response config integrity verification.
"""
import json
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from gateway.db import db
from gateway.config import settings
from gateway.schemas import canonical_json
import nacl.signing
import nacl.encoding
from pathlib import Path


def generate_challenge(agent_id: str) -> str:
    """Generate a fresh challenge nonce for an agent"""
    nonce = secrets.token_hex(16)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=settings.heartbeat_challenge_expire_sec)).isoformat().replace("+00:00", "Z")
    db.insert_heartbeat_challenge(agent_id, nonce, expires_at)
    return nonce


def verify_heartbeat_response(agent_id: str, nonce: str, signature: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Verify heartbeat response from agent.
    Returns (is_valid, error_message, config_hash)
    """
    # Get challenge
    challenge = db.get_heartbeat_challenge(nonce)
    if not challenge:
        return False, "Invalid or expired challenge", None
    
    # Check expiration
    expires_at = datetime.fromisoformat(challenge['expires_at'].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        db.delete_heartbeat_challenge(nonce)
        return False, "Challenge expired", None
    
    # Get agent public key
    agent = db.get_agent(agent_id)
    if not agent:
        return False, "Agent not found", None
    
    # Verify signature
    try:
        verify_key = nacl.signing.VerifyKey(agent['public_key'], encoder=nacl.encoding.HexEncoder)
        verify_key.verify(signature.encode('utf-8') + nonce.encode('utf-8'))
    except Exception:
        db.delete_heartbeat_challenge(nonce)
        return False, "Invalid signature", None
    
    # Delete challenge (single use)
    db.delete_heartbeat_challenge(nonce)
    
    # Gateway independently hashes config and verifies against manifest
    is_valid, error, config_hash = verify_config_integrity(agent_id)
    
    if not is_valid:
        return False, error, config_hash
    
    # Update last_seen
    conn = db.get_connection()
    conn.execute("""
        UPDATE agents SET last_seen = datetime('now') WHERE agent_id = ?
    """, (agent_id,))
    conn.commit()
    
    return True, None, config_hash


def verify_config_integrity(agent_id: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Gateway independently hashes agent's config and verifies against manifest.
    Returns (is_valid, error_message, config_hash)
    """
    # Load agent config
    config_path = Path(f"agents/configs/{agent_id}.json")
    if not config_path.exists():
        return False, "Config file not found", None
    
    config_content = config_path.read_text()
    config_hash = hashlib.sha256(config_content.encode('utf-8')).hexdigest()
    
    # Load manifest
    manifest_path = Path(f"manifests/{agent_id}.manifest.json")
    if not manifest_path.exists():
        return False, "Manifest not found", None
    
    manifest = json.loads(manifest_path.read_text())
    manifest_hash = manifest.get("config_hash")
    
    # Verify admin signature on manifest
    try:
        admin_key_path = Path("keys/admin_public.pem")
        if not admin_key_path.exists():
            return False, "Admin public key not found", None
        
        admin_public = admin_key_path.read_text().strip()
        verify_key = nacl.signing.VerifyKey(admin_public, encoder=nacl.encoding.HexEncoder)
        
        # Verify manifest signature
        manifest_json = json.dumps({
            "agent_id": manifest.get("agent_id"),
            "config_hash": manifest.get("config_hash"),
            "version": manifest.get("version")
        }, sort_keys=True, separators=(",", ":"))
        
        verify_key.verify(manifest.get("admin_signature").encode('utf-8') + manifest_json.encode('utf-8'))
    except Exception as e:
        return False, f"Invalid manifest signature: {str(e)}", None
    
    # Compare hashes
    if config_hash != manifest_hash:
        return False, "Config hash mismatch", config_hash
    
    return True, None, config_hash
