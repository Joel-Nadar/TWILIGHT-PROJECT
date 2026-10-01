"""
Sign agent manifests with admin key.
Hash each agent config, create manifest, and save trusted copy.
"""
import json
import hashlib
from pathlib import Path
import nacl.signing
import nacl.encoding


def hash_config_file(config_path: Path) -> str:
    """Hash an agent config file using SHA-256"""
    content = config_path.read_text()
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def load_admin_key(keys_dir: Path) -> nacl.signing.SigningKey:
    """Load admin private key"""
    private_key_hex = (keys_dir / "admin_private.pem").read_text().strip()
    return nacl.signing.SigningKey(private_key_hex, encoder=nacl.encoding.HexEncoder)


def main():
    """Sign all agent manifests"""
    keys_dir = Path("keys")
    configs_dir = Path("agents/configs")
    manifests_dir = Path("manifests")
    trusted_dir = Path("manifests/trusted_configs")
    
    # Create directories
    manifests_dir.mkdir(exist_ok=True)
    trusted_dir.mkdir(exist_ok=True)
    
    # Load admin key
    admin_key = load_admin_key(keys_dir)
    
    # Process each agent config
    agents = ["researcher", "emailer", "payments"]
    
    for agent in agents:
        config_path = configs_dir / f"{agent}.json"
        
        if not config_path.exists():
            print(f"Warning: Config file not found: {config_path}")
            continue
        
        # Hash config
        config_hash = hash_config_file(config_path)
        
        # Create manifest
        manifest = {
            "agent_id": agent,
            "config_hash": config_hash,
            "signed_at": "2026-10-01T12:00:00Z"  # Use actual timestamp in production
        }
        
        # Sign manifest
        manifest_json = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        signature = admin_key.sign(manifest_json.encode('utf-8'))
        signature_hex = signature.signature.hex()
        
        # Add signature to manifest
        manifest["admin_signature"] = signature_hex
        
        # Save manifest
        manifest_path = manifests_dir / f"{agent}.manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        
        # Copy pristine config to trusted directory
        trusted_config_path = trusted_dir / f"{agent}.json"
        trusted_config_path.write_text(config_path.read_text())
        
        print(f"Signed manifest for {agent}:")
        print(f"  Config hash: {config_hash}")
        print(f"  Manifest: {manifest_path}")
        print(f"  Trusted config: {trusted_config_path}")
    
    print("\nAll manifests signed successfully.")


if __name__ == "__main__":
    main()
