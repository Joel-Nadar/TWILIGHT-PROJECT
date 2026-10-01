"""
Generate Ed25519 keypairs for Twilight.
Creates admin, gateway, and per-agent keys in keys/ directory.
"""
import nacl.signing
import nacl.encoding
from pathlib import Path
import json


def generate_keypair(name: str, keys_dir: Path) -> tuple[str, str]:
    """
    Generate an Ed25519 keypair.
    Returns (public_key_hex, private_key_hex)
    """
    signing_key = nacl.signing.SigningKey.generate()
    
    # Get public key
    verify_key = signing_key.verify_key
    
    # Encode as hex
    public_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    private_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    
    # Save private key
    private_key_path = keys_dir / f"{name}_private.pem"
    private_key_path.write_text(private_key_hex)
    
    # Save public key
    public_key_path = keys_dir / f"{name}_public.pem"
    public_key_path.write_text(public_key_hex)
    
    print(f"Generated keypair for {name}:")
    print(f"  Public: {public_key_path}")
    print(f"  Private: {private_key_path}")
    
    return public_key_hex, private_key_hex


def main():
    """Generate all required keypairs"""
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)
    
    print("Generating Twilight keypairs...\n")
    
    # Admin key (for signing manifests)
    admin_public, admin_private = generate_keypair("admin", keys_dir)
    
    # Gateway key (for signing audit checkpoints)
    gateway_public, gateway_private = generate_keypair("gateway", keys_dir)
    
    # Agent keys
    agents = ["researcher", "emailer", "payments"]
    agent_keys = {}
    
    for agent in agents:
        public, private = generate_keypair(agent, keys_dir)
        agent_keys[agent] = {
            "public_key": public,
            "private_key": private
        }
    
    # Save summary for reference (excluding private keys)
    summary = {
        "admin": {"public_key": admin_public},
        "gateway": {"public_key": gateway_public},
        "agents": {agent: {"public_key": keys["public_key"]} for agent, keys in agent_keys.items()}
    }
    
    summary_path = keys_dir / "key_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"\nKey summary saved to {summary_path}")
    
    print("\nWARNING: keys/ directory is gitignored. Keep these secure!")
    print("    Admin private key is required for signing manifests.")
    print("    Gateway private key is required for audit checkpoints.")
    print("    Agent private keys are required for agents to sign actions.")


if __name__ == "__main__":
    main()
