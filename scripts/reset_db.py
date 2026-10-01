"""
Reset Twilight database and register agents.
Wipes data/, recreates schema, restores configs, registers agents.
"""
import shutil
from pathlib import Path
import json
import yaml
from gateway.db import db


def main():
    """Reset database and register agents"""
    print("Resetting Twilight database...")
    
    # Wipe data directory
    data_dir = Path("data")
    if data_dir.exists():
        shutil.rmtree(data_dir)
        print(f"Removed {data_dir}")
    
    # Recreate data directory
    data_dir.mkdir(parents=True, exist_ok=True)
    print(f"Created {data_dir}")
    
    # Recreate schema
    db.create_schema()
    print("Database schema created")
    
    # Restore configs from trusted_configs
    trusted_dir = Path("manifests/trusted_configs")
    configs_dir = Path("agents/configs")
    
    if trusted_dir.exists():
        for config_file in trusted_dir.glob("*.json"):
            dest = configs_dir / config_file.name
            shutil.copy(config_file, dest)
            print(f"Restored {config_file.name} to {dest}")
    
    # Register the three agents
    agents = ["researcher", "emailer", "payments"]
    
    for agent_id in agents:
        # Load public key
        key_file = Path(f"keys/{agent_id}_public.pem")
        if not key_file.exists():
            print(f"Warning: Key file not found: {key_file}")
            continue
        
        public_key = key_file.read_text().strip()
        
        # Load policy
        policy_file = Path(f"policies/{agent_id}.yaml")
        if not policy_file.exists():
            print(f"Warning: Policy file not found: {policy_file}")
            continue
        
        with open(policy_file, 'r') as f:
            policy = f.read()
        
        # Load manifest
        manifest_file = Path(f"manifests/{agent_id}.manifest.json")
        if not manifest_file.exists():
            print(f"Warning: Manifest file not found: {manifest_file}")
            continue
        
        with open(manifest_file, 'r') as f:
            manifest = f.read()
        
        # Register agent
        db.insert_agent(agent_id, public_key, status="HEALTHY", trust_score=100)
        db.insert_manifest(
            agent_id,
            manifest,
            json.loads(manifest).get("config_hash", ""),
            json.loads(manifest).get("admin_signature", "")
        )
        
        print(f"Registered agent: {agent_id}")
    
    print("\nDatabase reset complete. Agents registered:")
    for agent_id in agents:
        agent = db.get_agent(agent_id)
        if agent:
            print(f"  {agent_id}: status={agent['status']}, trust={agent['trust_score']}")


if __name__ == "__main__":
    main()
