"""
Quick test client for Twilight Gateway.
Signs and sends one event for testing.
"""
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import asyncio
import httpx
import json
import uuid
from datetime import datetime, timezone
import nacl.signing
import nacl.encoding

from gateway.schemas import canonical_json


async def send_test_event(agent_id: str, tool: str, args: dict):
    """Send a test event to the gateway"""
    gateway_url = "http://127.0.0.1:8000"
    
    # Load agent key
    keys_dir = Path("keys")
    private_key_path = keys_dir / f"{agent_id}_private.pem"
    
    if not private_key_path.exists():
        print(f"Error: Key file not found: {private_key_path}")
        return
    
    private_key_hex = private_key_path.read_text().strip()
    signing_key = nacl.signing.SigningKey(private_key_hex, encoder=nacl.encoding.HexEncoder)
    
    # Build event
    event = {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent_id": agent_id,
        "type": "tool_call",
        "tool": tool,
        "args": args,
        "context": {},
        "nonce": str(uuid.uuid4())
    }
    
    # Sign event
    canonical = canonical_json(event)
    signature = signing_key.sign(canonical.encode('utf-8'))
    event["signature"] = signature.signature.hex()
    
    print(f"Sending event: {tool} with args {args}")
    print(f"Event ID: {event['event_id']}")
    
    # Send to gateway
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{gateway_url}/action",
                json=event,
                headers={"X-API-Key": "change-me"},  # Gateway API key
                timeout=30.0
            )
            response.raise_for_status()
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
            return result
        except httpx.HTTPError as e:
            print(f"Error: {e}")
            return None


async def main():
    """Main test function"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python test_client.py <agent_id> <tool> [args as JSON]")
        print("Example: python test_client.py emailer send_email '{\"to\":\"someone@company.com\",\"subject\":\"Test\",\"body\":\"Hello\"}'")
        return
    
    agent_id = sys.argv[1]
    tool = sys.argv[2]
    args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    
    await send_test_event(agent_id, tool, args)


if __name__ == "__main__":
    asyncio.run(main())
