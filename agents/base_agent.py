"""
Base agent implementation for Twilight.
Loads Ed25519 key, builds events, signs them, and submits to gateway.
Never executes tools - treats gateway response as authoritative.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
import nacl.signing
import nacl.encoding
import httpx

from gateway.schemas import canonical_json


class BaseAgent:
    """Base agent for Twilight"""
    
    def __init__(self, agent_id: str, gateway_url: str = "http://127.0.0.1:8000"):
        self.agent_id = agent_id
        self.gateway_url = gateway_url
        
        # Load keypair
        keys_dir = Path("keys")
        private_key_path = keys_dir / f"{agent_id}_private.pem"
        public_key_path = keys_dir / f"{agent_id}_public.pem"
        
        if not private_key_path.exists():
            raise FileNotFoundError(f"Private key not found: {private_key_path}")
        
        self.private_key_hex = private_key_path.read_text().strip()
        self.public_key_hex = public_key_path.read_text().strip()
        
        self.signing_key = nacl.signing.SigningKey(
            self.private_key_hex,
            encoder=nacl.encoding.HexEncoder
        )
    
    def build_event(
        self,
        tool: str,
        args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Build an action event"""
        event = {
            "event_id": str(uuid.uuid4()),
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "agent_id": self.agent_id,
            "type": "tool_call",
            "tool": tool,
            "args": args,
            "context": context or {},
            "nonce": str(uuid.uuid4())  # Fresh nonce
        }
        
        # Sign the event (canonical JSON excluding signature field)
        canonical = canonical_json(event)
        signature = self.signing_key.sign(canonical.encode('utf-8'))
        event["signature"] = signature.signature.hex()
        
        return event
    
    async def submit_action(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Submit action to gateway and return response"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.gateway_url}/action",
                json=event,
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()
    
    async def call_tool(
        self,
        tool: str,
        args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Call a tool through the gateway"""
        event = self.build_event(tool, args, context)
        response = await self.submit_action(event)
        
        # Treat gateway response as authoritative
        if response.get("response") == "allow":
            print(f"[{self.agent_id}] Tool '{tool}' allowed: {response.get('reason')}")
            return {"success": True, "response": response}
        elif response.get("response") == "held":
            print(f"[{self.agent_id}] Tool '{tool}' held: {response.get('reason')}")
            return {"success": False, "response": response}
        else:
            print(f"[{self.agent_id}] Tool '{tool}' rejected: {response.get('reason')}")
            return {"success": False, "response": response}
    
    async def heartbeat(self) -> Dict[str, Any]:
        """Send heartbeat to gateway"""
        # Get challenge from gateway
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.gateway_url}/heartbeat/{self.agent_id}",
                json={"nonce": "initial", "signature": "placeholder"},
                timeout=30.0
            )
            # Placeholder - full heartbeat in Phase 5
            return response.json() if response.status_code == 200 else {}
