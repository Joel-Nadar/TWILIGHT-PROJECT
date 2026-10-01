"""
Twilight Gateway - FastAPI application entry point.
Runtime integrity gateway for multi-agent networks.
"""
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from pathlib import Path
import yaml
import json
from datetime import datetime

from gateway.schemas import (
    AgentRegistration, ActionEvent, Decision, HeartbeatRequest, HeartbeatResponse,
    AdminApproval, AgentInfo, VerifyChainResult, Incident, TrustHistoryEntry
)
from gateway.config import settings
from gateway.db import db
from gateway.pipeline import run_pipeline
from gateway.websocket import manager
from gateway.tools import clear_effects


# Create FastAPI app
app = FastAPI(
    title="Twilight Gateway",
    description="Runtime integrity gateway for multi-agent networks",
    version="1.0.0"
)

# Enable CORS for Vite dev origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Load policies at startup
policies = {}
manifests = {}


@app.on_event("startup")
async def startup_event():
    """Initialize database and load policies/manifests"""
    # Create database schema
    db.create_schema()
    
    # Load policies
    policy_dir = Path("policies")
    for policy_file in policy_dir.glob("*.yaml"):
        agent_id = policy_file.stem
        with open(policy_file, 'r') as f:
            policies[agent_id] = yaml.safe_load(f)
    
    # Load manifests
    manifest_dir = Path("manifests")
    for manifest_file in manifest_dir.glob("*.manifest.json"):
        agent_id = manifest_file.stem.replace(".manifest", "")
        with open(manifest_file, 'r') as f:
            manifests[agent_id] = json.load(f)
    
    print(f"Loaded {len(policies)} policies and {len(manifests)} manifests")


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Verify gateway API key for tool execution"""
    if x_api_key != settings.gateway_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return x_api_key


@app.post("/register")
async def register_agent(registration: AgentRegistration):
    """Register a new agent with the gateway"""
    # Validate policy YAML
    try:
        policy_data = yaml.safe_load(registration.policy)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid policy YAML: {str(e)}")
    
    # Validate manifest JSON
    try:
        manifest_data = json.loads(registration.manifest)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid manifest JSON: {str(e)}")
    
    # Store manifest in database
    db.insert_manifest(
        registration.agent_id,
        registration.manifest,
        manifest_data.get("config_hash", ""),
        manifest_data.get("admin_signature", "")
    )
    
    # Register agent
    db.insert_agent(
        registration.agent_id,
        registration.public_key,
        status="HEALTHY",
        trust_score=100
    )
    
    # Load policy
    policies[registration.agent_id] = policy_data
    manifests[registration.agent_id] = manifest_data
    
    return {
        "status": "registered",
        "agent_id": registration.agent_id,
        "trust_score": 100,
        "status": "HEALTHY"
    }


@app.post("/action", response_model=Decision)
async def submit_action(event: ActionEvent, x_api_key: Optional[str] = Header(None)):
    """Submit an agent action for validation and execution"""
    # Run pipeline
    decision = run_pipeline(event.model_dump(), x_api_key or "")
    return decision


@app.get("/agents")
async def list_agents():
    """List all registered agents"""
    agents = db.get_all_agents()
    
    return {
        "agents": [
            {
                "agent_id": a["agent_id"],
                "status": a["status"],
                "trust_score": a["trust_score"],
                "last_seen": a["last_seen"],
                "current_rate_limit": a.get("current_rate_limit"),
                "config_hash_state": a.get("config_hash_state", "matched"),
                "probation_until": a.get("probation_until")
            }
            for a in agents
        ]
    }


@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get detailed information about a specific agent"""
    agent = db.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    trust_history = db.get_trust_history(agent_id)
    
    return {
        "agent_id": agent["agent_id"],
        "status": agent["status"],
        "trust_score": agent["trust_score"],
        "last_seen": agent["last_seen"],
        "current_rate_limit": agent.get("current_rate_limit"),
        "config_hash_state": agent.get("config_hash_state", "matched"),
        "probation_until": agent.get("probation_until"),
        "trust_history": [
            {
                "ts": h["ts"],
                "score": h["score"],
                "reason": h["reason"]
            }
            for h in trust_history
        ]
    }


@app.get("/audit")
async def get_audit(agent_id: Optional[str] = None, limit: int = 100):
    """Get audit records (redacted)"""
    records = db.get_audit_records(agent_id, limit)
    return {"records": records}


@app.get("/audit/verify", response_model=VerifyChainResult)
async def verify_audit_chain():
    """Verify the integrity of the audit chain"""
    # Placeholder for Phase 4
    return VerifyChainResult(
        valid=True,
        first_broken_seq=None,
        expected_hash=None,
        actual_hash=None
    )


@app.get("/incidents")
async def get_incidents(agent_id: Optional[str] = None, resolved: Optional[bool] = None):
    """Get security incidents"""
    incidents = db.get_incidents(agent_id, resolved)
    return {"incidents": incidents}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for live updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive (client sends pings)
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/config")
async def get_config():
    """Get current gateway configuration thresholds"""
    return {
        "trust_healthy_min": settings.trust_healthy_min,
        "trust_flag_min": settings.trust_flag_min,
        "trust_throttle_min": settings.trust_throttle_min,
        "trust_recovery_per_min": settings.trust_recovery_per_min,
        "trust_hysteresis": settings.trust_hysteresis,
        "probation_start_score": settings.probation_start_score,
        "probation_cap": settings.probation_cap,
        "probation_clean_min": settings.probation_clean_min,
        "rate_window_sec": settings.rate_window_sec,
        "rate_halt_after_violations": settings.rate_halt_after_violations,
        "drift_zscore_threshold": settings.drift_zscore_threshold
    }
