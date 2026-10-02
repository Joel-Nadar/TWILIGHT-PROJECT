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
    AdminApproval, AgentInfo, VerifyChainResult, Incident, TrustHistoryEntry,
    RestoreStepResult, RestoreResult, RuntimeMode
)
from gateway.pipeline import run_pipeline, load_agent_policy
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
    """Initialize database, load policies/manifests, start background tasks"""
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
    
    # Start background tasks
    from gateway.background import start_background_tasks
    await start_background_tasks(app)


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks"""
    from gateway.background import stop_background_tasks
    await stop_background_tasks(app)
    
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
    # Check runtime mode
    if settings.runtime_mode == "off":
        return Decision(
            verdict=Verdict.BLOCK,
            response="blocked",
            reason="Gateway is in OFF mode - no actions processed",
            rule="runtime_mode.off",
            severity=Severity.MEDIUM,
            trust_before=None,
            trust_after=None,
            status=None,
            evidence={},
            latency_ms=0
        )
    
    # Run pipeline
    decision = run_pipeline(event.model_dump(), x_api_key or "", settings.runtime_mode)
    return decision


@app.get("/agents")
async def list_agents():
    """List all registered agents with status, trust, history, etc."""
    agents = db.get_agents_with_history()
    
    result = []
    for agent in agents:
        result.append({
            "agent_id": agent['agent_id'],
            "status": agent['status'],
            "trust_score": agent['trust_score'],
            "last_seen": agent['last_seen'],
            "config_hash_ok": agent['config_hash_state'] == 'matched',
            "probation_until": agent['probation_until'],
            "effective_rate_limit": agent['current_rate_limit'],
            "trust_history": agent['trust_history']
        })
    
    return {"agents": result}


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


@app.post("/admin/approve/{event_id}")
async def approve_held_action(event_id: str, approval: AdminApproval):
    """Approve or reject a held action"""
    held_action = db.get_held_action(event_id)
    if not held_action:
        raise HTTPException(status_code=404, detail="Held action not found")
    
    # Check if already decided
    if held_action["status"] != "PENDING":
        return {
            "status": held_action["status"].lower(),
            "event_id": event_id,
            "executed": held_action["status"] == "APPROVED"
        }
    
    import json
    event = json.loads(held_action["event_json"])
    
    if approval.approved:
        # Execute tool
        from gateway.tools import execute_tool
        tool_result = execute_tool(
            event.get("tool"),
            event.get("args", {}),
            event.get("event_id"),
            settings.gateway_api_key
        )
        
        db.update_held_action_status(event_id, "APPROVED")
        
        return {
            "status": "approved",
            "event_id": event_id,
            "executed": tool_result["success"]
        }
    else:
        # Reject and apply penalty
        db.update_held_action_status(event_id, "REJECTED")
        
        # Apply penalty
        agent = db.get_agent(event["agent_id"])
        if agent:
            from engine.policy import load_agent_policy
            from engine.trust import apply_penalty, status_for_score, apply_trust_update
            policy = load_agent_policy(event["agent_id"])
            new_score = apply_penalty(agent["trust_score"], "held_action_rejected", policy)
            new_status = status_for_score(new_score, agent["status"])
            apply_trust_update(event["agent_id"], new_score, new_status, "held_action_rejected")
        
        return {
            "status": "rejected",
            "event_id": event_id,
            "executed": False,
            "penalty_applied": True
        }


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


@app.get("/audit")
async def get_audit(limit: int = 100, offset: int = 0, agent_id: Optional[str] = None):
    """Get audit records with optional filtering"""
    records = db.get_audit_records(agent_id=agent_id, limit=limit)
    
    # Apply offset (for newest-first pagination)
    if offset > 0:
        records = records[offset:]
    
    # Sort newest-first (reverse by seq)
    records = list(reversed(records))
    
    return {
        "records": records,
        "count": len(records)
    }


@app.get("/audit/verify", response_model=VerifyChainResult)
async def verify_audit_chain():
    """Verify the audit chain integrity"""
    from audit.verify import verify_chain
    return verify_chain()


@app.post("/admin/tamper-log/{seq}")
async def tamper_audit_log(seq: int):
    """
    DEMO ONLY: Directly edit an audit record to demonstrate verification failure.
    Only works when DEMO_MODE=true.
    """
    if not settings.demo_mode:
        raise HTTPException(status_code=403, detail="Tamper-log endpoint only available in DEMO_MODE")
    
    # Get current record
    record = db.get_audit_record_by_seq(seq)
    if not record:
        raise HTTPException(status_code=404, detail=f"Audit record seq {seq} not found")
    
    # Modify the record (e.g., change verdict text)
    import json
    record_dict = json.loads(record["record_json"])
    record_dict["verdict"] = "TAMPERED-" + record_dict.get("verdict", "")
    new_record_json = json.dumps(record_dict, sort_keys=True, separators=(",", ":"))
    
    # Direct edit (bypass normal chain)
    db.tamper_audit_row(seq, new_record_json)
    
    return {
        "message": f"Audit record seq {seq} tampered with demo endpoint",
        "seq": seq,
        "original_verdict": record_dict.get("verdict").replace("TAMPERED-", ""),
        "new_verdict": record_dict["verdict"]
    }


@app.post("/heartbeat/{agent_id}")
async def heartbeat(agent_id: str, request: Optional[HeartbeatRequest] = None):
    """
    Heartbeat challenge-response for config integrity verification.
    First call (empty body): returns fresh challenge nonce.
    Second call (with nonce+signature): verifies response and config hash.
    """
    from engine.heartbeat import generate_challenge, verify_heartbeat_response
    from engine.enforcer import write_incident
    from gateway.schemas import Severity, AgentStatus
    from datetime import datetime, timezone
    
    # Get agent
    agent = db.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Empty request or no nonce/signature: generate challenge
    if not request or (not request.nonce and not request.signature):
        challenge = generate_challenge(agent_id)
        return HeartbeatResponse(challenge_nonce=challenge, config_hash=None)
    
    # Response: verify
    is_valid, error, config_hash = verify_heartbeat_response(agent_id, request.nonce, request.signature)
    
    if not is_valid:
        # Config mismatch: quarantine agent
        if "mismatch" in error.lower():
            # Set status QUARANTINED, trust unchanged
            conn = db.get_connection()
            conn.execute("""
                UPDATE agents SET status = 'QUARANTINED', config_hash_state = 'mismatch' WHERE agent_id = ?
            """, (agent_id,))
            conn.commit()
            
            # Create incident
            write_incident(
                agent_id,
                Severity.CRITICAL,
                f"Config hash mismatch: {error}",
                db.get_connection()
            )
            
            # Audit record
            from audit.chain import append_record
            decision = {
                "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "verdict": "QUARANTINE",
                "response": "quarantined",
                "reason": f"Config hash mismatch: {error}",
                "rule": "heartbeat.config_mismatch",
                "severity": Severity.CRITICAL,
                "trust_before": agent['trust_score'],
                "trust_after": agent['trust_score'],  # Unchanged
                "status": AgentStatus.QUARANTINED
            }
            append_record(decision, {"agent_id": agent_id, "event_id": f"heartbeat-{datetime.now(timezone.utc).timestamp()}", "tool": "heartbeat", "args": {}})
            
            # Publish status and incident
            await manager.publish({
                "type": "status",
                "data": {"agent_id": agent_id, "status": "QUARANTINED", "reason": error}
            })
            await manager.publish({
                "type": "incident",
                "data": {"agent_id": agent_id, "severity": "CRITICAL", "summary": f"Config hash mismatch: {error}"}
            })
        
        raise HTTPException(status_code=403, detail=error)
    
    return HeartbeatResponse(challenge_nonce=None, config_hash=config_hash)


@app.post("/admin/halt/{agent_id}")
async def halt_agent(agent_id: str):
    """Set agent status to HALTED (idempotent)"""
    agent = db.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Set status HALTED
    conn = db.get_connection()
    conn.execute("UPDATE agents SET status = 'HALTED' WHERE agent_id = ?", (agent_id,))
    conn.commit()
    
    return {"status": "halted", "agent_id": agent_id}


@app.post("/admin/restore/{agent_id}")
async def restore_agent(agent_id: str):
    """
    Restore agent from tampered config.
    Steps: verify manifest signature, copy pristine config, re-hash, compare.
    Returns per-step results.
    """
    from engine.heartbeat import verify_config_integrity
    from gateway.schemas import RestoreStepResult, RestoreResult
    from datetime import datetime, timezone
    import shutil
    import os
    
    steps = []
    agent = db.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Step 1: Verify manifest signature
    try:
        is_valid, error, _ = verify_config_integrity(agent_id)
        if not is_valid:
            steps.append(RestoreStepResult(step="verify_manifest", success=False, details=error))
            return RestoreResult(agent_id=agent_id, steps=steps, overall_success=False)
        steps.append(RestoreStepResult(step="verify_manifest", success=True, details=None))
    except Exception as e:
        steps.append(RestoreStepResult(step="verify_manifest", success=False, details=str(e)))
        return RestoreResult(agent_id=agent_id, steps=steps, overall_success=False)
    
    # Step 2: Copy pristine config from trusted_configs
    try:
        src = Path(f"manifests/trusted_configs/{agent_id}.json")
        dst = Path(f"agents/configs/{agent_id}.json.tmp")
        final = Path(f"agents/configs/{agent_id}.json")
        
        if not src.exists():
            steps.append(RestoreStepResult(step="copy_config", success=False, details="Trusted config not found"))
            return RestoreResult(agent_id=agent_id, steps=steps, overall_success=False)
        
        shutil.copy(src, dst)
        # Atomic replace
        if final.exists():
            os.replace(dst, final)
        else:
            shutil.move(dst, final)
        
        steps.append(RestoreStepResult(step="copy_config", success=True, details=None))
    except Exception as e:
        steps.append(RestoreStepResult(step="copy_config", success=False, details=str(e)))
        return RestoreResult(agent_id=agent_id, steps=steps, overall_success=False)
    
    # Step 3: Re-hash config
    try:
        import hashlib
        config_path = Path(f"agents/configs/{agent_id}.json")
        config_content = config_path.read_text()
        config_hash = hashlib.sha256(config_content.encode('utf-8')).hexdigest()
        steps.append(RestoreStepResult(step="rehash_config", success=True, details=None))
    except Exception as e:
        steps.append(RestoreStepResult(step="rehash_config", success=False, details=str(e)))
        return RestoreResult(agent_id=agent_id, steps=steps, overall_success=False)
    
    # Step 4: Compare with manifest hash
    try:
        manifest_path = Path(f"manifests/{agent_id}.manifest.json")
        manifest = json.loads(manifest_path.read_text())
        manifest_hash = manifest.get("config_hash")
        
        if config_hash != manifest_hash:
            steps.append(RestoreStepResult(step="compare_hash", success=False, details=f"Hash mismatch: {config_hash} != {manifest_hash}"))
            return RestoreResult(agent_id=agent_id, steps=steps, overall_success=False)
        
        steps.append(RestoreStepResult(step="compare_hash", success=True, details=None))
    except Exception as e:
        steps.append(RestoreStepResult(step="compare_hash", success=False, details=str(e)))
        return RestoreResult(agent_id=agent_id, steps=steps, overall_success=False)
    
    # Update config_hash_state
    conn = db.get_connection()
    conn.execute("UPDATE agents SET config_hash_state = 'matched' WHERE agent_id = ?", (agent_id,))
    conn.commit()
    
    return RestoreResult(agent_id=agent_id, steps=steps, overall_success=True)


@app.post("/admin/resume/{agent_id}")
async def resume_agent(agent_id: str):
    """
    Resume agent from QUARANTINED or HALTED status.
    Verifies config integrity before releasing. Applies probation on success.
    """
    from engine.heartbeat import verify_config_integrity
    from engine.trust import status_for_score, apply_trust_update
    from engine.enforcer import write_incident
    from gateway.schemas import Severity, AgentStatus
    from datetime import datetime, timezone, timedelta
    
    agent = db.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Only valid from QUARANTINED or HALTED
    if agent['status'] not in ['QUARANTINED', 'HALTED']:
        raise HTTPException(status_code=409, detail=f"Cannot resume agent in {agent['status']} status")
    
    # Verify config integrity
    is_valid, error, config_hash = verify_config_integrity(agent_id)
    if not is_valid:
        raise HTTPException(status_code=409, detail=f"Config still mismatches: {error}")
    
    # Apply probation
    from gateway.config import settings
    new_trust = min(agent['trust_score'], settings.probation_start_score)
    probation_until = (datetime.now(timezone.utc) + timedelta(minutes=settings.probation_clean_min)).isoformat().replace("+00:00", "Z")
    
    # Cap trust at PROBATION_CAP
    if new_trust > settings.probation_cap:
        new_trust = settings.probation_cap
    
    # Update agent
    conn = db.get_connection()
    conn.execute("""
        UPDATE agents 
        SET trust_score = ?, probation_until = ?, current_rate_limit = current_rate_limit / 2
        WHERE agent_id = ?
    """, (new_trust, probation_until, agent_id))
    conn.commit()
    
    # Derive status from score
    new_status = status_for_score(new_trust, agent['status'])
    conn.execute("UPDATE agents SET status = ? WHERE agent_id = ?", (new_status.value, agent_id))
    conn.commit()
    
    # Mark open incidents as resolved
    conn.execute("UPDATE incidents SET resolved = 1 WHERE agent_id = ? AND resolved = 0", (agent_id,))
    conn.commit()
    
    # Audit record
    from audit.chain import append_record
    decision = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "verdict": "RESUME",
        "response": "resumed",
        "reason": "Agent resumed by admin",
        "rule": "admin.resume",
        "severity": Severity.LOW,
        "trust_before": agent['trust_score'],
        "trust_after": new_trust,
        "status": new_status
    }
    append_record(decision, {"agent_id": agent_id, "event_id": f"resume-{datetime.now(timezone.utc).timestamp()}", "tool": "admin", "args": {}})
    
    # Publish trust and status
    await manager.publish({
        "type": "trust",
        "data": {"agent_id": agent_id, "trust_before": agent['trust_score'], "trust_after": new_trust}
    })
    await manager.publish({
        "type": "status",
        "data": {"agent_id": agent_id, "status": new_status.value, "reason": "Admin resume"}
    })
    
    return {
        "status": "resumed",
        "agent_id": agent_id,
        "trust_score": new_trust,
        "status": new_status.value,
        "probation_until": probation_until
    }


@app.get("/incidents")
async def get_incidents(agent_id: Optional[str] = None, resolved: Optional[bool] = None,
                      severity: Optional[str] = None, limit: int = 100, offset: int = 0):
    """Get incidents with optional filters"""
    incidents = db.get_incidents(agent_id=agent_id, resolved=resolved, severity=severity, limit=limit, offset=offset)
    return {"incidents": incidents, "count": len(incidents)}


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
        "audit_checkpoint_every": settings.audit_checkpoint_every,
        "timestamp_window_sec": settings.timestamp_window_sec,
        "heartbeat_interval_sec": settings.heartbeat_interval_sec,
        "heartbeat_challenge_expire_sec": settings.heartbeat_challenge_expire_sec,
        "hold_timeout_sec": settings.hold_timeout_sec,
        "hold_sweep_interval_sec": settings.hold_sweep_interval_sec,
        "trust_recovery_interval_sec": settings.trust_recovery_interval_sec,
        "drift_zscore_threshold": settings.drift_zscore_threshold,
        "demo_mode": settings.demo_mode,
        "runtime_mode": settings.runtime_mode,
        "pipeline_timeout_sec": settings.pipeline_timeout_sec,
        "tool_timeout_sec": settings.tool_timeout_sec
    }


@app.get("/mode")
async def get_mode():
    """Get current runtime mode"""
    return {"mode": settings.runtime_mode}


@app.post("/mode")
async def set_mode(mode_request: RuntimeMode):
    """Set runtime mode (off, dry-run, on)"""
    valid_modes = ["off", "dry-run", "on"]
    if mode_request.mode not in valid_modes:
        raise HTTPException(status_code=400, detail=f"Invalid mode. Must be one of: {valid_modes}")
    
    settings.runtime_mode = mode_request.mode
    return {"mode": settings.runtime_mode, "message": f"Runtime mode set to {mode_request.mode}"}


@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get specific agent with full details"""
    agents = db.get_agents_with_history(agent_id)
    if not agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent = agents[0]
    return {
        "agent_id": agent['agent_id'],
        "status": agent['status'],
        "trust_score": agent['trust_score'],
        "last_seen": agent['last_seen'],
        "config_hash_ok": agent['config_hash_state'] == 'matched',
        "probation_until": agent['probation_until'],
        "effective_rate_limit": agent['current_rate_limit'],
        "trust_history": agent['trust_history']
    }


@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get specific agent with full details"""
    agents = db.get_agents_with_history(agent_id)
    if not agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent = agents[0]
    return {
        "agent_id": agent['agent_id'],
        "status": agent['status'],
        "trust_score": agent['trust_score'],
        "last_seen": agent['last_seen'],
        "config_hash_ok": agent['config_hash_state'] == 'matched',
        "probation_until": agent['probation_until'],
        "effective_rate_limit": agent['current_rate_limit'],
        "trust_history": agent['trust_history']
    }


@app.post("/attack/{attack_type}")
async def run_attack(attack_type: str):
    """
    Attack dispatcher - runs attack driver for given type.
    Returns 501 if driver not implemented, 404 if unknown type.
    """
    # Check if attack type is known
    known_types = ["injection", "tamper", "spike", "spread", "impersonate"]
    if attack_type not in known_types:
        raise HTTPException(status_code=404, detail=f"Unknown attack type: {attack_type}")
    
    # Check if driver exists
    try:
        from pathlib import Path
        driver_path = Path(f"attacks/{attack_type}.py")
        if not driver_path.exists():
            raise HTTPException(status_code=501, detail={"error": "not_implemented", "type": attack_type})
        
        # Import and run driver
        import importlib.util
        spec = importlib.util.spec_from_file_location(f"attacks.{attack_type}", driver_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        result = module.run()
        return result
    except HTTPException:
        raise
    except Exception as e:
        # If driver has any error, return 501
        raise HTTPException(status_code=501, detail={"error": "not_implemented", "type": attack_type, "details": str(e)})
