"""
Decision pipeline for Twilight Gateway.
Orchestrates steps 1-4 and 10-12 with fail-closed wrapper.
"""
import time
import threading
from datetime import datetime, timezone
from typing import Dict, Any
from gateway.schemas import Verdict, AgentStatus, Decision
from gateway.db import db
from gateway.config import settings
from engine.attestation import verify_signature, check_nonce_and_timestamp, verify_config_hash, insert_nonce
from gateway.tools import execute_tool
from audit.chain import append_record
from gateway.websocket import manager


# Lock for serializing decisions to ensure audit seq consistency
decision_lock = threading.Lock()


def run_pipeline(event: Dict[str, Any], api_key: str) -> Decision:
    """
    Run the decision pipeline for an event.
    Steps 1-4 and 10-12 with fail-closed wrapper.
    """
    start_time = time.perf_counter()
    
    # Initialize decision
    decision = Decision(
        verdict="BLOCK",
        response="blocked",
        reason="",
        rule=None,
        severity=None,
        trust_before=None,
        trust_after=None,
        status=None,
        evidence={},
        latency_ms=None
    )
    
    try:
        with decision_lock:
            # Step 1: Status check (reject QUARANTINED/HALTED first)
            agent = db.get_agent(event.get("agent_id"))
            if not agent:
                decision.reason = "Agent not registered"
                decision.rule = "registration.unknown_agent"
                decision.response = "blocked"
                decision.verdict = Verdict.BLOCK
                return decision
            
            agent_status = agent["status"]
            if agent_status in ["QUARANTINED", "HALTED"]:
                decision.reason = f"Agent is {agent_status}"
                decision.rule = f"status.{agent_status.lower()}"
                decision.response = "halted" if agent_status == "HALTED" else "blocked"
                decision.verdict = Verdict.BLOCK
                decision.status = AgentStatus(agent_status)
                decision.trust_before = agent["trust_score"]
                decision.trust_after = agent["trust_score"]
                return decision
            
            decision.trust_before = agent["trust_score"]
            decision.status = AgentStatus(agent_status)
            
            # Step 2: Signature and replay
            is_valid_sig, sig_error = verify_signature(event, agent["public_key"])
            if not is_valid_sig:
                decision.reason = sig_error
                decision.rule = "attestation.signature"
                decision.response = "blocked"
                decision.verdict = Verdict.BLOCK
                return decision
            
            is_valid_nonce, nonce_error = check_nonce_and_timestamp(event)
            if not is_valid_nonce:
                decision.reason = nonce_error
                decision.rule = "attestation.replay" if "replay" in nonce_error else "attestation.timestamp"
                decision.response = "blocked"
                decision.verdict = Verdict.BLOCK
                return decision
            
            # Insert nonce (atomically with decision)
            insert_nonce(event)
            
            # Step 3: Attestation (config hash vs manifest)
            is_valid_hash, hash_error, computed_hash = verify_config_hash(event["agent_id"])
            if not is_valid_hash:
                # Mismatch: set QUARANTINED immediately, CRITICAL severity
                db.update_agent_status(event["agent_id"], "QUARANTINED")
                decision.reason = hash_error
                decision.rule = "attestation.config_hash_mismatch"
                decision.response = "blocked"
                decision.verdict = Verdict.QUARANTINE
                decision.severity = "CRITICAL"
                decision.status = AgentStatus.QUARANTINED
                decision.trust_after = agent["trust_score"]  # Trust unchanged (critical override)
                decision.evidence = {"computed_hash": computed_hash}
                
                # Create incident
                from gateway.schemas import Incident
                incident = Incident(
                    agent_id=event["agent_id"],
                    severity="CRITICAL",
                    summary=f"Config hash mismatch: {hash_error}"
                )
                db.insert_incident(incident.model_dump())
                
                return decision
            
            # Step 4: Minimal policy check (tool in allow_tools)
            policy = load_agent_policy(event["agent_id"])
            if not policy:
                decision.reason = "Policy not found for agent"
                decision.rule = "policy.missing"
                decision.response = "blocked"
                decision.verdict = Verdict.BLOCK
                return decision
            
            tool = event.get("tool")
            allow_tools = policy.get("allow_tools", [])
            
            if tool not in allow_tools:
                decision.reason = f"Tool '{tool}' not allowed for this agent"
                decision.rule = "allow_tools"
                decision.response = "blocked"
                decision.verdict = Verdict.BLOCK
                decision.evidence = {"requested_tool": tool}
                return decision
            
            # Allow the action
            decision.verdict = Verdict.ALLOW
            decision.response = "allow"
            decision.reason = "Tool allowed"
            decision.rule = "allow_tools"
            decision.trust_after = agent["trust_score"]
            
            # Step 10: Execute tool
            tool_result = execute_tool(tool, event.get("args", {}), event.get("event_id"), api_key)
            if not tool_result["success"]:
                decision.verdict = Verdict.BLOCK
                decision.response = "blocked"
                decision.reason = tool_result["result"]
                decision.rule = "tool.execution_error"
            
            decision.evidence = {"tool_result": tool_result["redacted_args"]}
            
            return decision
    
    except Exception as exc:
        # Fail-closed: any exception results in BLOCK
        decision.verdict = Verdict.BLOCK
        decision.response = "blocked"
        decision.reason = "internal_error"
        decision.rule = "pipeline.exception"
        decision.evidence = {"error_type": type(exc).__name__, "error_message": str(exc)}
        return decision
    
    finally:
        # Measure latency
        latency_ms = (time.perf_counter() - start_time) * 1000
        decision.latency_ms = latency_ms
        
        # Insert event record for EVERY decision
        try:
            db.insert_event({
                "event_id": event.get("event_id"),
                "ts": event.get("ts"),
                "agent_id": event.get("agent_id"),
                "type": event.get("type"),
                "tool": event.get("tool"),
                "args": event.get("args"),
                "context": event.get("context"),
                "nonce": event.get("nonce"),
                "signature": event.get("signature"),
                "verdict": decision.verdict.value,
                "response": decision.response,
                "reason": decision.reason,
                "rule": decision.rule,
                "severity": decision.severity.value if decision.severity else None,
                "trust_before": decision.trust_before,
                "trust_after": decision.trust_after,
                "status": decision.status.value if decision.status else None,
                "evidence": decision.evidence,
                "latency_ms": decision.latency_ms
            })
        except Exception as exc:
            print(f"Failed to insert event record: {exc}")
        
        # Step 11: Append audit record for EVERY decision
        try:
            # Add timestamp for audit record
            decision_dict = decision.model_dump()
            decision_dict["ts"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            append_record(decision_dict, event)
        except Exception as exc:
            # If audit fails, log but don't crash
            print(f"Failed to append audit record: {exc}")
        
        # Step 12: Publish to WebSocket
        try:
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(manager.publish("decision", decision.model_dump(exclude={"evidence"})))
            except RuntimeError:
                # No event loop running (e.g., in tests)
                pass
        except Exception as exc:
            # If WebSocket fails, log but don't crash
            print(f"Failed to publish WebSocket message: {exc}")


def load_agent_policy(agent_id: str) -> Dict[str, Any]:
    """Load agent policy from YAML file"""
    import yaml
    from pathlib import Path
    
    policy_path = Path(f"policies/{agent_id}.yaml")
    if not policy_path.exists():
        return None
    
    with open(policy_path, 'r') as f:
        return yaml.safe_load(f)
