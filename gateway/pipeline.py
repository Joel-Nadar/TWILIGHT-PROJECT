"""
Decision pipeline for Twilight Gateway.
Orchestrates steps 1-4, 6-9, 10-12 with fail-closed wrapper.
"""
import time
import threading
from datetime import datetime, timezone
from typing import Dict, Any
from gateway.schemas import Verdict, AgentStatus, Decision, Severity
from gateway.db import db
from gateway.config import settings
from engine.attestation import verify_signature, check_nonce_and_timestamp, verify_config_hash, insert_nonce
from engine.policy import check_policy, get_recent_history
from engine.trust import apply_penalty, status_for_score, apply_trust_update
from engine.enforcer import (
    check_status, decide, check_sustained_rate_violations,
    apply_response_ladder, write_incident, publish_trust_change, publish_status_change
)
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
                decision.severity = Severity.CRITICAL
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
                write_incident(event["agent_id"], "CRITICAL", f"Config hash mismatch: {hash_error}", "attestation.config_hash_mismatch")
                
                return decision
            
            # Step 4: Full policy check
            policy = load_agent_policy(event["agent_id"])
            if not policy:
                decision.reason = "Policy not found for agent"
                decision.rule = "policy.missing"
                decision.response = "blocked"
                decision.verdict = Verdict.BLOCK
                return decision
            
            tool = event.get("tool")
            history = get_recent_history(event["agent_id"])
            policy_result = check_policy(event, policy, history)
            
            if not policy_result["allowed"]:
                # Policy rejected
                decision.reason = policy_result["reason"]
                decision.rule = policy_result["rule"]
                severity_str = policy_result.get("severity")
                decision.severity = Severity(severity_str) if severity_str else None
                decision.verdict = Verdict.BLOCK
                decision.response = "blocked"
                decision.evidence = {"policy_check": policy_result}
                
                # Apply penalty and update status (fetch fresh agent state from DB)
                fresh_agent = db.get_agent(event["agent_id"])
                new_score = apply_penalty(fresh_agent["trust_score"], decision.reason, policy)
                new_status = status_for_score(new_score, fresh_agent["status"])
                apply_trust_update(event["agent_id"], new_score, new_status, decision.reason)
                
                # Use computed values directly (don't rely on DB read due to transaction visibility)
                decision.trust_after = new_score
                decision.status = new_status
                
                # Update cached agent for publishing
                agent = fresh_agent
                
                # Write incident
                if decision.severity:
                    severity_val = decision.severity.value if hasattr(decision.severity, 'value') else str(decision.severity)
                    write_incident(event["agent_id"], severity_val, decision.reason, decision.rule)
                
                # Publish changes
                publish_trust_change(event["agent_id"], agent["trust_score"], new_score, decision.reason)
                if new_status != agent["status"]:
                    publish_status_change(event["agent_id"], agent["status"], new_status.value, decision.reason)
                
                return decision
            
            # Step 5: Drift (skipped - Phase 2)
            
            # Step 6: Decide verdict and response
            verdict, response, severity = decide(policy_result, agent, tool, policy)
            decision.verdict = verdict
            decision.response = response
            if severity:
                decision.severity = severity if isinstance(severity, Severity) else Severity(severity)
            else:
                decision.severity = None
            decision.rule = policy_result["rule"]
            
            # Check for sustained rate violations (THROTTLE -> HALT)
            if response == "throttled" and check_sustained_rate_violations(event["agent_id"]):
                decision.verdict = Verdict.BLOCK
                decision.response = "halted"
                decision.reason = "Sustained rate violations - agent halted"
                decision.rule = "rate.sustained_violations"
                decision.status = AgentStatus.HALTED
                apply_trust_update(event["agent_id"], agent["trust_score"], AgentStatus.HALTED, decision.reason)
                write_incident(event["agent_id"], "CRITICAL", decision.reason, decision.rule)
                publish_status_change(event["agent_id"], agent["status"], "HALTED", decision.reason)
                return decision
            
            # Step 7: HOLD queue
            if verdict == Verdict.HOLD:
                # Store in held_actions
                import json
                db.insert_held_action(
                    event.get("event_id"),
                    event["agent_id"],
                    json.dumps(event)
                )
                decision.reason = policy_result["reason"]
                decision.trust_after = agent["trust_score"]
                decision.status = AgentStatus(agent["status"])
                return decision
            
            # Step 8: Trust (penalties already applied for BLOCK)
            # For ALLOW/FLAG, no penalty, just update last_seen
            if verdict in [Verdict.ALLOW, Verdict.FLAG]:
                decision.trust_after = agent["trust_score"]
                decision.status = AgentStatus(agent["status"])
            
            # Step 9: Response ladder (update status if needed)
            if verdict == Verdict.BLOCK:
                new_score, new_status = apply_response_ladder(
                    event["agent_id"], verdict, response, agent, policy,
                    decision.reason, decision.rule
                )
                decision.trust_after = new_score
                decision.status = new_status
            
            # Step 10: Execute tool (only ALLOW/FLAG or approved HOLD)
            if verdict in [Verdict.ALLOW, Verdict.FLAG]:
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
        import traceback
        traceback.print_exc()  # Print traceback for debugging
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


# Export load_agent_policy for use in main.py
__all__ = ["run_pipeline", "load_agent_policy"]
