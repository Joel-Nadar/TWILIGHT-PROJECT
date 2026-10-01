"""
Background tasks for Twilight Gateway.
Heartbeat scheduler, trust recovery, HOLD timeout.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from gateway.config import settings
from gateway.db import db
from engine.heartbeat import verify_config_integrity
from engine.trust import recover_clean_agent, status_for_score
from engine.enforcer import write_incident
from gateway.schemas import Severity, AgentStatus
from audit.chain import append_record


async def heartbeat_scheduler(app):
    """
    Every HEARTBEAT_INTERVAL_SEC, for each non-HALTED agent,
    hash config and verify manifest. On mismatch, QUARANTINE.
    """
    while True:
        try:
            # Delete expired challenges
            db.expire_old_challenges()
            
            # Get all non-HALTED agents
            conn = db.get_connection()
            agents = conn.execute("SELECT * FROM agents WHERE status != 'HALTED'").fetchall()
            
            for agent in agents:
                agent_id = agent['agent_id']
                current_status = agent['status']
                
                # Skip if already QUARANTINED (no duplicate incidents)
                if current_status == 'QUARANTINED':
                    continue
                
                # Verify config integrity
                is_valid, error, config_hash = verify_config_integrity(agent_id)
                
                if not is_valid and "mismatch" in error.lower():
                    # Set status QUARANTINED, trust unchanged
                    conn.execute("""
                        UPDATE agents SET status = 'QUARANTINED', config_hash_state = 'mismatch' 
                        WHERE agent_id = ?
                    """, (agent_id,))
                    conn.commit()
                    
                    # Create incident
                    write_incident(agent_id, Severity.CRITICAL, f"Config hash mismatch (scheduler): {error}", conn)
                    
                    # Audit record
                    decision = {
                        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "verdict": "QUARANTINE",
                        "response": "quarantined",
                        "reason": f"Config hash mismatch (scheduler): {error}",
                        "rule": "heartbeat.scheduler_mismatch",
                        "severity": Severity.CRITICAL,
                        "trust_before": agent['trust_score'],
                        "trust_after": agent['trust_score'],
                        "status": AgentStatus.QUARANTINED
                    }
                    append_record(decision, {"agent_id": agent_id, "event_id": f"scheduler-{datetime.now(timezone.utc).timestamp()}", "tool": "heartbeat", "args": {}})
                    
                    # Publish status
                    from gateway.websocket import manager
                    await manager.publish({
                        "type": "status",
                        "data": {"agent_id": agent_id, "status": "QUARANTINED", "reason": error}
                    })
                    await manager.publish({
                        "type": "incident",
                        "data": {"agent_id": agent_id, "severity": "CRITICAL", "summary": f"Config hash mismatch (scheduler): {error}"}
                    })
            
        except Exception as e:
            print(f"Error in heartbeat scheduler: {e}")
        
        await asyncio.sleep(settings.heartbeat_interval_sec)


async def trust_recovery_loop(app):
    """
    Every TRUST_RECOVERY_INTERVAL_SEC, call recover_clean_agent for agents
    with no violations in the last interval. QUARANTINED and HALTED never auto-recover.
    """
    while True:
        try:
            conn = db.get_connection()
            agents = conn.execute("SELECT * FROM agents WHERE status NOT IN ('QUARANTINED', 'HALTED')").fetchall()
            
            for agent in agents:
                agent_id = agent['agent_id']
                
                # Check for violations in the last interval
                window_start = datetime.now(timezone.utc) - timedelta(seconds=settings.trust_recovery_interval_sec)
                violations = conn.execute("""
                    SELECT COUNT(*) as count FROM events 
                    WHERE agent_id = ? AND ts > ? AND (verdict = 'BLOCK' OR verdict = 'QUARANTINE')
                """, (agent_id, window_start.isoformat().replace("+00:00", "Z"))).fetchone()
                
                if violations['count'] == 0:
                    # No violations, recover trust
                    new_score = recover_clean_agent(agent_id)
                    
                    # Check probation expiry
                    if agent['probation_until']:
                        probation_end = datetime.fromisoformat(agent['probation_until'].replace("Z", "+00:00"))
                        if datetime.now(timezone.utc) > probation_end:
                            # Remove probation cap
                            conn.execute("UPDATE agents SET probation_until = NULL WHERE agent_id = ?", (agent_id,))
                            conn.commit()
                            
                            # Restore normal rate limit
                            conn.execute("UPDATE agents SET current_rate_limit = current_rate_limit * 2 WHERE agent_id = ?", (agent_id,))
                            conn.commit()
            
        except Exception as e:
            print(f"Error in trust recovery loop: {e}")
        
        await asyncio.sleep(settings.trust_recovery_interval_sec)


async def hold_timeout_sweep(app):
    """
    Every HOLD_SWEEP_INTERVAL_SEC, expire PENDING held actions older than HOLD_TIMEOUT_SEC.
    Mark REJECTED_TIMEOUT, do not execute, write audit record.
    """
    while True:
        try:
            conn = db.get_connection()
            timeout_threshold = (datetime.now(timezone.utc) - timedelta(seconds=settings.hold_timeout_sec)).isoformat().replace("+00:00", "Z")
            
            # Find expired PENDING actions
            expired = conn.execute("""
                SELECT * FROM held_actions 
                WHERE status = 'PENDING' AND decided_at < ?
            """, (timeout_threshold,)).fetchall()
            
            for action in expired:
                event_id = action['event_id']
                agent_id = action['agent_id']
                
                # Mark as REJECTED_TIMEOUT
                conn.execute("""
                    UPDATE held_actions SET status = 'REJECTED_TIMEOUT', decided_at = datetime('now')
                    WHERE event_id = ?
                """, (event_id,))
                conn.commit()
                
                # Audit record
                decision = {
                    "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "verdict": "BLOCK",
                    "response": "rejected",
                    "reason": "HOLD action expired",
                    "rule": "hold.timeout",
                    "severity": Severity.MEDIUM,
                    "trust_before": None,
                    "trust_after": None,
                    "status": None
                }
                append_record(decision, {"agent_id": agent_id, "event_id": event_id, "tool": "hold", "args": {}})
            
        except Exception as e:
            print(f"Error in HOLD timeout sweep: {e}")
        
        await asyncio.sleep(settings.hold_sweep_interval_sec)


async def start_background_tasks(app):
    """Start all background tasks on startup"""
    # Store task references for cleanup
    app.state.heartbeat_task = asyncio.create_task(heartbeat_scheduler(app))
    app.state.recovery_task = asyncio.create_task(trust_recovery_loop(app))
    app.state.hold_task = asyncio.create_task(hold_timeout_sweep(app))


async def stop_background_tasks(app):
    """Stop all background tasks on shutdown"""
    for task_name in ["heartbeat_task", "recovery_task", "hold_task"]:
        task = getattr(app.state, task_name, None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
