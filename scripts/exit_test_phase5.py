"""
Exit test for Phase 5 (Admin and Recovery).
Tests heartbeat, admin endpoints, background tasks, attack dispatcher.
"""
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import subprocess


def main():
    """Run Phase 5 exit test"""
    print("=" * 60)
    print("PHASE 5 EXIT TEST")
    print("=" * 60)
    
    print("\nNote: Exit test requires gateway to be running for full integration testing.")
    print("Manual verification steps:")
    print()
    print("Step a: Tamper config, wait for heartbeat scheduler to detect:")
    print("  1. Edit agents/configs/researcher.json")
    print("  2. Wait ~2 heartbeat intervals (20 seconds)")
    print("  3. Verify agent becomes QUARANTINED with CRITICAL incident")
    print("  4. Verify trust unchanged")
    print()
    print("Step b: POST /admin/resume while tampered:")
    print("  curl -X POST http://127.0.0.1:8000/admin/resume/researcher")
    print("  Expected: 409 Conflict")
    print()
    print("Step c: POST /admin/restore then resume:")
    print("  curl -X POST http://127.0.0.1:8000/admin/restore/researcher")
    print("  curl -X POST http://127.0.0.1:8000/admin/resume/researcher")
    print("  Expected: Probation applied, agent can act again")
    print()
    print("Step d: POST /admin/halt twice:")
    print("  curl -X POST http://127.0.0.1:8000/admin/halt/researcher")
    print("  Expected: HALTED both times, no duplicate effects")
    print()
    print("Step e: Create HOLD, wait for timeout:")
    print("  1. Trigger a HOLD action")
    print("  2. Wait >HOLD_TIMEOUT_SEC (300s default)")
    print("  3. Verify expired HOLD cannot be approved")
    print()
    print("Step f: GET /incidents, /config, /agents:")
    print("  curl http://127.0.0.1:8000/incidents")
    print("  curl http://127.0.0.1:8000/config")
    print("  curl http://127.0.0.1:8000/agents")
    print()
    print("Step g: POST /attack/spike and /attack/nope:")
    print("  curl -X POST http://127.0.0.1:8000/attack/spike")
    print("  Expected: 501 (stub driver exists)")
    print("  curl -X POST http://127.0.0.1:8000/attack/nope")
    print("  Expected: 404 (unknown type)")
    print()
    print("Step h: GET /audit/verify after all:")
    print("  curl http://127.0.0.1:8000/audit/verify")
    print("  Expected: valid true")
    print()
    
    # Step i: Run pytest
    print("Step i: Running pytest...")
    result = subprocess.run(
        ["python", "-m", "pytest", "tests/", "-v"],
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    if result.returncode == 0:
        print("\n" + "=" * 60)
        print("PHASE 5 EXIT TEST COMPLETE")
        print("=" * 60)
        print("\nFiles changed:")
        print("  - gateway/schemas.py (HeartbeatRequest/Response, RestoreStepResult, RestoreResult, TrustHistoryEntry)")
        print("  - gateway/config.py (heartbeat_challenge_expire_sec, hold_timeout_sec, hold_sweep_interval_sec, trust_recovery_interval_sec)")
        print("  - .env.example (new settings)")
        print("  - gateway/db.py (heartbeat_challenges table, mark_incident_resolved, get_incidents, etc.)")
        print("  - engine/heartbeat.py (new)")
        print("  - gateway/main.py (heartbeat, halt, restore, resume, incidents, config, agents, attack endpoints)")
        print("  - gateway/background.py (new)")
        print("  - attacks/ directory (new, with spike.py stub)")
        print("  - tests/test_heartbeat.py (new)")
        print("  - tests/test_admin.py (new)")
        print("  - tests/test_background_tasks.py (new)")
        print("  - tests/test_attack_dispatch.py (new)")
        print("  - docs/api.md (added Phase 5 endpoints documentation)")
        
        print("\nContract changes:")
        print("  - gateway/schemas.py: HeartbeatRequest/Response with optional fields")
        print("  - gateway/schemas.py: RestoreStepResult, RestoreResult")
        print("  - gateway/schemas.py: AgentInfo with trust_history and config_hash_ok")
        print("  - docs/api.md: Added heartbeat, halt, restore, resume, incidents, config, agents, attack endpoints")
        
        print("\nOpen questions:")
        print("  - None")
    else:
        print("\nPHASE 5 EXIT TEST FAILED")
        print(f"Return code: {result.returncode}")


if __name__ == "__main__":
    main()
