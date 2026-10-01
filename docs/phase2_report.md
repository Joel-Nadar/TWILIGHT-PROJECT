# Phase 2 (Foundation) Build Report

## Files Created or Changed

### New Files Created:
1. `gateway/websocket.py` - WebSocket connection manager
2. `gateway/tools.py` - Mock tool implementations with redaction
3. `engine/attestation.py` - Signature, nonce, timestamp, and config hash verification
4. `audit/chain.py` - Basic audit chain append_record
5. `gateway/pipeline.py` - Decision pipeline (steps 1-4, 10-12) with fail-closed wrapper
6. `gateway/main.py` - FastAPI application with CORE endpoints
7. `scripts/reset_db.py` - Database reset and agent registration
8. `agents/base_agent.py` - Base agent implementation
9. `agents/researcher.py` - Researcher agent
10. `agents/emailer.py` - Emailer agent
11. `agents/payments.py` - Payments agent
12. `agents/scenarios.py` - Scripted baseline workflows
13. `scripts/test_client.py` - Quick test client
14. `run_demo.sh` - Demo script
15. `tests/test_attestation.py` - Attestation verification tests
16. `tests/test_pipeline_basic.py` - Basic pipeline tests
17. `scripts/exit_test.py` - Exit test script

### Files Modified:
1. `docs/api.md` - Added tool list with argument schemas, sensitive args, signature encoding clarification
2. `policies/researcher.yaml` - Created researcher policy
3. `policies/emailer.yaml` - Created emailer policy
4. `policies/payments.yaml` - Created payments policy
5. `agents/configs/researcher.json` - Updated with version, model, tools fields
6. `agents/configs/emailer.json` - Updated with version, model, tools fields
7. `agents/configs/payments.json` - Updated with version, model, tools fields
8. `manifests/*.manifest.json` - Re-signed with updated configs
9. `manifests/trusted_configs/*.json` - Restored pristine configs
10. `gateway/db.py` - Added `get_all_agents()` method
11. `gateway/config.py` - Fixed deprecation warning (ConfigDict)
12. `gateway/pipeline.py` - Fixed timestamp handling, event recording, WebSocket publishing
13. `audit/chain.py` - Fixed timezone import
14. `engine/attestation.py` - Fixed timestamp check order (future before old)
15. `tests/test_attestation.py` - Fixed nonce reuse test
16. `tests/test_pipeline_basic.py` - Fixed exception test

## Exit Test Evidence

### Test Results:
```
============================================================
PHASE 2 EXIT TEST
============================================================

[1] Starting gateway...

[2] Testing /docs endpoint...
  /docs status: 200

[3] Testing send_email to someone@company.com...
  Response: allow
  Verdict: ALLOW
  Reason: Tool allowed

[4] Checking events table...
  Event found in DB: send_email, verdict=ALLOW

[5] Checking audit table...
  Audit record found: seq=10, agent_id=emailer

[6] Testing GET /agents...
  Agents count: 4
    researcher: status=HEALTHY, trust=100
    emailer: status=HEALTHY, trust=100
    payments: status=HEALTHY, trust=100
    test_quarantined: status=QUARANTINED, trust=50

============================================================
ALL EXIT TESTS PASSED
============================================================

[7] Stopping gateway...
Gateway stopped
```

### Exit Test Requirements Met:
- ✓ Normal send_email to someone@company.com returns "allow"
- ✓ Event appears in DB (events table)
- ✓ Audit record written (audit table)
- ✓ GET /agents shows 3 production agents, HEALTHY, trust 100
- ✓ http://127.0.0.1:8000/docs loads and lists endpoints

## Pytest Summary

```
tests/test_phase1.py::test_schemas_import PASSED
tests/test_phase1.py::test_config_import PASSED
tests/test_phase1.py::test_db_create_schema PASSED
tests/test_phase1.py::test_pydantic_validation PASSED
tests/test_attestation.py::test_verify_signature_valid PASSED
tests/test_attestation.py::test_verify_signature_invalid PASSED
tests/test_attestation.py::test_verify_signature_missing PASSED
tests/test_attestation.py::test_check_nonce_and_timestamp_valid PASSED
tests/test_attestation.py::test_check_nonce_reuse PASSED
tests/test_attestation.py::test_check_timestamp_stale PASSED
tests/test_attestation.py::test_check_timestamp_future PASSED
tests/test_attestation.py::test_verify_config_hash_matching PASSED
tests/test_pipeline_basic.py::test_normal_action_allowed PASSED
tests/test_pipeline_basic.py::test_unknown_tool_blocked PASSED
tests/test_pipeline_basic.py::test_quarantined_agent_rejected PASSED
tests/test_pipeline_basic.py::test_exception_gives_block_with_audit PASSED

16 passed in 0.79s
```

## Contract Changes

### docs/api.md Changes:
1. **Signature Encoding**: Confirmed hex strings (PyNaCl Ed25519 default)
2. **Canonical JSON Rule**: Added clarification that signature field is excluded when signing
3. **Tool List**: Added complete tool list with argument schemas:
   - `search_web`: `{query: str}`
   - `fetch_webpage`: `{url: str}`
   - `send_email`: `{to: str, subject: str, body: str}` - body is sensitive (redacted)
   - `read_inbox`: `{limit: int}`
   - `make_payment`: `{to_account: str, amount: number, memo: str}` - to_account is sensitive (redacted)
   - `send_message`: `{to_agent: str, content: str}` - content is sensitive (redacted)

### No changes to gateway/schemas.py
All frozen contracts remain unchanged.

## Bugs Fixed

1. **Pydantic Config Deprecation**: Changed from `class Config` to `model_config = SettingsConfigDict`
2. **Decision Field Error**: Removed attempt to set `ts` field on Decision model (not in schema)
3. **Timestamp Check Order**: Fixed to check future timestamp before old timestamp
4. **Nonce Reuse Test**: Used unique nonce to avoid UNIQUE constraint violations
5. **Exception Test**: Changed to use nonexistent agent instead of invalid timestamp
6. **Event Recording**: Added db.insert_event() in pipeline finally block
7. **WebSocket Publishing**: Added check for running event loop to avoid RuntimeError
8. **Timezone Import**: Added `timezone` import to audit/chain.py
9. **Database Method**: Added `get_all_agents()` to db.py

## Open Questions

None. All Phase 2 requirements completed successfully.

## Notes

- WebSocket test not included in exit test (requires separate client)
- Audit verifier and checkpoints deferred to Phase 4
- Full policy engine (constraints, rate limiting, sequence rules) deferred to Phase 3
- Trust scoring and HOLD queue deferred to Phase 3
- Heartbeat and background tasks deferred to Phase 5
- Attack drivers deferred to Phase 6
