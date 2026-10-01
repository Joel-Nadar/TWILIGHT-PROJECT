# Twilight Gateway API Documentation

## Overview

Twilight is a runtime integrity gateway for multi-agent networks. All agent actions must be signed and submitted to the gateway for validation before execution.

**Base URL:** `http://127.0.0.1:8000`

**Signature Encoding:** All signatures are encoded as hex strings (PyNaCl Ed25519 default).

**Canonical JSON:** For signing and hashing, JSON must be canonical:
- Sorted keys
- Compact separators (no spaces after commas/colons)
- UTF-8 encoding
- No extra whitespace
- **Signature field excluded** when signing

Example canonical JSON:
```json
{"agent_id":"researcher","args":{"query":"example"},"event_id":"123e4567-e89b-12d3-a456-426614174000","nonce":"abc123","tool":"search_web","ts":"2026-10-01T12:00:00Z","type":"tool_call"}
```

---

## Tools

All tool execution must go through the gateway. Tools are mock implementations that record effects.

| Tool | Arguments | Sensitive Args (Redacted) |
|---|---|---|
| `search_web` | `{query: str}` | None |
| `fetch_webpage` | `{url: str}` | None |
| `send_email` | `{to: str, subject: str, body: str}` | `body` |
| `read_inbox` | `{limit: int}` | None |
| `make_payment` | `{to_account: str, amount: number, memo: str}` | `to_account` |
| `send_message` | `{to_agent: str, content: str}` | `content` |

**Redaction:** Sensitive arguments are replaced with `***` in audit records, WebSocket messages, and logs.

---

---

## Endpoints

### POST /register

Register a new agent with the gateway.

**Request Body:**
```json
{
  "agent_id": "researcher",
  "public_key": "a1b2c3d4e5f6... (hex string)",
  "policy": "agent: researcher\nversion: 1\nallow_tools: [search_web, fetch_webpage, send_message]\n...",
  "manifest": "{\"agent_id\":\"researcher\",\"config_hash\":\"abc123...\",\"admin_signature\":\"def456...\"}",
  "config_path": "agents/configs/researcher.json"
}
```

**Response (200 OK):**
```json
{
  "status": "registered",
  "agent_id": "researcher",
  "trust_score": 100,
  "status": "HEALTHY"
}
```

**Response (400 Bad Request):**
```json
{
  "detail": "Invalid policy YAML: ..."
}
```

---

### POST /action

Submit an agent action for validation and execution.

**Request Body:**
```json
{
  "event_id": "123e4567-e89b-12d3-a456-426614174000",
  "ts": "2026-10-01T12:00:00Z",
  "agent_id": "researcher",
  "type": "tool_call",
  "tool": "search_web",
  "args": {
    "query": "machine learning"
  },
  "context": {},
  "nonce": "fresh-unique-nonce-123",
  "signature": "789abcdef... (hex signature of canonical JSON excluding signature field)"
}
```

**Response (200 OK) - Allowed:**
```json
{
  "verdict": "ALLOW",
  "response": "allow",
  "reason": "Tool allowed",
  "rule": "allow_tools",
  "severity": null,
  "trust_before": 100,
  "trust_after": 100,
  "status": "HEALTHY",
  "evidence": {},
  "latency_ms": 5.2
}
```

**Response (200 OK) - Blocked:**
```json
{
  "verdict": "BLOCK",
  "response": "blocked",
  "reason": "Tool not allowed for this agent",
  "rule": "allow_tools",
  "severity": "MEDIUM",
  "trust_before": 100,
  "trust_after": 60,
  "status": "FLAGGED",
  "evidence": {"requested_tool": "send_email"},
  "latency_ms": 3.8
}
```

**Response (200 OK) - Held:**
```json
{
  "verdict": "HOLD",
  "response": "held",
  "reason": "High-risk action from flagged agent",
  "rule": "risk_tier_hold",
  "severity": "HIGH",
  "trust_before": 45,
  "trust_after": 45,
  "status": "FLAGGED",
  "evidence": {"risk_level": "high"},
  "latency_ms": 4.1
}
```

**Response (200 OK) - Throttled:**
```json
{
  "verdict": "THROTTLE",
  "response": "throttled",
  "reason": "Rate limit exceeded",
  "rule": "rate.max_per_minute",
  "severity": "LOW",
  "trust_before": 100,
  "trust_after": 85,
  "status": "HEALTHY",
  "evidence": {"requests_in_window": 31, "limit": 30},
  "latency_ms": 2.9
}
```

**Response (200 OK) - Halted:**
```json
{
  "verdict": "BLOCK",
  "response": "halted",
  "reason": "Agent is HALTED by administrator",
  "rule": "status.halted",
  "severity": "CRITICAL",
  "trust_before": 50,
  "trust_after": 50,
  "status": "HALTED",
  "evidence": {},
  "latency_ms": 1.5
}
```

---

### POST /heartbeat/{agent_id}

Agent heartbeat for config integrity verification.

**Request:**
```json
{
  "nonce": "challenge-nonce-from-gateway",
  "signature": "agent-signed-response"
}
```

**Response (200 OK):**
```json
{
  "challenge_nonce": "new-challenge-nonce",
  "config_hash": "abc123def456... (gateway-computed hash)"
}
```

**Response (403 Forbidden) - Config mismatch:**
```json
{
  "detail": "Config hash mismatch - agent quarantined"
}
```

---

### GET /agents

List all registered agents.

**Response (200 OK):**
```json
{
  "agents": [
    {
      "agent_id": "researcher",
      "status": "HEALTHY",
      "trust_score": 100,
      "last_seen": "2026-10-01T12:00:00Z",
      "current_rate_limit": 30,
      "config_hash_state": "matched",
      "probation_until": null
    },
    {
      "agent_id": "emailer",
      "status": "FLAGGED",
      "trust_score": 45,
      "last_seen": "2026-10-01T11:55:00Z",
      "current_rate_limit": 30,
      "config_hash_state": "matched",
      "probation_until": null
    }
  ]
}
```

---

### GET /agents/{agent_id}

Get detailed information about a specific agent.

**Response (200 OK):**
```json
{
  "agent_id": "researcher",
  "status": "HEALTHY",
  "trust_score": 100,
  "last_seen": "2026-10-01T12:00:00Z",
  "current_rate_limit": 30,
  "config_hash_state": "matched",
  "probation_until": null,
  "trust_history": [
    {
      "ts": "2026-10-01T11:30:00Z",
      "score": 100,
      "reason": "initial_registration"
    }
  ]
}
```

---

### GET /audit

Get audit records (redacted).

**Query Parameters:**
- `agent_id` (optional): Filter by agent
- `limit` (optional, default 100): Maximum records to return

**Response (200 OK):**
```json
{
  "records": [
    {
      "seq": 1,
      "timestamp": "2026-10-01T12:00:00Z",
      "agent_id": "researcher",
      "record_json": "{\"ts\":\"2026-10-01T12:00:00Z\",\"agent_id\":\"researcher\",\"event_id\":\"...\",\"tool\":\"search_web\",\"args\":{\"query\":\"***\"},\"verdict\":\"ALLOW\",\"response\":\"allow\",\"reason\":\"Tool allowed\",\"rule\":\"allow_tools\",\"severity\":null,\"trust_before\":100,\"trust_after\":100,\"status\":\"HEALTHY\"}",
      "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "record_hash": "abc123...",
      "signature": null
    }
  ]
}
```

---

### GET /audit/verify

Verify the integrity of the audit chain.

**Response (200 OK) - Valid:**
```json
{
  "valid": true,
  "first_broken_seq": null,
  "expected_hash": null,
  "actual_hash": null
}
```

**Response (200 OK) - Invalid:**
```json
{
  "valid": false,
  "first_broken_seq": 42,
  "expected_hash": "abc123def456...",
  "actual_hash": "xyz789uvw012..."
}
```

---

### GET /incidents

Get security incidents.

**Query Parameters:**
- `agent_id` (optional): Filter by agent
- `resolved` (optional): Filter by resolution status (true/false)

**Response (200 OK):**
```json
{
  "incidents": [
    {
      "incident_id": "inc-123",
      "ts": "2026-10-01T12:00:00Z",
      "agent_id": "emailer",
      "severity": "CRITICAL",
      "summary": "Config hash mismatch detected",
      "resolved": false
    }
  ]
}
```

---

### POST /admin/resume/{agent_id}

Release a quarantined or halted agent on probation.

**Request Body:**
```json
{
  "reason": "Investigation complete, restoring service"
}
```

**Response (200 OK):**
```json
{
  "status": "resumed",
  "agent_id": "emailer",
  "trust_score": 60,
  "status": "FLAGGED",
  "probation_until": "2026-10-01T13:00:00Z"
}
```

---

### POST /admin/halt/{agent_id}

Manually halt an agent.

**Request Body:**
```json
{
  "reason": "Suspicious activity detected"
}
```

**Response (200 OK):**
```json
{
  "status": "halted",
  "agent_id": "researcher",
  "status": "HALTED"
}
```

---

### POST /admin/restore/{agent_id}

Restore agent config from trusted manifest.

**Response (200 OK):**
```json
{
  "status": "restored",
  "agent_id": "emailer",
  "steps": [
    {"step": "copy_trusted_config", "status": "success"},
    {"step": "verify_manifest_signature", "status": "success"},
    {"step": "rehash_config", "status": "success"},
    {"step": "verify_hash_match", "status": "success"}
  ],
  "config_hash_state": "matched"
}
```

---

### POST /admin/approve/{event_id}

Approve or reject a held action.

**Request Body:**
```json
{
  "approved": true,
  "reason": "Verified safe"
}
```

**Response (200 OK) - Approved:**
```json
{
  "status": "approved",
  "event_id": "evt-123",
  "executed": true
}
```

**Response (200 OK) - Rejected:**
```json
{
  "status": "rejected",
  "event_id": "evt-123",
  "executed": false,
  "penalty_applied": true
}
```

---

### POST /admin/tamper-log/{seq}

**DEMO MODE ONLY** - Tamper with an audit record for demonstration.

**Response (200 OK):**
```json
{
  "status": "tampered",
  "seq": 42,
  "original_hash": "abc123...",
  "new_hash": "xyz789..."
}
```

---

### POST /attack/{type}

Execute a simulated attack.

**Attack Types:**
- `injection` - Inject poisoned context and attempt forbidden action
- `tamper` - Tamper with agent config file
- `spike` - Send requests above rate limit
- `spread` - Quarantined agent attempts to message peers
- `impersonate` [W2] - Invalid signature attempt

**Response (200 OK):**
```json
{
  "attack": "injection",
  "expected": "BLOCK or HOLD",
  "actual": "BLOCK",
  "detected": true,
  "latency_ms": 4.2,
  "details": {
    "agent": "researcher",
    "tool": "send_email",
    "verdict": "BLOCK",
    "reason": "Tool not allowed for this agent"
  }
}
```

---

### WS /ws

WebSocket endpoint for live updates.

**Message Envelope:**
```json
{
  "type": "decision" | "incident" | "trust" | "status",
  "ts": "2026-10-01T12:00:00Z",
  "data": { ... }
}
```

**Decision Message:**
```json
{
  "type": "decision",
  "ts": "2026-10-01T12:00:00Z",
  "data": {
    "event_id": "evt-123",
    "agent_id": "researcher",
    "tool": "search_web",
    "verdict": "ALLOW",
    "response": "allow",
    "reason": "Tool allowed",
    "trust_before": 100,
    "trust_after": 100
  }
}
```

**Incident Message:**
```json
{
  "type": "incident",
  "ts": "2026-10-01T12:00:00Z",
  "data": {
    "incident_id": "inc-123",
    "agent_id": "emailer",
    "severity": "CRITICAL",
    "summary": "Config hash mismatch detected"
  }
}
```

**Trust Message:**
```json
{
  "type": "trust",
  "ts": "2026-10-01T12:00:00Z",
  "data": {
    "agent_id": "researcher",
    "score_before": 100,
    "score_after": 60,
    "reason": "tool_not_allowed"
  }
}
```

**Status Message:**
```json
{
  "type": "status",
  "ts": "2026-10-01T12:00:00Z",
  "data": {
    "agent_id": "emailer",
    "status_before": "HEALTHY",
    "status_after": "QUARANTINED",
    "reason": "config_hash_mismatch"
  }
}
```

---

## W2 Endpoints (Second Wave)

### GET /trust/{agent_id}

Get peer trust information for an agent.

**Response (200 OK):**
```json
{
  "agent_id": "researcher",
  "peer_trust_score": 85,
  "peer_count": 3,
  "trusted_by": ["emailer", "payments"]
}
```

---

### GET /metrics

Get benchmark metrics.

**Response (200 OK):**
```json
{
  "detection_rate": 0.98,
  "false_positive_rate": 0.03,
  "avg_latency_ms": 5.2,
  "quarantine_rejection_rate": 1.0,
  "audit_tamper_detection_rate": 1.0
}
```

---

## Error Responses

All endpoints may return standard error responses:

**400 Bad Request:**
```json
{
  "detail": "Invalid request: ..."
}
```

**401 Unauthorized:**
```json
{
  "detail": "Invalid or missing API key"
}
```

**403 Forbidden:**
```json
{
  "detail": "Agent is quarantined"
}
```

**404 Not Found:**
```json
{
  "detail": "Agent not found"
}
```

**500 Internal Server Error:**
```json
{
  "detail": "Internal error"
}
```

---

## Configuration Endpoints

### GET /config

Get current gateway configuration thresholds (read-only).

**Response (200 OK):**
```json
{
  "trust_healthy_min": 70,
  "trust_flag_min": 40,
  "trust_throttle_min": 20,
  "trust_recovery_per_min": 1.0,
  "trust_hysteresis": 5,
  "probation_start_score": 60,
  "probation_cap": 80,
  "probation_clean_min": 10,
  "rate_window_sec": 60,
  "rate_halt_after_violations": 5,
  "drift_zscore_threshold": 3.0
}
```
