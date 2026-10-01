# Twilight - Runtime Integrity Gateway for Multi-Agent Networks

Twilight is a trusted FastAPI gateway (a reference monitor) between untrusted AI agents and their tools. Every agent action is signed, sent to `POST /action`, and checked **before execution**.

## Phase 1 Complete: Contract Foundation

### What Was Built

1. **Frozen Contracts** (`gateway/schemas.py`)
   - All enum types: `Verdict`, `AgentStatus`, `Severity`
   - Pydantic models for all API boundaries
   - `canonical_json()` helper for signing/hashing
   - Single source of truth for API contracts

2. **Configuration** (`gateway/config.py`)
   - Typed settings object using Pydantic Settings
   - All configurable thresholds from the PRD
   - Loads from `.env` file

3. **Database** (`gateway/db.py`)
   - SQLite with WAL mode for concurrency
   - Transaction support with context manager
   - All required tables: agents, manifests, events, audit, audit_checkpoints, incidents, nonces, trust_history, held_actions, baselines
   - Prepared queries and indexes for performance

4. **Project Files**
   - `.env.example` - Configuration template
   - `.gitignore` - Excludes keys, data, secrets
   - `requirements.txt` - Python dependencies
   - `docs/api.md` - Complete API documentation with examples

5. **Key Generation Script** (`scripts/setup_keys.py`)
   - Generates Ed25519 keypairs for admin, gateway, and agents
   - Saves to `keys/` directory (gitignored)
   - Creates summary file for reference

6. **Tests** (`tests/test_phase1.py`)
   - Schema import and enum validation
   - Config loading
   - Database schema creation
   - Pydantic model validation
   - **All tests passing** ✓

### Directory Structure

```
twilight/
  README.md  requirements.txt  .env.example  .gitignore
  agents/      __init__.py configs/
  gateway/     __init__.py schemas.py config.py db.py
  engine/      __init__.py
  audit/       __init__.py
  policies/
  manifests/   trusted_configs/
  scripts/     setup_keys.py
  attacks/
  data/
  tests/       test_phase1.py
  docs/        api.md
```

### Key Design Decisions

1. **Signature Encoding**: Hex strings (PyNaCl Ed25519 default)
2. **Canonical JSON**: Sorted keys, compact separators, UTF-8, no whitespace
3. **HALT Status**: HALT is an agent status + `halted` response, not a verdict value
4. **Verdict Mapping**: BLOCK or QUARANTINE verdicts trigger HALT status
5. **Transaction Safety**: All writes use transactions for atomicity
6. **Thread Safety**: Thread-local database connections with global lock for audit serialization

### Next Steps (Phase 2)

- Build `base_agent.py` and 3 mock agents
- Create agent configs and policies
- Implement `sign_manifests.py`
- Build `/register` and `/action` endpoints with steps 1-4, 10-12
- Implement mock tools in `gateway/tools.py`
- Add WebSocket support in `gateway/websocket.py`

### Running Tests

```bash
# Install dependencies
pip install -r requirements.txt

# Run Phase 1 tests
pytest tests/test_phase1.py -v
```

### Generating Keys

```bash
python scripts/setup_keys.py
```

This creates Ed25519 keypairs in `keys/`:
- `admin_private.pem` / `admin_public.pem` - For signing manifests
- `gateway_private.pem` / `gateway_public.pem` - For audit checkpoints
- `*_private.pem` / `*_public.pem` - For each agent

## License

Prototype for Repoforge 2026 (PS002)
