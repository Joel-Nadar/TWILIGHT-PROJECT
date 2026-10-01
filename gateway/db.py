"""
Database module for Twilight Gateway.
SQLite with WAL mode, transactions, and prepared queries.
"""
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Dict, Any, List
from gateway.config import settings


class Database:
    """SQLite database manager with WAL mode and transaction support"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.db_path
        self._local = threading.local()
        self._lock = threading.Lock()
        self._ensure_db_dir()
    
    def _ensure_db_dir(self):
        """Ensure database directory exists"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    def get_connection(self) -> sqlite3.Connection:
        """Get thread-local connection with WAL mode"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn
    
    @contextmanager
    def transaction(self):
        """Context manager for transactions"""
        conn = self.get_connection()
        try:
            conn.execute("BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    
    def create_schema(self):
        """Create all database tables and indexes"""
        with self.transaction() as conn:
            # Agents table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'HEALTHY',
                    trust_score INTEGER NOT NULL DEFAULT 100,
                    probation_until TEXT,
                    last_seen TEXT,
                    current_rate_limit INTEGER,
                    config_hash_state TEXT DEFAULT 'matched'
                )
            """)
            
            # Manifests table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS manifests (
                    agent_id TEXT PRIMARY KEY,
                    manifest_json TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    admin_signature TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)
            
            # Events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    context_json TEXT,
                    nonce TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    verdict TEXT,
                    response TEXT,
                    reason TEXT,
                    rule TEXT,
                    severity TEXT,
                    trust_before INTEGER,
                    trust_after INTEGER,
                    status TEXT,
                    evidence_json TEXT,
                    latency_ms REAL,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)
            
            # Audit chain table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    signature TEXT,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)
            
            # Audit checkpoints table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_checkpoints (
                    seq INTEGER PRIMARY KEY,
                    record_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    ts TEXT NOT NULL
                )
            """)
            
            # Incidents table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    resolved BOOLEAN NOT NULL DEFAULT 0,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)
            
            # Nonces table for replay protection
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce TEXT PRIMARY KEY,
                    ts TEXT NOT NULL
                )
            """)
            
            # Trust history table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trust_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)
            
            # Held actions table for HOLD queue
            conn.execute("""
                CREATE TABLE IF NOT EXISTS held_actions (
                    event_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    decided_at TEXT,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)
            
            # Heartbeat challenges table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS heartbeat_challenges (
                    agent_id TEXT NOT NULL,
                    nonce TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)
            
            # Baselines table (W2)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    agent_id TEXT PRIMARY KEY,
                    baseline_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_agent_id ON audit(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_agent_id ON incidents(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_trust_history_agent_id ON trust_history(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_trust_history_ts ON trust_history(ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nonces_ts ON nonces(ts)")
    
    def insert_agent(self, agent_id: str, public_key: str, status: str = "HEALTHY", trust_score: int = 100):
        """Insert or update agent record"""
        with self.transaction() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO agents 
                (agent_id, public_key, status, trust_score, last_seen, config_hash_state)
                VALUES (?, ?, ?, ?, datetime('now'), 'matched')
            """, (agent_id, public_key, status, trust_score))
    
    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get agent by ID"""
        conn = self.get_connection()
        row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        return dict(row) if row else None
    
    def update_agent_status(self, agent_id: str, status: str, trust_score: Optional[int] = None):
        """Update agent status and optionally trust score"""
        with self.transaction() as conn:
            if trust_score is not None:
                conn.execute("""
                    UPDATE agents SET status = ?, trust_score = ?, last_seen = datetime('now')
                    WHERE agent_id = ?
                """, (status, trust_score, agent_id))
            else:
                conn.execute("""
                    UPDATE agents SET status = ?, last_seen = datetime('now')
                    WHERE agent_id = ?
                """, (status, agent_id))
    
    def insert_nonce(self, nonce: str, ts: str):
        """Insert nonce for replay protection"""
        with self.transaction() as conn:
            conn.execute("INSERT INTO nonces (nonce, ts) VALUES (?, ?)", (nonce, ts))
    
    def nonce_exists(self, nonce: str) -> bool:
        """Check if nonce has been used"""
        conn = self.get_connection()
        row = conn.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,)).fetchone()
        return row is not None
    
    def insert_event(self, event: Dict[str, Any]):
        """Insert event record"""
        import json
        with self.transaction() as conn:
            conn.execute("""
                INSERT INTO events (
                    event_id, ts, agent_id, type, tool, args_json, context_json,
                    nonce, signature, verdict, response, reason, rule, severity,
                    trust_before, trust_after, status, evidence_json, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get("event_id"),
                event.get("ts"),
                event.get("agent_id"),
                event.get("type"),
                event.get("tool"),
                json.dumps(event.get("args", {})),
                json.dumps(event.get("context", {})),
                event.get("nonce"),
                event.get("signature"),
                event.get("verdict"),
                event.get("response"),
                event.get("reason"),
                event.get("rule"),
                event.get("severity"),
                event.get("trust_before"),
                event.get("trust_after"),
                event.get("status"),
                json.dumps(event.get("evidence", {})),
                event.get("latency_ms")
            ))
    
    def append_audit_record(self, record: Dict[str, Any]) -> int:
        """Append audit record and return sequence number"""
        import json
        with self.transaction() as conn:
            cursor = conn.execute("""
                INSERT INTO audit (ts, agent_id, record_json, prev_hash, record_hash, signature)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                record["timestamp"],
                record["agent_id"],
                record["record_json"],
                record["prev_hash"],
                record["record_hash"],
                record.get("signature")
            ))
            return cursor.lastrowid
    
    def get_audit_records(self, agent_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit records, optionally filtered by agent"""
        conn = self.get_connection()
        if agent_id:
            rows = conn.execute("""
                SELECT * FROM audit WHERE agent_id = ? ORDER BY seq DESC LIMIT ?
            """, (agent_id, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM audit ORDER BY seq DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(row) for row in rows]
    
    def get_audit_chain_for_verify(self) -> List[Dict[str, Any]]:
        """Get all audit records in order for verification"""
        conn = self.get_connection()
        rows = conn.execute("SELECT * FROM audit ORDER BY seq ASC").fetchall()
        return [dict(row) for row in rows]
    
    def insert_incident(self, incident: Dict[str, Any]):
        """Insert incident record"""
        with self.transaction() as conn:
            conn.execute("""
                INSERT INTO incidents (incident_id, ts, agent_id, severity, summary, resolved)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                incident.get("incident_id"),
                incident.get("ts"),
                incident.get("agent_id"),
                incident.get("severity"),
                incident.get("summary"),
                incident.get("resolved", False)
            ))
    
    def get_incidents(self, agent_id: Optional[str] = None, resolved: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Get incidents, optionally filtered"""
        conn = self.get_connection()
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        
        if resolved is not None:
            query += " AND resolved = ?"
            params.append(resolved)
        
        query += " ORDER BY ts DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
    
    def insert_trust_history(self, agent_id: str, score: int, reason: str):
        """Insert trust history entry"""
        with self.transaction() as conn:
            conn.execute("""
                INSERT INTO trust_history (agent_id, ts, score, reason)
                VALUES (?, datetime('now'), ?, ?)
            """, (agent_id, score, reason))
    
    def get_trust_history(self, agent_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get trust history for an agent"""
        conn = self.get_connection()
        rows = conn.execute("""
            SELECT * FROM trust_history WHERE agent_id = ? 
            ORDER BY ts DESC LIMIT ?
        """, (agent_id, limit)).fetchall()
        return [dict(row) for row in rows]
    
    def insert_held_action(self, event_id: str, agent_id: str, event_json: str):
        """Insert held action into queue"""
        with self.transaction() as conn:
            conn.execute("""
                INSERT INTO held_actions (event_id, agent_id, event_json, status, decided_at)
                VALUES (?, ?, ?, 'PENDING', datetime('now'))
            """, (event_id, agent_id, event_json))
    
    def get_held_action(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Get held action by event ID"""
        conn = self.get_connection()
        row = conn.execute("SELECT * FROM held_actions WHERE event_id = ?", (event_id,)).fetchone()
        return dict(row) if row else None
    
    def update_held_action_status(self, event_id: str, status: str):
        """Update held action status"""
        with self.transaction() as conn:
            conn.execute("""
                UPDATE held_actions SET status = ?, decided_at = datetime('now')
                WHERE event_id = ?
            """, (status, event_id))
    
    def insert_manifest(self, agent_id: str, manifest_json: str, config_hash: str, admin_signature: str):
        """Insert or update manifest"""
        with self.transaction() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO manifests (agent_id, manifest_json, config_hash, admin_signature, created_at)
                VALUES (?, ?, ?, ?, datetime('now'))
            """, (agent_id, manifest_json, config_hash, admin_signature))
    
    def get_manifest(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get manifest by agent ID"""
        conn = self.get_connection()
        row = conn.execute("SELECT * FROM manifests WHERE agent_id = ?", (agent_id,)).fetchone()
        return dict(row) if row else None
    
    def get_all_agents(self) -> List[Dict[str, Any]]:
        """Get all agents"""
        conn = self.get_connection()
        rows = conn.execute("SELECT * FROM agents").fetchall()
        return [dict(row) for row in rows]
    
    def tamper_audit_row(self, seq: int, new_record_json: str):
        """Directly edit an audit row (demo attack only)"""
        with self.transaction() as conn:
            conn.execute("""
                UPDATE audit SET record_json = ? WHERE seq = ?
            """, (new_record_json, seq))
    
    def get_audit_record_by_seq(self, seq: int) -> Optional[Dict[str, Any]]:
        """Get a specific audit record by sequence number"""
        conn = self.get_connection()
        row = conn.execute("SELECT * FROM audit WHERE seq = ?", (seq,)).fetchone()
        return dict(row) if row else None
    
    def get_last_audit_seq(self) -> int:
        """Get the last audit sequence number"""
        conn = self.get_connection()
        row = conn.execute("SELECT MAX(seq) as max_seq FROM audit").fetchone()
        return row["max_seq"] if row and row["max_seq"] else 0
    
    def insert_checkpoint(self, seq: int, record_hash: str, signature: str):
        """Insert audit checkpoint"""
        with self.transaction() as conn:
            conn.execute("""
                INSERT INTO audit_checkpoints (seq, record_hash, signature, ts)
                VALUES (?, ?, ?, datetime('now'))
            """, (seq, record_hash, signature))
    
    def get_checkpoints(self) -> List[Dict[str, Any]]:
        """Get all audit checkpoints"""
        conn = self.get_connection()
        rows = conn.execute("SELECT * FROM audit_checkpoints ORDER BY seq ASC").fetchall()
        return [dict(row) for row in rows]
    
    def insert_heartbeat_challenge(self, agent_id: str, nonce: str, expires_at: str):
        """Insert a heartbeat challenge"""
        with self.transaction() as conn:
            conn.execute("""
                INSERT INTO heartbeat_challenges (agent_id, nonce, created_at, expires_at)
                VALUES (?, ?, datetime('now'), ?)
            """, (agent_id, nonce, expires_at))
    
    def get_heartbeat_challenge(self, nonce: str) -> Optional[Dict[str, Any]]:
        """Get a heartbeat challenge by nonce"""
        conn = self.get_connection()
        row = conn.execute("SELECT * FROM heartbeat_challenges WHERE nonce = ?", (nonce,)).fetchone()
        return dict(row) if row else None
    
    def delete_heartbeat_challenge(self, nonce: str):
        """Delete a heartbeat challenge after use"""
        with self.transaction() as conn:
            conn.execute("DELETE FROM heartbeat_challenges WHERE nonce = ?", (nonce,))
    
    def mark_incident_resolved(self, incident_id: str):
        """Mark an incident as resolved"""
        with self.transaction() as conn:
            conn.execute("UPDATE incidents SET resolved = 1 WHERE incident_id = ?", (incident_id,))
    
    def get_incidents(self, agent_id: Optional[str] = None, resolved: Optional[bool] = None, 
                      severity: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get incidents with optional filters"""
        conn = self.get_connection()
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if resolved is not None:
            query += " AND resolved = ?"
            params.append(1 if resolved else 0)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
    
    def update_agent_probation(self, agent_id: str, probation_until: Optional[str]):
        """Update agent probation status"""
        with self.transaction() as conn:
            if probation_until:
                conn.execute("""
                    UPDATE agents SET probation_until = ? WHERE agent_id = ?
                """, (probation_until, agent_id))
            else:
                conn.execute("""
                    UPDATE agents SET probation_until = NULL WHERE agent_id = ?
                """, (agent_id,))
    
    def expire_old_challenges(self):
        """Delete expired heartbeat challenges"""
        with self.transaction() as conn:
            conn.execute("DELETE FROM heartbeat_challenges WHERE expires_at < datetime('now')")
    
    def get_agents_with_history(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get agents with their trust history"""
        conn = self.get_connection()
        if agent_id:
            rows = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM agents").fetchall()
        
        agents = []
        for row in rows:
            agent = dict(row)
            # Get trust history
            history_rows = conn.execute("""
                SELECT ts, score, reason FROM trust_history 
                WHERE agent_id = ? ORDER BY ts DESC LIMIT 10
            """, (agent['agent_id'],)).fetchall()
            agent['trust_history'] = [dict(row) for row in history_rows]
            agents.append(agent)
        
        return agents
    
    def close(self):
        """Close database connection"""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Global database instance
db = Database()
