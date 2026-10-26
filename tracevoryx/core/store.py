"""Local storage: SQLite with migrations, tamper-evident event chain,
findings, approvals, sensor health, retention. Single-writer per process;
the chain head is derived from the DB (not memory) so multiple Store
instances on one file stay consistent.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from ..config import get_settings
from .events import TrustEvent, utcnow_iso

SCHEMA_VERSION = 1

_MIGRATIONS: dict[int, str] = {
    1: """
    CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        host TEXT NOT NULL,
        event_type TEXT NOT NULL,
        source TEXT NOT NULL,
        actor TEXT NOT NULL,
        target TEXT NOT NULL,
        destination TEXT NOT NULL,
        pid INTEGER, exe TEXT, parent_pid INTEGER, parent_exe TEXT,
        trust_label TEXT NOT NULL,
        sensitive INTEGER NOT NULL DEFAULT 0,
        evidence TEXT NOT NULL, source_ref TEXT NOT NULL,
        correlation_confidence REAL NOT NULL,
        collection_limitations TEXT NOT NULL,
        details TEXT NOT NULL,
        prev_hash TEXT NOT NULL, hash TEXT NOT NULL, received_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_events_ts ON events(timestamp);
    CREATE INDEX IF NOT EXISTS ix_events_actor ON events(actor);
    CREATE INDEX IF NOT EXISTS ix_events_type ON events(event_type);

    CREATE TABLE IF NOT EXISTS provenance_nodes (
        node_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        key TEXT NOT NULL,
        label TEXT NOT NULL,
        trust_label TEXT NOT NULL,
        sensitive INTEGER NOT NULL DEFAULT 0,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        meta TEXT NOT NULL DEFAULT '{}',
        UNIQUE(kind, key)
    );
    CREATE TABLE IF NOT EXISTS provenance_edges (
        edge_id TEXT PRIMARY KEY,
        src TEXT NOT NULL, dst TEXT NOT NULL,
        relation TEXT NOT NULL,
        event_id TEXT NOT NULL,
        observed INTEGER NOT NULL DEFAULT 1,
        confidence REAL NOT NULL,
        timestamp TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_edges_src ON provenance_edges(src);
    CREATE INDEX IF NOT EXISTS ix_edges_dst ON provenance_edges(dst);

    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        detection_id TEXT NOT NULL, detection_version TEXT NOT NULL,
        severity TEXT NOT NULL, confidence REAL NOT NULL,
        title TEXT NOT NULL,
        timeline TEXT NOT NULL,        -- JSON [{ts, event_id, what}]
        supporting_events TEXT NOT NULL,   -- JSON [event_id]
        contradictory_evidence TEXT NOT NULL, -- JSON
        rule TEXT NOT NULL, action_taken TEXT NOT NULL,
        blind_spots TEXT NOT NULL,     -- JSON [str]
        suggested_response TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        false_positive INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS approvals (
        approval_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        agent TEXT NOT NULL, tool TEXT NOT NULL,
        reason TEXT NOT NULL,
        summary TEXT NOT NULL,
        event_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|denied|expired
        decided_at TEXT
    );

    CREATE TABLE IF NOT EXISTS sensor_health (
        sensor TEXT PRIMARY KEY,
        status TEXT NOT NULL DEFAULT 'up',  -- up|down|degraded
        last_beat TEXT,
        events_collected INTEGER NOT NULL DEFAULT 0,
        errors INTEGER NOT NULL DEFAULT 0,
        last_error TEXT
    );

    CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    """,
}


def canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class StoreClosedError(RuntimeError):
    """Raised when the store is used after close() — a lifecycle bug, not a
    silent no-op."""


class Store:
    def __init__(self, db_path: Optional[Path] = None):
        self.settings = get_settings()
        self.db_path = db_path or self.settings.data_dir / "tracevoryx.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._closed = False
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._migrate()

    def _ensure_open(self) -> None:
        if self._closed:
            raise StoreClosedError(
                "store already closed (lifecycle bug: a worker used the "
                "store after shutdown)")

    def _migrate(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(version INTEGER PRIMARY KEY, applied_at TEXT)"
        )
        applied = {
            r["version"] for r in
            self._conn.execute("SELECT version FROM schema_migrations").fetchall()
        }
        for version in sorted(_MIGRATIONS):
            if version in applied:
                continue
            self._conn.executescript(_MIGRATIONS[version])
            self._conn.execute(
                "INSERT INTO schema_migrations VALUES (?, ?)",
                (version, utcnow_iso()),
            )
        self._conn.commit()

    # ------------------------------------------------------------- events
    def append_event(self, event: TrustEvent, redact_keys: Optional[set[str]] = None) -> dict:
        self._ensure_open()  # fast path (checked again under the lock below)
        payload = event.model_dump()
        keys = redact_keys if redact_keys is not None else set(
            get_settings().get("redact_keys", []))
        payload["evidence"] = [_redact_dict(e, keys) for e in payload["evidence"]]
        payload["details"] = _redact_dict(payload["details"], keys)
        with self._lock:
            # re-check under the lock: a concurrent close() must not
            # interleave between the open-check and the first sqlite
            # statement (would surface as a bare sqlite3.ProgrammingError
            # instead of the documented StoreClosedError)
            self._ensure_open()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT hash FROM events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev = row["hash"] if row else "GENESIS"
                digest = hashlib.sha256((canon(payload) + prev).encode()).hexdigest()
                self._conn.execute(
                    """INSERT INTO events (event_id, timestamp, host, event_type,
                       source, actor, target, destination, pid, exe, parent_pid,
                       parent_exe, trust_label, sensitive, evidence, source_ref,
                       correlation_confidence, collection_limitations, details,
                       prev_hash, hash, received_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (payload["event_id"], payload["timestamp"], payload["host"],
                     payload["event_type"], payload["source"], payload["actor"],
                     payload["target"], payload["destination"], payload["pid"],
                     payload["exe"], payload["parent_pid"], payload["parent_exe"],
                     payload["trust_label"], int(payload["sensitive"]),
                     canon(payload["evidence"]), payload["source_ref"],
                     payload["correlation_confidence"],
                     canon(payload["collection_limitations"]),
                     canon(payload["details"]), prev, digest, utcnow_iso()),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                # concurrent duplicate: return the already-stored event
                self._conn.rollback()
                existing = self._conn.execute(
                    "SELECT * FROM events WHERE event_id=?",
                    (payload["event_id"],)).fetchone()
                if existing:
                    return self._existing_to_payload(existing)
                raise
            except Exception:
                self._conn.rollback()
                raise
        return {**payload, "hash": digest, "prev_hash": prev}

    @staticmethod
    def _existing_to_payload(r: sqlite3.Row) -> dict:
        return {
            "event_id": r["event_id"], "timestamp": r["timestamp"],
            "host": r["host"], "event_type": r["event_type"],
            "source": r["source"], "actor": r["actor"], "target": r["target"],
            "destination": r["destination"], "pid": r["pid"], "exe": r["exe"],
            "parent_pid": r["parent_pid"], "parent_exe": r["parent_exe"],
            "trust_label": r["trust_label"], "sensitive": bool(r["sensitive"]),
            "evidence": json.loads(r["evidence"]), "source_ref": r["source_ref"],
            "correlation_confidence": r["correlation_confidence"],
            "collection_limitations": json.loads(r["collection_limitations"]),
            "details": json.loads(r["details"]),
            "hash": r["hash"], "prev_hash": r["prev_hash"], "duplicate": True,
        }

    def integrity_check(self) -> dict:
        with self._lock:
            row = self._conn.execute("PRAGMA integrity_check").fetchone()
        return {"sqlite_integrity": row[0] if row else "unknown"}

    def query_events(self, event_type: str | None = None, actor: str | None = None,
                     since: str | None = None, limit: int = 200,
                     sensitive: bool | None = None) -> list[dict]:
        self._ensure_open()
        q = "SELECT * FROM events WHERE 1=1"
        args: list[Any] = []
        if event_type:
            q += " AND event_type=?"
            args.append(event_type)
        if actor:
            q += " AND actor LIKE ?"
            args.append(f"%{actor}%")
        if since:
            q += " AND timestamp>=?"
            args.append(since)
        if sensitive is not None:
            q += " AND sensitive=?"
            args.append(int(sensitive))
        q += " ORDER BY seq DESC LIMIT ?"
        args.append(min(limit, 5000))
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"])
            d["details"] = json.loads(d["details"])
            d["collection_limitations"] = json.loads(d["collection_limitations"])
            d["sensitive"] = bool(d["sensitive"])
            out.append(d)
        return out

    def verify_chain(self) -> dict:
        self._ensure_open()
        with self._lock:
            rows = self._conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
        if not rows:
            return {"valid": True, "checked": 0}
        base = self.chain_base()
        first = rows[0]
        if int(first["seq"]) > 1:
            # older events were removed (retention); the anchor recorded at
            # cleanup time must match the first remaining row exactly
            if not base or int(base.get("seq", -1)) != int(first["seq"]) \
                    or base.get("hash") != first["hash"] \
                    or base.get("prev_hash") != first["prev_hash"]:
                return {"valid": False, "checked": 0,
                        "broken_at_seq": first["seq"],
                        "note": "chain start does not match the retention "
                                "anchor (history may have been deleted)"}
            prev = str(first["prev_hash"])
        elif base and int(base.get("seq", -1)) == int(first["seq"]):
            prev = str(first["prev_hash"])  # anchored base of a single-row chain
        else:
            prev = "GENESIS"
        for i, r in enumerate(rows):
            payload = {
                "event_id": r["event_id"], "timestamp": r["timestamp"],
                "host": r["host"], "event_type": r["event_type"],
                "source": r["source"], "actor": r["actor"], "target": r["target"],
                "destination": r["destination"], "pid": r["pid"], "exe": r["exe"],
                "parent_pid": r["parent_pid"], "parent_exe": r["parent_exe"],
                "trust_label": r["trust_label"], "sensitive": bool(r["sensitive"]),
                "evidence": json.loads(r["evidence"]), "source_ref": r["source_ref"],
                "correlation_confidence": r["correlation_confidence"],
                "collection_limitations": json.loads(r["collection_limitations"]),
                "details": json.loads(r["details"]),
            }
            digest = hashlib.sha256((canon(payload) + prev).encode()).hexdigest()
            if digest != r["hash"] or r["prev_hash"] != prev:
                return {"valid": False, "checked": i, "broken_at_seq": r["seq"]}
            prev = digest
        return {"valid": True, "checked": len(rows)}

    def retention_cleanup(self, days: int | None = None) -> int:
        """Delete events older than the retention window.

        Deleting the oldest events would otherwise invalidate the hash chain
        forever (GENESIS-based verification). After deleting, the first
        remaining row is recorded as the chain base in kv; verify_chain()
        then treats that row as the trust origin for the remaining history.
        Deleting a range in the middle still breaks the prev_hash link, and a
        full-database rewrite is still detected by signed checkpoints
        (rewritten head != signed checkpoint head)."""
        self._ensure_open()
        days = days if days is not None else int(self.settings.get("retention_days", 30))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            cur = self._conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            removed = cur.rowcount
            if removed:
                first = self._conn.execute(
                    "SELECT seq, prev_hash, hash FROM events ORDER BY seq ASC LIMIT 1"
                ).fetchone()
                if first:
                    self._conn.execute(
                        "INSERT INTO kv(key,value) VALUES('tw_chain_base',?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (canon({"seq": int(first["seq"]),
                                "prev_hash": first["prev_hash"],
                                "hash": first["hash"],
                                "anchored_at": utcnow_iso()}),))
            self._conn.commit()
            return removed

    def chain_base(self) -> Optional[dict]:
        self._ensure_open()
        with self._lock:
            r = self._conn.execute(
                "SELECT value FROM kv WHERE key='tw_chain_base'").fetchone()
        if not r:
            return None
        try:
            base = json.loads(r["value"])
        except (ValueError, TypeError):
            return None
        return base if isinstance(base, dict) and base.get("seq") else None

    # --------------------------------------------------------- findings
    def insert_finding(self, f: dict) -> None:
        self._ensure_open()
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO findings (finding_id, created_at,
                   detection_id, detection_version, severity, confidence, title,
                   timeline, supporting_events, contradictory_evidence, rule,
                   action_taken, blind_spots, suggested_response, status, false_positive)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (f["finding_id"], f["created_at"], f["detection_id"],
                 f["detection_version"], f["severity"], f["confidence"],
                 f["title"], canon(f["timeline"]), canon(f["supporting_events"]),
                 canon(f.get("contradictory_evidence", [])), f["rule"],
                 f["action_taken"], canon(f.get("blind_spots", [])),
                 f["suggested_response"], f.get("status", "open"),
                 int(f.get("false_positive", 0))),
            )
            self._conn.commit()

    def list_findings(self, status: str | None = None, limit: int = 200) -> list[dict]:
        self._ensure_open()
        q = "SELECT * FROM findings"
        args: list[Any] = []
        if status:
            q += " WHERE status=?"
            args.append(status)
        q += " ORDER BY created_at DESC LIMIT ?"
        args.append(min(limit, 1000))
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            for f in ("timeline", "supporting_events", "contradictory_evidence", "blind_spots"):
                d[f] = json.loads(d[f])
            d["false_positive"] = bool(d["false_positive"])
            out.append(d)
        return out

    def mark_finding(self, finding_id: str, status: str | None = None,
                     false_positive: bool | None = None) -> bool:
        self._ensure_open()
        with self._lock:
            if status is not None:
                self._conn.execute(
                    "UPDATE findings SET status=? WHERE finding_id=?",
                    (status, finding_id))
            if false_positive is not None:
                self._conn.execute(
                    "UPDATE findings SET false_positive=?, status='dismissed' WHERE finding_id=?",
                    (int(false_positive), finding_id))
            self._conn.commit()
            row = self._conn.execute(
                "SELECT 1 FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
            return row is not None

    # -------------------------------------------------------- approvals
    def add_approval(self, rec: dict) -> None:
        self._ensure_open()
        with self._lock:
            self._conn.execute(
                """INSERT INTO approvals (approval_id, created_at, expires_at,
                   agent, tool, reason, summary, event_id, status)
                   VALUES (?,?,?,?,?,?,?,?, 'pending')""",
                (rec["approval_id"], rec["created_at"], rec["expires_at"],
                 rec["agent"], rec["tool"], rec["reason"], rec["summary"],
                 rec["event_id"]),
            )
            self._conn.commit()

    def get_approval(self, approval_id: str) -> Optional[dict]:
        self._ensure_open()
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM approvals WHERE approval_id=?", (approval_id,)
            ).fetchone()
        return dict(r) if r else None

    def find_pending_approval(self, agent: str, tool: str) -> Optional[dict]:
        self._ensure_open()
        now = utcnow_iso()
        with self._lock:
            self._conn.execute(
                "UPDATE approvals SET status='expired' WHERE status='pending' AND expires_at < ?",
                (now,))
            self._conn.commit()
            r = self._conn.execute(
                "SELECT * FROM approvals WHERE agent=? AND tool=? AND status='pending' "
                "ORDER BY created_at DESC LIMIT 1", (agent, tool)).fetchone()
        return dict(r) if r else None

    def decide_approval(self, approval_id: str, decision: str) -> bool:
        self._ensure_open()
        if decision not in ("approved", "denied"):
            raise ValueError("decision must be approved|denied")
        with self._lock:
            cur = self._conn.execute(
                "UPDATE approvals SET status=?, decided_at=? "
                "WHERE approval_id=? AND status='pending'",
                (decision, utcnow_iso(), approval_id))
            self._conn.commit()
            return cur.rowcount > 0

    def list_approvals(self, status: str | None = None) -> list[dict]:
        self._ensure_open()
        q = "SELECT * FROM approvals"
        args: list[Any] = []
        if status:
            q += " WHERE status=?"
            args.append(status)
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    # --------------------------------------------------- sensor health
    def beat_sensor(self, sensor: str, status: str = "up",
                    error: str | None = None) -> None:
        self._ensure_open()
        with self._lock:
            self._conn.execute(
                """INSERT INTO sensor_health
                   (sensor, status, last_beat, events_collected, errors, last_error)
                   VALUES (?,?,?,1,?,?)
                   ON CONFLICT(sensor) DO UPDATE SET status=excluded.status,
                   last_beat=excluded.last_beat,
                   events_collected=events_collected+1,
                   errors=errors+excluded.errors, last_error=excluded.last_error""",
                (sensor, status, utcnow_iso(), 1 if error else 0, error),
            )
            self._conn.commit()

    def sensor_health(self) -> list[dict]:
        self._ensure_open()
        with self._lock:
            rows = self._conn.execute("SELECT * FROM sensor_health ORDER BY sensor").fetchall()
        return [dict(r) for r in rows]

    # --------------------------------------------------------------- kv
    def kv_get(self, key: str, default: Any = None) -> Any:
        self._ensure_open()
        with self._lock:
            r = self._conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(r["value"]) if r else default

    def kv_set(self, key: str, value: Any) -> None:
        self._ensure_open()
        with self._lock:
            self._conn.execute(
                "INSERT INTO kv(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, canon(value)))
            self._conn.commit()

    def kv_consume_if_unused(self, key: str, now_iso: str) -> bool:
        """Atomically consume a single-use kv binding.

        Read-check-write is NOT atomic across threads even under one process
        lock between separate calls; this performs the whole decision inside
        a single lock hold and finishes with a compare-and-swap UPDATE whose
        rowcount decides the winner, so concurrent consumers cannot both
        succeed (in-process AND multi-process against the same DB file).
        Expired bindings are consumed (disabled) and refused."""
        with self._lock:
            self._ensure_open()
            r = self._conn.execute(
                "SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            if not r:
                return False
            try:
                val = json.loads(r["value"])
            except (ValueError, TypeError):
                return False
            if not isinstance(val, dict) or val.get("used"):
                return False
            used_val = {**val, "used": True}
            if str(val.get("expires_at", "")) < now_iso:
                self._conn.execute(
                    "UPDATE kv SET value=? WHERE key=? AND value=?",
                    (canon({**used_val, "consumed_reason": "expired"}),
                     key, r["value"]))
                self._conn.commit()
                return False
            cur = self._conn.execute(
                "UPDATE kv SET value=? WHERE key=? AND value=?",
                (canon(used_val), key, r["value"]))
            self._conn.commit()
            return cur.rowcount == 1

    def execute(self, sql: str, args: tuple = (), fetch: bool = False):
        with self._lock:
            self._ensure_open()
            cur = self._conn.execute(sql, args)
            self._conn.commit()
            if fetch:
                return [dict(r) for r in cur.fetchall()]
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return  # idempotent
            self._closed = True
            self._conn.close()


def _redact_dict(d: dict, keys: set[str]) -> dict:
    out = {}
    for k, v in d.items():
        if k in keys and isinstance(v, str) and v:
            out[k] = v[:3] + "…[REDACTED]" if len(v) > 8 else "[REDACTED]"
        elif isinstance(v, dict):
            out[k] = _redact_dict(v, keys)
        elif isinstance(v, list):
            out[k] = _redact_list(v, keys)
        else:
            out[k] = v
    return out


def _redact_list(items: list, keys: set[str]) -> list:
    out = []
    for v in items:
        if isinstance(v, dict):
            out.append(_redact_dict(v, keys))
        elif isinstance(v, list):
            out.append(_redact_list(v, keys))
        else:
            out.append(v)
    return out
