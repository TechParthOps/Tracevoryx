"""Shared application singletons — 0.2.0 security model.

Tokens: generated once, displayed ONCE, stored as SHA-256 hashes in
data/api_tokens.json (never plaintext). Roles:
  admin   — full control API
  analyst — read-only (events, findings, graph)
  agent   — gateway + result reporting only
A plaintext token in data/api_token from v0.1.0 is treated as compromised:
if found, it is ignored and a fresh admin token is generated.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .agent_guard.gateway import MCPGateway
from .agent_guard.registry import AgentRegistry
from .api_mapper.mapper import ApiMapper
from .collector.clipboard_win import ClipboardSensor
from .collector.process import ProcessCollector
from .collector.win_eventlog import WinEventLogCollector
from .config import get_settings
from .core.approvals import ApprovalManager
from .core.bus import EventBus
from .core.logging_util import log_error, log_event, setup_logging
from .core.pipeline import EventPipeline
from .core.policy import PolicyEngine
from .core.store import Store
from .privacy_guard.service import PrivacyService

ROLES = ("admin", "analyst", "agent")


def _tokens_path(data_dir: Path) -> Path:
    return data_dir / "api_tokens.json"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def load_token_records(data_dir: Path) -> dict:
    p = _tokens_path(data_dir)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {}


def save_token_records(data_dir: Path, records: dict) -> None:
    p = _tokens_path(data_dir)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(records, indent=2), encoding="utf-8")
    tmp.replace(p)


def issue_token(data_dir: Path, role: str = "admin",
                label: str = "", ttl_s: int | None = None) -> str:
    """Generate a new token, store ONLY its hash, return plaintext once.

    ttl_s optionally bounds the token's lifetime (expiry checked at every
    authentication). For agent tokens the label is the agent identity the
    token is bound to at the gateway."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    token = "tw_" + secrets.token_urlsafe(32)
    records = load_token_records(data_dir)
    rec: dict = {
        "role": role, "label": label,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc)
                       + timedelta(seconds=int(ttl_s))).isoformat()
        if ttl_s else None,
    }
    records[_hash(token)] = rec
    save_token_records(data_dir, records)
    return token


def authenticate_record(data_dir: Path, token: str) -> Optional[dict]:
    """Return the token record {role, label, expires_at} for a valid,
    unexpired token, else None. Expired tokens are removed lazily."""
    if not token:
        return None
    records = load_token_records(data_dir)
    h = _hash(token)
    rec = records.get(h)
    if not rec:
        return None
    expires_at = rec.get("expires_at")
    if expires_at:
        now = datetime.now(timezone.utc).isoformat()
        if str(expires_at) < now:
            # expired: lazily remove so revocation state stays tidy
            records.pop(h, None)
            save_token_records(data_dir, records)
            return None
    return rec


def authenticate(data_dir: Path, token: str) -> Optional[str]:
    """Return the role for a valid, unexpired token, else None.

    Note on timing: candidate tokens are SHA-256 hashed before lookup, so a
    timing side channel over the dict probe leaks nothing about preimages."""
    rec = authenticate_record(data_dir, token)
    return rec["role"] if rec else None


def revoke_token(data_dir: Path, token: str) -> bool:
    """Remove a token by its plaintext (we hash-compare to the stored hash)."""
    records = load_token_records(data_dir)
    h = _hash(token)
    if h in records:
        del records[h]
        save_token_records(data_dir, records)
        return True
    return False


def bootstrap_tokens(data_dir: Path, logger=None) -> str:
    """First-run: create an admin token; migrate/retire v0.1.0 plaintext."""
    records = load_token_records(data_dir)
    if records:
        return ""  # already bootstrapped; tokens issued via CLI/API
    legacy = data_dir / "api_token"
    if legacy.exists():
        legacy.unlink()  # v0.1.0 plaintext token is retired (compromised)
        if logger:
            log_event(logger, "legacy_plaintext_token_retired")
    return issue_token(data_dir, "admin", "bootstrap-admin")


class AppState:
    def __init__(self):
        self.settings = get_settings()
        self.logger = setup_logging(self.settings.data_dir,
                                    self.settings.get("log_level", "INFO"))
        self._stopping = threading.Event()
        self._shutdown_done = False
        self._shutdown_lock = threading.Lock()
        self.store = Store()
        self.bus = EventBus(self.store)
        self.pipeline = EventPipeline(self.bus, self.store, maxsize=int(
            self.settings.get("pipeline.max_queue", 5000)))
        self.policy = PolicyEngine()
        self.registry = AgentRegistry(self.store)
        self.privacy = PrivacyService(self.store)
        self.graph = self.bus.graph
        self.approvals = ApprovalManager(self.store)
        from .agent_guard.executors import ExecutorRegistry
        self.executors = ExecutorRegistry()
        self.gateway = MCPGateway(self.store, self.registry, self.privacy,
                                  self.graph, self.policy, self.approvals,
                                  self.executors)
        self.collector = ProcessCollector(self.store)
        # winlog probe thread receives our stop signal and checks it before
        # every store access (regression fix for the shutdown race)
        self.winlog = WinEventLogCollector(
            self.store, should_stop=self._stopping.is_set)
        self.clipboard = ClipboardSensor(self.store, self.privacy)
        self.api_mapper = ApiMapper(self.store)
        from .core.audit_checkpoints import AuditCheckpoints
        self.checkpoints = AuditCheckpoints(self.store, self.settings.data_dir)
        from .handoff.service import HandoffService
        self.handoff = HandoffService(self.store)
        self.token = bootstrap_tokens(self.settings.data_dir, self.logger)
        self.store.beat_sensor("core", "up")
        # probe Windows providers in the background (never blocks startup)
        self._probe_thread = threading.Thread(target=self._probe_winlog,
                                              daemon=True,
                                              name="tw-winlog-probe")
        self._probe_thread.start()

    def _probe_winlog(self) -> None:
        try:
            self.winlog.probe()
        except Exception as exc:
            log_error(self.logger, "winlog_probe_thread_error", error=repr(exc))

    # ------------------------------------------------------------ auth api
    def authenticate(self, token: str) -> Optional[str]:
        return authenticate(self.settings.data_dir, token)

    def authenticate_record(self, token: str) -> Optional[dict]:
        return authenticate_record(self.settings.data_dir, token)

    def shutdown(self) -> None:
        """Idempotent, deterministic teardown:
        signal stop -> join background workers -> close the store last."""
        with self._shutdown_lock:
            if self._shutdown_done:
                return
            self._shutdown_done = True
        self._stopping.set()
        # join the winlog probe before closing the store it may touch
        if self._probe_thread is not None and self._probe_thread.is_alive():
            self._probe_thread.join(timeout=5)
        try:
            self.clipboard.stop()
        except Exception as exc:
            log_error(self.logger, "clipboard_stop_error", error=repr(exc))
        try:
            self.pipeline.stop()
        except Exception as exc:
            log_error(self.logger, "pipeline_stop_error", error=repr(exc))
        try:
            self.store.close()
        except Exception as exc:
            log_error(self.logger, "store_close_error", error=repr(exc))


_state: Optional[AppState] = None


def get_state() -> AppState:
    global _state
    if _state is None:
        _state = AppState()
    return _state


def reset_state() -> None:
    global _state
    if _state is not None:
        _state.shutdown()
    _state = None
