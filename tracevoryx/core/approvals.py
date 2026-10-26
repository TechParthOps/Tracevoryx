"""Approval queue with argument binding.

An approval authorizes exactly (agent, tool, args_hash). Reuse with modified
arguments, a different identity, or after expiry is rejected. Approval is
single-use: consuming it (on execution) invalidates it.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .events import utcnow_iso
from .store import Store


def bind_key(agent: str, tool: str, args_hash: str) -> str:
    return hashlib.sha256(
        f"{agent}|{tool}|{args_hash}".encode()).hexdigest()


class ApprovalManager:
    def __init__(self, store: Store):
        self.store = store

    @staticmethod
    def args_hash(arguments: Any) -> str:
        return hashlib.sha256(
            json.dumps(arguments, sort_keys=True, default=str)
            .encode()).hexdigest()[:16]

    def request(self, agent: str, tool: str, reason: str, summary: str,
                event_id: str, ttl_s: int | None = None,
                args_hash: str = "") -> dict:
        ttl = ttl_s or int(self.store.settings.get("policy.approval_ttl_s", 900))
        rec = {
            "approval_id": uuid.uuid4().hex,
            "created_at": utcnow_iso(),
            "expires_at": (datetime.now(timezone.utc)
                           + timedelta(seconds=ttl)).isoformat(),
            "agent": agent, "tool": tool, "reason": reason, "summary": summary,
            "event_id": event_id,
        }
        # argument binding stored in kv: bind_key -> approval_id (single-use)
        self.store.kv_set(f"tw_approval_bind:{bind_key(agent, tool, args_hash)}",
                          {"approval_id": rec["approval_id"],
                           "expires_at": rec["expires_at"], "used": False})
        self.store.add_approval(rec)
        return rec

    def find_binding(self, agent: str, tool: str, args_hash: str) -> dict | None:
        return self.store.kv_get(
            f"tw_approval_bind:{bind_key(agent, tool, args_hash)}")

    def consume_binding(self, agent: str, tool: str, args_hash: str) -> bool:
        """Consume (single-use) only when: binding exists, unexpired, unused,
        AND the linked approval record was actually approved by a human.
        A pending (not yet decided) or denied approval is never consumable.
        The final mark-used step is a single atomic compare-and-swap in the
        store, so two concurrent consumers cannot both win."""
        key = f"tw_approval_bind:{bind_key(agent, tool, args_hash)}"
        b = self.store.kv_get(key)
        if not b or b.get("used"):
            return False
        if datetime.now(timezone.utc).isoformat() > b.get("expires_at", ""):
            self.store.kv_set(key, {**b, "used": True})
            return False
        approval = self.store.get_approval(b.get("approval_id", ""))
        if not approval or approval.get("status") != "approved":
            return False
        # the approval record's expiry is authoritative (single source)
        if datetime.now(timezone.utc).isoformat() > approval.get(
                "expires_at", ""):
            self.store.kv_set(key, {**b, "used": True})
            return False
        # atomic single-use consumption (CAS in the store, thread- and
        # process-safe); the expiry pre-check above is advisory, the store
        # re-checks expiry atomically
        return self.store.kv_consume_if_unused(
            key, datetime.now(timezone.utc).isoformat())

    def decide(self, approval_id: str, approved: bool) -> bool:
        return self.store.decide_approval(
            approval_id, "approved" if approved else "denied")

    def pending(self) -> list[dict]:
        return self.store.list_approvals(status="pending")
