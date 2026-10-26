"""Privacy service + reversible redaction vault.

Reversible placeholders: within a bounded local session, `[TW:REDACT:xxxx]`
placeholders map back to originals via an in-memory vault that auto-purges at
TTL. The vault is never written to disk; a restart loses reversibility by
design. Audit records store masked previews only — never originals.
"""
from __future__ import annotations

import secrets
import threading
import time
from typing import Any

from ..core.events import TrustEvent
from ..core.store import Store
from .detectors import Detection, apply_redaction, inspect_deterministic


class RedactionVault:
    """Session-bounded placeholder -> original mapping (memory only)."""

    def __init__(self, ttl_s: int = 1800):
        self.ttl = ttl_s
        self._lock = threading.RLock()
        self._vaults: dict[str, dict[str, tuple[str, float]]] = {}

    def put(self, session_id: str, original: str) -> str:
        ph = f"[TW:REDACT:{secrets.token_hex(4)}]"
        with self._lock:
            self._purge(session_id)
            self._vaults.setdefault(session_id, {})[ph] = (
                original, time.time() + self.ttl)
        return ph

    def reveal(self, session_id: str, placeholder: str) -> str | None:
        with self._lock:
            self._purge(session_id)
            item = self._vaults.get(session_id, {}).get(placeholder)
            return item[0] if item else None

    def _purge(self, session_id: str) -> None:
        vault = self._vaults.get(session_id)
        if not vault:
            return
        now = time.time()
        for ph in [p for p, (_, exp) in vault.items() if exp < now]:
            vault[ph] = ("", 0)
            del vault[ph]
        if not vault:
            self._vaults.pop(session_id, None)

    def drop_session(self, session_id: str) -> None:
        with self._lock:
            self._vaults.pop(session_id, None)

    def size(self, session_id: str) -> int:
        with self._lock:
            return len(self._vaults.get(session_id, {}))


class PrivacyService:
    def __init__(self, store: Store):
        self.store = store
        self.vault = RedactionVault(
            int(store.settings.get("privacy.reversible_vault_ttl_s", 1800)))

    @staticmethod
    def inspect_deterministic(text: str) -> list[Detection]:
        return inspect_deterministic(text)

    def evaluate(self, text: str, context: str = "manual",
                 actor: str = "user", reversible: bool = False,
                 session_id: str = "default") -> dict[str, Any]:
        detections = inspect_deterministic(text)
        det_types = sorted({d.detector for d in detections})
        redacted = None
        if detections:
            if reversible:
                # reversible: replace with vault-backed placeholders
                parts = []
                last = 0
                for d in detections:
                    parts.append(text[last:d.start])
                    parts.append(self.vault.put(session_id, text[d.start:d.end]))
                    last = d.end
                parts.append(text[last:])
                redacted = "".join(parts)
            else:
                redacted = apply_redaction(text, detections)
        evt = TrustEvent(
            event_type="clipboard_content" if context == "clipboard"
            else "content_ingested" if context == "agent"
            else "system",
            source=f"privacy_guard:{context}",
            actor=actor,
            target=f"detections:{len(detections)}",
            trust_label="SENSITIVE_DATA" if detections else "UNKNOWN",
            sensitive=bool(detections),
            evidence=[
                {"kind": "dlp", "label": d.label, "observed": True,
                 "detail": {"detector": d.detector, "confidence": d.confidence,
                            "preview": d.preview}}
                for d in detections[:10]
            ] or [{"kind": "dlp", "label": "no sensitive data detected",
                   "observed": True, "detail": {"chars": len(text)}}],
            collection_limitations=[
                "deterministic detectors; encoded content can evade them",
                "clipboard: post-hoc on Windows (race with other apps)"]
            if context == "clipboard" else [
                "deterministic detectors; encoded content can evade them"],
            details={"detectors": det_types, "match_count": len(detections),
                     "reversible": reversible and bool(detections),
                     "raw_stored": False})
        self.store.append_event(
            evt, redact_keys=set(self.store.settings.get("redact_keys", [])))
        # redaction receipt: what was detected, what replaced it — no originals
        receipt = {
            "event_id": evt.event_id,
            "timestamp": evt.timestamp,
            "context": context,
            "match_count": len(detections),
            "replacements": [
                {"detector": d.detector, "placeholder": d.placeholder,
                 "span": [d.start, d.end]}
                for d in detections
            ],
            "reversible": bool(reversible and detections),
            "original_stored": False,
        }
        if detections:
            self.store.kv_set(f"tw_redaction_receipt:{evt.event_id}", receipt)
        return {
            "decision": "redact" if detections else "allow",
            "detections": [
                {"detector": d.detector, "label": d.label,
                 "preview": d.preview, "confidence": d.confidence,
                 "span": [d.start, d.end]} for d in detections],
            "redacted_text": redacted,
            "event_id": evt.event_id,
            "receipt": receipt,
            "vault_entries": self.vault.size(session_id) if reversible else 0,
        }

    def reveal(self, session_id: str, placeholder: str) -> str | None:
        return self.vault.reveal(session_id, placeholder)
