"""Optional ephemeral secure handoff (deliberately minimal).

Standard primitives only: X25519 + HKDF-SHA256 + ChaCha20-Poly1305.
Single-chunk AEAD for files up to max_file_mb (handoff is not a bulk
transfer product). Receipts state exactly what was verified.

Open tokens: the token returned at seal time is random (256-bit) and is
NOT derivable from the record — possession of the sealed record alone is
insufficient to open it. Tokens are single-use together with the session
and expire with it.
"""
from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"tracevoryx-handoff-v1"
_MAX_SESSIONS = 1000


class HandoffError(PermissionError):
    pass


class HandoffService:
    def __init__(self, store):
        self.store = store
        self.max_file = int(store.settings.get("handoff.max_file_mb", 128)) * 1024 * 1024
        self.ttl = int(store.settings.get("handoff.session_ttl_s", 600))
        # session_id -> (ciphertext, expires_epoch, open_token)
        self._keys: dict[str, tuple[bytes, float, str]] = {}
        self._identity = X25519PrivateKey.generate()

    # -------------------------------------------------------------- keys
    def public_key_pem(self) -> bytes:
        return self._identity.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def private_key_pem(self) -> bytes:
        """Recipient identity private key (this host receives handoffs)."""
        return self._identity.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())

    # -------------------------------------------------------------- send
    def seal(self, recipient_pub_pem: bytes, data: bytes,
             ttl_s: int | None = None) -> tuple[dict[str, Any], str]:
        """Seal data for a recipient. Returns (record, open_token); the
        token must be delivered over a separate channel from the record."""
        if len(data) > self.max_file:
            raise ValueError("file exceeds handoff size cap")
        peer_pub = serialization.load_pem_public_key(recipient_pub_pem)
        eph = X25519PrivateKey.generate()
        salt = secrets.token_bytes(16)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                   info=INFO).derive(eph.exchange(peer_pub))
        session_id = uuid.uuid4().hex
        nonce = secrets.token_bytes(12)
        ct = ChaCha20Poly1305(key).encrypt(nonce, data, session_id.encode())
        rec = {
            "session_id": session_id, "nonce": nonce.hex(), "salt": salt.hex(),
            "eph_pub": eph.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "expires_at": (datetime.now(timezone.utc)
                           + timedelta(seconds=ttl_s or self.ttl)).isoformat(),
            "single_use": True, "state": "sealed",
        }
        # bounded session store: refuse new sessions beyond the cap (DoS
        # guard); expiry is enforced at open time and sessions evicted there
        self._evict_expired()
        if len(self._keys) >= _MAX_SESSIONS:
            raise HandoffError("too many pending handoff sessions; retry later")
        open_token = secrets.token_urlsafe(32)
        expires_epoch = time.time() + (ttl_s or self.ttl)
        self._keys[session_id] = (ct, expires_epoch, open_token)
        return rec, open_token

    # ----------------------------------------------------------- receive
    def open(self, rec: dict, token: str, own_private_pem: bytes) -> dict:
        if not isinstance(rec, dict):
            raise HandoffError("invalid record")
        session_id = str(rec.get("session_id", ""))[:64]
        if not session_id:
            raise HandoffError("invalid token")
        entry = self._keys.get(session_id)
        expected = entry[2] if entry else ""
        if not expected or not isinstance(token, str) or \
                not secrets.compare_digest(token, expected):
            # token check BEFORE any other signal (no oracle about state)
            raise HandoffError("invalid token")
        if datetime.now(timezone.utc).isoformat() > str(rec.get("expires_at", "")):
            self._keys.pop(session_id, None)
            raise HandoffError("session expired")
        entry = self._keys.pop(session_id, None)
        if entry is None:
            raise HandoffError("unknown or already-consumed session")
        ct = entry[0]
        eph_pub = serialization.load_pem_public_key(
            str(rec.get("eph_pub", "")).encode())
        own = serialization.load_pem_private_key(own_private_pem, password=None)
        try:
            salt = bytes.fromhex(str(rec.get("salt", "")))
            nonce = bytes.fromhex(str(rec.get("nonce", "")))
        except ValueError as exc:
            raise HandoffError("malformed record encoding") from exc
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=salt, info=INFO).derive(own.exchange(eph_pub))
        pt = ChaCha20Poly1305(key).decrypt(
            nonce, ct, session_id.encode())
        digest_ok = hashlib.sha256(pt).hexdigest() == rec.get("sha256")
        receipt = {
            "session_id": session_id,
            "integrity": "verified" if digest_ok else "FAILED",
            "sha256_recomputed": hashlib.sha256(pt).hexdigest(),
            "single_use_consumed": True,
            "key_handling": "ephemeral key material dropped from process memory",
            "limitations": [
                "recipient-created copies are outside this receipt",
                "no claim of secure erasure of SSD sectors, pagefile, or backups",
            ],
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        if not digest_ok:
            raise HandoffError("integrity verification failed")
        return {"plaintext": pt, "receipt": receipt}

    def _evict_expired(self) -> None:
        now = time.time()
        for sid in [s for s, (_, exp, _) in self._keys.items() if exp < now]:
            self._keys.pop(sid, None)
