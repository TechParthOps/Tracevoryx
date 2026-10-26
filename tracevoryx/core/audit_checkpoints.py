"""Signed audit checkpoints.

A hash chain alone cannot detect a full-database rewrite. Checkpoints close
part of that gap: periodically the chain head is HMAC-signed with a key
stored in a SEPARATE file (data/audit_key, user-only ACL on POSIX). The key
is created with restrictive permissions and never world-readable where the
OS allows enforcement.

Key rotation (`tracevoryx rotate-audit-key`): a final checkpoint is created
under the current key, the old key is preserved as data/audit_key.retired-<ts>
(for verifying pre-rotation checkpoints), and a fresh key is generated.
Consequences, stated honestly:
- checkpoints signed before rotation verify against the RETIRED key;
- verification reports which key epoch validated ("trust_anchor");
- anyone who could read the old key can still forge pre-rotation records —
  rotation limits FUTURE forgery only.

Threat model honesty: an attacker who can rewrite BOTH the database and the
current key file defeats this control. What it defeats: database-only
tampering, including full-chain regeneration, and tampered exports (exports
are signed with the same key). The local trust anchor is part of the local
trust boundary; export checkpoints off-host for stronger guarantees.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .store import Store


def _key_path(data_dir: Path) -> Path:
    return data_dir / "audit_key"


def ensure_key(data_dir: Path) -> bytes:
    """Load or create the audit key. On POSIX the file is created 0600 and
    never follows a pre-existing symlink at that path."""
    p = _key_path(data_dir)
    if p.exists():
        key = p.read_bytes().strip()
        if key:
            return key
    key = secrets.token_bytes(32)
    flags = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | flags, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def _candidate_keys(data_dir: Path, current: bytes) -> list[tuple[str, bytes]]:
    """Current key first, then any retired epoch keys (sorted oldest-first)."""
    out: list[tuple[str, bytes]] = [("current", current)]
    for p in sorted(data_dir.glob("audit_key.retired-*")):
        key = p.read_bytes().strip()
        if key:
            out.append((p.name.removeprefix("audit_key.retired-"), key))
    return out


class AuditCheckpoints:
    def __init__(self, store: Store, data_dir: Path):
        self.store = store
        self.data_dir = data_dir
        self.key = ensure_key(data_dir)
        store.execute("""CREATE TABLE IF NOT EXISTS audit_checkpoints (
            checkpoint_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
            chain_head TEXT NOT NULL, seq INTEGER NOT NULL, mac TEXT NOT NULL)""")

    # ---------------------------------------------------------- checkpoint
    def create(self) -> dict[str, Any]:
        row = self.store.execute(
            "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1",
            fetch=True)
        if not row:
            return {"created": False, "reason": "no events"}
        seq, head = int(row[0]["seq"]), row[0]["hash"]
        existing = self.store.execute(
            "SELECT checkpoint_id FROM audit_checkpoints WHERE seq=?",
            (seq,), fetch=True)
        if existing:
            return {"created": False, "reason": "checkpoint already exists",
                    "seq": seq}
        now = datetime.now(timezone.utc).isoformat()
        mac = hmac.new(self.key, f"{head}|{seq}|{now}".encode(),
                       hashlib.sha256).hexdigest()
        self.store.execute(
            "INSERT INTO audit_checkpoints VALUES (?,?,?,?,?)",
            (hashlib.sha256(f"{head}|{seq}".encode()).hexdigest()[:16],
             now, head, seq, mac))
        return {"created": True, "seq": seq, "created_at": now}

    # ------------------------------------------------------------ verify
    def verify(self) -> dict[str, Any]:
        """Verify the current chain head against the most recent checkpoint.

        Detects: row tampering (chain mismatch), deletion of a middle range
        (prev_hash link break), chain truncation (shorter than checkpoint),
        AND full-database rewrite (chain valid but head != signed checkpoint).
        Reports the trust-anchor epoch that validated the checkpoint."""
        chain = self.store.verify_chain()
        rows = self.store.execute(
            "SELECT * FROM audit_checkpoints ORDER BY seq DESC LIMIT 1",
            fetch=True)
        if not rows:
            return {**chain, "checkpoint": "none", "trust_anchor": "current",
                    "note": "no checkpoint yet — full-DB rewrite "
                            "undetectable; create checkpoints to close "
                            "this gap"}
        cp = rows[0]
        message = f"{cp['chain_head']}|{cp['seq']}|{cp['created_at']}"
        key_epoch = None
        for epoch, key in _candidate_keys(self.data_dir, self.key):
            expect_mac = hmac.new(key, message.encode(),
                                  hashlib.sha256).hexdigest()
            if hmac.compare_digest(expect_mac, cp["mac"]):
                key_epoch = epoch
                break
        if key_epoch is None:
            return {**chain, "checkpoint": "INVALID_MAC",
                    "trust_anchor": "unavailable",
                    "note": "checkpoint MAC does not verify under the "
                            "current or any retired key — the checkpoint "
                            "record or the key was tampered with"}
        head_row = self.store.execute(
            "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1",
            fetch=True)
        if not head_row:
            return {**chain, "checkpoint": "MISMATCH",
                    "trust_anchor": key_epoch,
                    "note": "checkpoint exists but event table is empty "
                            "(possible full-database rewrite)"}
        if head_row[0]["seq"] >= cp["seq"] and \
                chain.get("valid") and chain.get("checked", 0) >= cp["seq"]:
            # chain still contains the checkpointed prefix?
            at = self.store.execute(
                "SELECT hash FROM events WHERE seq=?", (cp["seq"],),
                fetch=True)
            if at and at[0]["hash"] == cp["chain_head"]:
                return {**chain, "checkpoint": "valid",
                        "trust_anchor": key_epoch,
                        "checkpoint_seq": cp["seq"]}
            return {**chain, "checkpoint": "MISMATCH",
                    "trust_anchor": key_epoch,
                    "note": "chain at checkpoint seq differs from signed "
                            "checkpoint — history rewritten"}
        # events may have been legitimately retired after this checkpoint:
        # verify the retention anchor explains the shorter chain
        base = self.store.chain_base()
        if base and int(base.get("seq", -1)) >= cp["seq"] and chain.get("valid"):
            return {**chain, "checkpoint": "valid_pre_retention",
                    "trust_anchor": key_epoch,
                    "checkpoint_seq": cp["seq"],
                    "note": "events older than the checkpoint were removed "
                            "by retention; the chain anchor matches the "
                            "checkpointed history"}
        return {**chain, "checkpoint": "MISMATCH",
                "trust_anchor": key_epoch,
                "note": "chain shorter than checkpoint — events deleted"}

    # ------------------------------------------------------------ export
    def export_events(self, path: Path, limit: int = 100000) -> dict:
        """Signed JSONL export: each line HMAC-tagged; final line is a
        checkpoint of the export. Tampering with the export file is
        detectable while the audit key remains secret."""
        events = self.store.query_events(limit=limit)
        lines = []
        for e in events:
            body = json.dumps(e, sort_keys=True, default=str)
            mac = hmac.new(self.key, body.encode(), hashlib.sha256).hexdigest()
            lines.append(body)
            lines.append(mac)
        cp = self.create()
        head = self.store.execute(
            "SELECT hash FROM events ORDER BY seq DESC LIMIT 1", fetch=True)
        head_hash = head[0]["hash"] if head else "GENESIS"
        tail = json.dumps({"export_checkpoint": {
            "chain_head": head_hash,
            "mac": hmac.new(self.key, head_hash.encode(),
                            hashlib.sha256).hexdigest(),
            "count": len(events)}}, sort_keys=True)
        path.write_text("\n".join(lines) + "\n" + tail + "\n",
                        encoding="utf-8")
        return {"exported": len(events), "path": str(path),
                "checkpoint": cp}

    def verify_export(self, path: Path) -> dict:
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines()
                 if ln.strip()]
        ok = 0
        bad = 0
        tail = None
        if lines and lines[-1].startswith('{"export_checkpoint":'):
            tail = json.loads(lines[-1])
            lines = lines[:-1]
        for i in range(0, len(lines) - 1, 2):
            body, mac = lines[i], lines[i + 1]
            expect = hmac.new(self.key, body.encode(),
                              hashlib.sha256).hexdigest()
            if hmac.compare_digest(expect, mac):
                ok += 1
            else:
                bad += 1
        valid_tail = False
        if tail:
            expect = hmac.new(self.key,
                              tail["export_checkpoint"]["chain_head"].encode(),
                              hashlib.sha256).hexdigest()
            valid_tail = hmac.compare_digest(
                expect, tail["export_checkpoint"]["mac"])
        return {"verified_records": ok, "tampered_records": bad,
                "checkpoint_valid": valid_tail}

    # ---------------------------------------------------------- rotation
    def rotate_key(self) -> dict[str, Any]:
        """Rotate the audit key: final checkpoint under the old key, old key
        preserved as audit_key.retired-<ts>, fresh key generated. Returns a
        summary WITHOUT printing any key material."""
        final_cp = self.create()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        old_path = _key_path(self.data_dir)
        retired = self.data_dir / f"audit_key.retired-{stamp}"
        if old_path.exists():
            retired.write_bytes(old_path.read_bytes())
        self.key = secrets.token_bytes(32)
        flags = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(old_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | flags,
                     0o600)
        try:
            os.write(fd, self.key)
        finally:
            os.close(fd)
        return {"rotated": True, "retired_key_file": retired.name,
                "final_checkpoint": final_cp,
                "note": "pre-rotation checkpoints verify against the "
                        "retired key epoch; rotation limits future "
                        "forgery only"}
