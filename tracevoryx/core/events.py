"""Normalized event schema (spec §4).

Every sensor/collector event passes through here. Rules:
- Identity: host, pid, exe, parent where the OS exposes them; absent fields
  stay absent — they are never invented.
- Evidence: what was directly observed + a source reference so any alert can
  be traced back to the raw event.
- collection_limitations: explicit disclosure of what this event cannot see.
"""
from __future__ import annotations

import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_validator

EVENT_TYPES = (
    "agent_registered", "tool_registered", "tool_call", "tool_result",
    "content_ingested", "clipboard_content", "file_access", "file_write",
    "process_started", "connection", "pcap_ingested", "har_ingested",
    "approval_requested", "approval_decided", "system", "handoff_transfer",
)
TRUST_LABELS = (
    "TRUSTED_CONFIGURATION", "USER_INPUT", "UNTRUSTED_EXTERNAL_CONTENT",
    "SENSITIVE_DATA", "UNKNOWN",
)
DECISIONS = ("allow", "deny", "require_approval", "audit_only")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class TrustEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = Field(default_factory=utcnow_iso)
    host: str = Field(default_factory=lambda: socket.gethostname()[:128])
    event_type: str = Field(max_length=64)
    source: str = Field(description="sensor/component that produced the event",
                        max_length=128)
    actor: str = Field(default="", max_length=256,
                       description="agent/process/tool identity responsible")
    target: str = Field(default="", max_length=512)
    destination: str = Field(default="", max_length=512)
    pid: Optional[int] = None
    exe: str = Field(default="", max_length=512)
    parent_pid: Optional[int] = None
    parent_exe: str = Field(default="", max_length=512)
    trust_label: Literal["TRUSTED_CONFIGURATION", "USER_INPUT",
                         "UNTRUSTED_EXTERNAL_CONTENT", "SENSITIVE_DATA",
                         "UNKNOWN"] = "UNKNOWN"
    sensitive: bool = False
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    source_ref: str = Field(default="", max_length=256)
    correlation_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    collection_limitations: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> "TrustEvent":
        if self.correlation_confidence < 1.0 and not self.collection_limitations:
            self.collection_limitations = [
                "sub-1.0 correlation confidence: relationship is inferred, "
                "not directly observed"]
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event_type: {self.event_type}")
        return self

    def actor_is_agent(self) -> bool:
        return self.actor.startswith("agent:") or self.details.get("is_agent", False)
