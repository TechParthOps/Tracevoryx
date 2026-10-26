"""Endpoint collector: process snapshot + connection attribution via psutil.

Sampling, not kernel audit: short-lived processes/connections can be missed.
Every event carries collection_limitations saying exactly that.
"""
from __future__ import annotations

from typing import Any

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore

from ..core.events import TrustEvent
from ..core.store import Store

AGENT_HINTS = ("agent", "mcp", "llm", "claude", "openai", "autogen",
               "crewai", "langchain", "tracevoryx", "trustweave")


class ProcessCollector:
    def __init__(self, store: Store):
        self.store = store
        self.available = psutil is not None

    def snapshot(self, limit: int = 400) -> list[dict[str, Any]]:
        if not self.available:
            return []
        out = []
        for proc in psutil.process_iter(["pid", "ppid", "name", "exe"]):
            try:
                i = proc.info
                out.append({"pid": i["pid"], "ppid": i["ppid"] or 0,
                            "name": (i["name"] or "")[:128],
                            "exe": (i["exe"] or "")[:512]})
                if len(out) >= limit:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return out

    def agent_connections(self) -> list[TrustEvent]:
        """Sample connections and attribute them to processes. Agent-ish
        processes contacting non-approved destinations produce events."""
        if not self.available:
            return []
        events: list[TrustEvent] = []
        approved = set(self.store.settings.get(
            "network.approved_destinations", ["localhost", "127.0.0.1"]))
        internal = set(self.store.settings.get(
            "network.internal_hosts", ["localhost", "127.0.0.1"]))
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (proc.info["name"] or "").lower()
                if not any(h in name for h in AGENT_HINTS):
                    continue
                conns = proc.net_connections(kind="inet")
                for c in conns:
                    if c.raddr is None or c.status != "ESTABLISHED":
                        continue
                    host = c.raddr.ip
                    is_internal = host in internal or host.startswith(
                        ("10.", "192.168.", "169.254.", "127.")) or \
                        host.startswith("172.16.") or host.startswith("172.17.") \
                        or host.startswith("172.18.") or host.startswith("172.19.") \
                        or host.startswith("172.2") or host.startswith("172.30.") \
                        or host.startswith("172.31.")
                    approved_dst = any(host == a or host.endswith("." + a)
                                       for a in approved | internal)
                    events.append(TrustEvent(
                        event_type="connection",
                        source="process_collector",
                        actor=f"proc:{name}:{proc.info['pid']}",
                        target=f"{host}:{c.raddr.port}",
                        destination=f"{host}:{c.raddr.port}",
                        pid=proc.info["pid"], exe=(proc.info["exe"] or "")[:512],
                        trust_label="UNKNOWN",
                        evidence=[{"kind": "connection",
                                   "label": f"{host}:{c.raddr.port}",
                                   "observed": True,
                                   "detail": {"status": c.status}}],
                        correlation_confidence=0.8,
                        collection_limitations=[
                            "sampled via psutil; not a kernel audit stream",
                            "process-to-connection attribution by pid snapshot"],
                        details={"approved": approved_dst,
                                 "private": is_internal,
                                 "is_agent": True}))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return events
