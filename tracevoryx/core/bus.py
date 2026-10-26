"""Event bus: normalize -> store (redacted) -> provenance graph ->
detections -> findings. Single ingestion path for every sensor.
"""
from __future__ import annotations

from typing import Any

from ..config import get_settings
from ..core.events import TrustEvent
from ..core.store import Store


class EventBus:
    def __init__(self, store: Store):
        self.settings = get_settings()
        self.store = store
        from ..provenance.graph import ProvenanceGraph
        self.graph = ProvenanceGraph(store)

    def submit(self, event: TrustEvent) -> dict[str, Any]:
        redact_keys = set(self.settings.get("redact_keys", []))
        stored = self.store.append_event(event, redact_keys=redact_keys)
        sensor = event.source.split(":")[0]
        self.store.beat_sensor(sensor, "up")
        findings = self.graph.ingest(event)
        for f in findings:
            self.store.insert_finding(f)
        stored["findings"] = findings
        return stored

    def stats(self) -> dict:
        total = self.store.execute("SELECT COUNT(*) n FROM events", fetch=True)[0]["n"]
        by_type = {r["event_type"]: r["n"] for r in self.store.execute(
            "SELECT event_type, COUNT(*) n FROM events GROUP BY event_type",
            fetch=True)}
        sensitive = self.store.execute(
            "SELECT COUNT(*) n FROM events WHERE sensitive=1", fetch=True)[0]["n"]
        open_findings = self.store.execute(
            "SELECT COUNT(*) n FROM findings WHERE status='open'", fetch=True)[0]["n"]
        return {
            "total_events": total,
            "by_type": by_type,
            "sensitive_events": sensitive,
            "open_findings": open_findings,
            "chain": self.store.verify_chain(),
            "provenance": self.graph.stats(),
        }
