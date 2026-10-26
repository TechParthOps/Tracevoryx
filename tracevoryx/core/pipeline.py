"""Real ingestion pipeline: dedup, bounded queue, backpressure, health.

- `submit_now(event)`: synchronous durable write (gateway needs the event_id
  and decision atomically; unchanged contract).
- `enqueue(event)`: async path for high-volume sensors. Bounded queue;
  when full the OLDEST event is dropped and `pipeline_dropped` increments —
  sensors are never silently stalled and drops are visible in /api/v1/status.
- Dedup: recent-event LRU by event_id; duplicates are idempotent (the
  original stored event is returned, nothing is double-counted).
- Staleness: a sensor whose last beat is older than its declared interval
  reports 'stale' — distinct from 'down' (error) and from 'zero events seen'.
"""
from __future__ import annotations

import queue
import threading
import time
from collections import OrderedDict

from .events import TrustEvent
from .logging_util import log_error
from .store import Store


class DedupCache:
    def __init__(self, capacity: int = 10000):
        self.capacity = capacity
        self._seen: OrderedDict[str, dict] = OrderedDict()
        self._lock = threading.Lock()

    def check(self, event_id: str) -> dict | None:
        with self._lock:
            if event_id in self._seen:
                self._seen.move_to_end(event_id)
                return self._seen[event_id]
            return None

    def remember(self, event_id: str, stored: dict) -> None:
        with self._lock:
            self._seen[event_id] = stored
            while len(self._seen) > self.capacity:
                self._seen.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


class EventPipeline:
    def __init__(self, bus, store: Store, maxsize: int = 5000,
                 workers: int = 1):
        self.bus = bus
        self.store = store
        self.dedup = DedupCache()
        self.queue: "queue.Queue[TrustEvent]" = queue.Queue(maxsize=maxsize)
        self.workers: list[threading.Thread] = []
        self._stop = threading.Event()
        self.stats = {
            "submitted": 0, "dropped": 0, "duplicates": 0,
            "queue_high_watermark": 0, "processing_errors": 0,
            "last_ingest_latency_ms": 0.0, "avg_ingest_latency_ms": 0.0,
        }
        self._lat_sum = 0.0
        self._lat_n = 0
        self._lock = threading.Lock()
        for i in range(max(1, workers)):
            t = threading.Thread(target=self._worker, daemon=True,
                                 name=f"tw-pipeline-{i}")
            t.start()
            self.workers.append(t)

    # ------------------------------------------------------------ sync path
    def submit_now(self, event: TrustEvent) -> dict:
        """Synchronous durable ingest (dedup-aware). Returns stored event."""
        self.stats["submitted"] += 1
        prior = self.dedup.check(event.event_id)
        if prior is not None:
            self.stats["duplicates"] += 1
            return prior
        t0 = time.perf_counter()
        try:
            stored = self._store_once(event)
        except Exception:
            raise
        latency = (time.perf_counter() - t0) * 1000
        with self._lock:
            self.stats["last_ingest_latency_ms"] = round(latency, 3)
            self._lat_sum += latency
            self._lat_n += 1
            self.stats["avg_ingest_latency_ms"] = round(
                self._lat_sum / self._lat_n, 3)
        self.dedup.remember(event.event_id, stored)
        return stored

    def _store_once(self, event: TrustEvent) -> dict:
        stored = self.bus.submit(event)
        return stored

    # ------------------------------------------------------------ async path
    def enqueue(self, event: TrustEvent) -> bool:
        """Non-blocking async ingest with bounded backpressure.
        Returns False only when the queue is full AND the event was dropped."""
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            # drop oldest to make room; the drop is counted and visible
            try:
                self.queue.get_nowait()
                self.stats["dropped"] += 1
                self.queue.put_nowait(event)
            except (queue.Empty, queue.Full):
                self.stats["dropped"] += 1
                return False
        hw = self.queue.qsize()
        if hw > self.stats["queue_high_watermark"]:
            self.stats["queue_high_watermark"] = hw
        return True

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                event = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.submit_now(event)
            except Exception as exc:  # worker must survive bad events
                self.stats["processing_errors"] += 1
                log_error(self.store and logging_hack(), "pipeline_worker_error",
                          error=str(exc), event_id=getattr(event, "event_id", "?"))

    def drain(self, timeout: float = 5.0) -> int:
        """Wait for the async queue to empty (tests + graceful shutdown)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.queue.empty():
                return 0
            time.sleep(0.02)
        return self.queue.qsize()

    def snapshot_stats(self) -> dict:
        with self._lock:
            s = dict(self.stats)
        s["queue_depth"] = self.queue.qsize()
        s["dedup_cache_entries"] = len(self.dedup)
        return s

    def stop(self) -> None:
        self._stop.set()
        for t in self.workers:
            t.join(timeout=2)


def logging_hack():
    """Pipeline logger (avoids import cycle at module top)."""
    import logging
    return logging.getLogger("tracevoryx.pipeline")


def sensor_staleness(store: Store, stale_after_s: float = 60.0) -> list[dict]:
    """Sensor health enriched with honest staleness classification."""
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    out = []
    for s in store.sensor_health():
        entry = dict(s)
        if s["last_beat"]:
            age = (now - _dt.datetime.fromisoformat(s["last_beat"])).total_seconds()
            entry["seconds_since_beat"] = round(age, 1)
            if s["status"] == "down":
                entry["health"] = "down"
            elif s["status"] == "degraded":
                entry["health"] = "degraded"
            elif age > stale_after_s:
                entry["health"] = "stale"
            else:
                entry["health"] = "up"
        else:
            entry["health"] = "no_data"
            entry["seconds_since_beat"] = None
        out.append(entry)
    return out
