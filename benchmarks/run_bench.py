"""TrustWeave benchmark runner.

Reproducible methodology (docs/BENCHMARKS.md):
- single process, synthetic events, isolated temp DB
- measures: ingest latency (p50/p95), exposure-path query latency,
  graph memory (node/edge counts), process RSS delta
Run: python benchmarks/run_bench.py [events]
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tracevoryx.config as config
from tracevoryx.config import Settings

tmp = Path(tempfile.mkdtemp())
config._settings = Settings(root=tmp, raw={"data_dir": str(tmp / "data")})

from tracevoryx.core.bus import EventBus
from tracevoryx.core.events import TrustEvent


def make_event(i: int, pattern: str) -> TrustEvent:
    if pattern == "chain" and i % 100 == 0:
        return TrustEvent(event_type="content_ingested", source="bench",
                          actor=f"agent:a-{i % 4}",
                          target=f"http://ext-{i % 6}.example/x",
                          trust_label="UNTRUSTED_EXTERNAL_CONTENT")
    if pattern == "chain" and i % 100 == 1:
        return TrustEvent(event_type="file_access", source="bench",
                          actor=f"agent:a-{(i - 1) % 4}",
                          target=f"C:/u/secrets-{i}.key", sensitive=True,
                          trust_label="SENSITIVE_DATA")
    if pattern == "chain" and i % 100 == 2:
        return TrustEvent(event_type="connection", source="bench",
                          actor=f"agent:a-{(i - 2) % 4}",
                          destination=f"203.0.113.{i % 250}:443",
                          evidence=[{"kind": "conn", "label": "d",
                                     "observed": True,
                                     "detail": {"approved": False}}])
    return TrustEvent(event_type="file_access", source="bench",
                      actor=f"agent:a-{i % 4}",
                      target=f"C:/data/file-{i}.txt",
                      sensitive=i % 37 == 0,
                      evidence=[{"kind": "file", "label": "f",
                                 "observed": True}])


def bench(n: int, pattern: str) -> dict:
    from tracevoryx.core.store import Store

    bus = EventBus(store=Store())
    lat: list[float] = []
    for i in range(n):
        t0 = time.perf_counter()
        bus.submit(make_event(i, pattern))
        lat.append((time.perf_counter() - t0) * 1000)
    lat.sort()

    def pct(p):
        return round(lat[int(len(lat) * p)], 3)

    t0 = time.perf_counter()
    for _ in range(20):
        bus.graph.find_exposure_paths()
    q_ms = (time.perf_counter() - t0) / 20 * 1000
    proc = __import__("psutil").Process()
    return {
        "events": n, "pattern": pattern,
        "ingest_p50_ms": pct(0.50), "ingest_p95_ms": pct(0.95),
        "ingest_p99_ms": pct(0.99),
        "events_per_s": round(n / (sum(lat) / 1000), 1),
        "exposure_query_avg_ms": round(q_ms, 3),
        "graph_nodes": sum(bus.graph.stats()["nodes"].values()),
        "graph_edges": sum(bus.graph.stats()["edges"].values()),
        "rss_mb": round(proc.memory_info().rss / 1024 / 1024, 1),
        "chain_valid": bus.store.verify_chain()["valid"],
    }


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    results = [bench(n, "flat"), bench(n, "chain")]
    print(json.dumps(results, indent=2))
