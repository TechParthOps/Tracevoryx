# Benchmarks — Tracevoryx (formerly TrustWeave) 0.1.0

## Methodology (reproducible)

```powershell
python benchmarks/run_bench.py 3000
```

- Single process, synthetic events, isolated temp SQLite DB (WAL).
- `flat` pattern: benign file-access events, every 37th sensitive.
- `chain` pattern: every 100th triple is untrusted-content → sensitive-read →
  external-connection (forces exposure-path evaluation).
- Ingest latency = full pipeline: validate → hash-chained store (fsync'd WAL
  commit) → graph upsert → taint BFS (cached) → exposure-path detection.
- Local microbenchmark on the developer workstation (Windows, Python 3.11).
  **Not a production SLA.**

## Results (2026-10-15, 3000 events per pattern)

| Metric | flat | chain |
|---|---|---|
| Ingest p50 | 7.8 ms | 20.2 ms |
| Ingest p95 | 18.9 ms | 41.5 ms |
| Ingest p99 | 24.2 ms | 73.3 ms |
| Events/s | ~122 | ~42 |
| Exposure query avg | 11.1 ms | 11.8 ms |
| Graph nodes / edges | 3004 / 3000 | 3042 / 6000 |
| RSS | 38.4 MB | 41.3 MB |
| Chain valid | yes | yes |

## Interpretation & known costs

- The pipeline is **correctness-first**: every event is committed durably
  before returning, and exposure paths are re-evaluated whenever edges are
  added. Throughput (~40–120 ev/s single process) is adequate for a local
  agent-workflow monitor, not for fleet collection.
- `find_exposure_paths()` scans all sensitive nodes × their edges per call —
  O(S·E). At local scale (thousands of nodes) it stays in the tens of ms;
  at millions of edges it would need indexing or incremental path caching.
  This is a documented, bounded limitation, not a hidden one.
- The taint BFS is cached and invalidated only on graph changes, so repeated
  gateway calls between graph mutations are cheap.
