# Architecture — Tracevoryx (formerly TrustWeave) 0.2.0

## Data flow (production path)

```
Sources                      Pipeline (Tracevoryx (formerly TrustWeave)/core/pipeline.py)
──────────────────────       ─────────────────────────────────────
MCP gateway decisions   ──â”   submit() → validate → dedup(event_id)
Windows Event Log       ──┤     → bounded queue (drop-oldest, counters)
psutil process/conn     ──┼──▶ → worker: store.append (hash chain)
clipboard sensor        ──┤     → provenance graph ingest
privacy DLP evaluations ──┘     → detections → findings
API mapper imports              → SSE fan-out to dashboard
handoff events
```

- **event_time** (sensor clock, preserved) vs **ingested_at** (server clock,
  set at durable write) are both stored.
- Backpressure: bounded queue; when full, oldest events are dropped with a
  `pipeline_dropped` counter (visible in /api/v1/status). Sensors are never
  silently stalled.
- Collector failure: sensors report to `sensor_health` (up/degraded/down +
  last_beat + last_error). Staleness = now - last_beat > threshold, surfaced
  in status and dashboard.

## Gateway execution model (0.2.0)

```
agent request → auth (role=agent token) → JSON-RPC validation
→ registry (deny-by-default) → args scan → policy v(hash)
→ [require_approval: bound to (agent, tool, args_hash), TTL]
→ executor registry: built-in handlers (fs.read, http.get) or
  "delegated" tools → execution (timeout, subprocess limit)
→ result validation → tool_result event → response
```

Delegated tools: the gateway returns the decision to the integrating agent,
which executes and reports via `tool_result` — the **adapter contract** is
documented in docs/LIVE_DEPLOYMENT_GUIDE.md and verified by tests that the
result event is persisted and graph-linked.

## Enforcement boundary (honest statement)

Enforced: calls that pass through the gateway; Tracevoryx (formerly TrustWeave)-managed child
processes; handoff tokens; approval consumption.
Observed only: OS processes/connections (sampled + Windows Event Log where
available); processes that bypass the gateway are never intercepted.

## Storage

SQLite (WAL). Tables: events (hash chain), provenance_nodes/edges, findings,
approvals, sensor_health, kv, api_endpoints, schema_migrations,
audit_checkpoints. Audit checkpoints are HMAC-signed with a key in
`data/audit_key` (separate file, user-only ACL) — see Phase 8 in
IMPLEMENTATION_ROADMAP.md for the tamper model.
