# Implementation Audit — Tracevoryx (formerly TrustWeave) 0.1.0 → 0.2.0 (2026-10-15)

Baseline at audit time: **73/73 tests pass**, server boots, dashboard serves.

## Traced feature paths (input → output)

| Feature | Path | Verdict |
|---|---|---|
| Event ingestion | `core/events.py` → `core/bus.py` → `core/store.py` (hash chain) | Works; **no dedup, no backpressure, unbounded queue risk** |
| MCP gateway | `api_app.py /mcp` → `agent_guard/gateway.py` → policy → decision | Decision-only. **No registered-handler execution.** Tool_result events exist but are caller-reported only |
| Approvals | `core/approvals.py` → store | Works; **approval NOT bound to argument hash** → approve-then-modify-args bypass |
| Policy | `core/policy.py` (rules JSON, deny-wins) | Works; **no versioning**, no exceptions-with-expiry |
| Provenance | `provenance/graph.py` | Works; edges evidence-linked; taint cached; O(S·E) path query documented |
| Telemetry | `collector/process.py` (psutil sampling), `collector/clipboard_win.py` | **Polling only.** No Windows Event Log/Sysmon. No PID-reuse handling |
| Privacy | `privacy_guard/*` | Deterministic detection + reversible vault. **No phone/custom patterns, no stage-reporting (observe→verify)** |
| API mapper | `api_mapper/*` | Works; findings not evidence-linked to sample event ids |
| Auth | `api_app.py` bearer + `state.py` token file | **Token stored in PLAINTEXT** (data/api_token); no rate limiting; no roles; no CORS config |
| Audit | store hash chain + verify | Detects row tampering; **full-DB rewrite undetectable** (no checkpoints) |
| Handoff | `handoff/service.py` | Works; needs adversarial tests (replay/expiry/tag) |
| Dashboard | 3s polling | No live stream, no collector-health view, no loading/error states |
| Demo data | `cli.py demo`, fixtures | Confined to demo mode ✓ (production path never injects fixtures) |

## Critical defects found (fix first)
1. Plaintext API token at rest — treat any shipped token as compromised (C-01)
2. Approval reuse with modified arguments (C-02)
3. Gateway decision ≠ execution — agents can't actually run tools through it (C-03)
4. Unbounded ingest — one slow query can drop or block all sensors (C-04)
5. Audit chain rewriteable wholesale (C-05 — mitigate with signed checkpoints)

## Plan
Phase 1 pipeline hardening → Phase 2 gateway execution + binding → Phase 3
Windows Event Log collector → Phase 4/5 provenance+privacy upgrades →
Phase 6 policy versioning → Phase 7 auth → Phase 8 audit checkpoints →
Phase 9 SSE dashboard → Phases 10-14 tests/deployment/CI.
