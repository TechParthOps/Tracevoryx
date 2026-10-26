# Implementation Roadmap — executed for 0.2.0

| Phase | Scope | Status |
|---|---|---|
| 0 | Audit + baseline (73 tests) | done |
| 1 | Real pipeline: dedup, bounded queue, backpressure, health, structured logs | done |
| 2 | Gateway execution: built-in executors, delegation contract, approval binding (args-hash), rate limit, policy version | done |
| 3 | Windows Event Log collector (Security 4688 + Sysmon 1/3/11 when present) + prereq script; Linux adapter skeleton honestly labelled unavailable | done (collector) / live-validation procedure provided |
| 4 | Provenance: correlation-method labels, PID-reuse handling, dedup/out-of-order tests | done |
| 5 | Privacy: phones, custom patterns, stage reporting, redaction receipts, size limits | done |
| 6 | Policy version hash in every decision; exceptions with expiry | done |
| 7 | Auth: hashed tokens, roles, rate limits, CORS, .env.example | done |
| 8 | Audit checkpoints (HMAC-signed), signed export, integrity check, pagination | done |
| 9 | Dashboard: SSE live stream, collector health, honest states | done |
| 10 | API mapper evidence-linked findings + coverage | done |
| 11 | Handoff adversarial tests | done |
| 12 | Integration + live security scenarios + resilience | done (tests/test_live_scenarios.py) |
| 13 | Deployment scripts + LIVE_DEPLOYMENT_GUIDE | done |
| 14 | CI workflow + TEST_RESULTS.md | done |

Deferred (documented, not claimed): Linux eBPF/audit collectors, ETW
file-access telemetry, active API validation, multi-host clustering.
