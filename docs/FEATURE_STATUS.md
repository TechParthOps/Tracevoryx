# Feature Status — Tracevoryx 0.3.0

Classifications: **verified** (implemented + tested + exercised) ·
**partial** · **not-implemented** · **unsupported** (platform).

Updated for 0.3.0; evidence in `reports/PENETRATION_TEST_REPORT.md`,
`docs/VULNERABILITY_REGISTER.md`, and `docs/CONTROL_COVERAGE.md`.

| Capability | Status | Evidence (0.3.0) |
|---|---|---|
| Pipeline (bounded queue, dedup, backpressure, drop counters) | verified | live run; pipeline stats endpoint |
| Gateway decisions (deny-by-default, policy v-hash) | verified | suite + live run |
| Built-in executors (fs.read / sys.echo / http.get) | verified | live run: real execution + audit; SSRF/FS adversarial suites |
| Approvals (binding, TTL, atomic single-use) | verified | race test (8 threads, 1 winner) + live run |
| Agent identity binding | verified | identity suite + live run |
| Shadow mode (observe without bypass) | verified | withholding live check |
| Role-based auth + hashed tokens + expiry | verified | auth suites + expiry test |
| SSE stream + short-lived tickets | verified | ticket suite + live check (raw token fallback deprecated) |
| Policy what-if simulator | verified | `/api/v1/policy/simulate` + `tracevoryx simulate`; zero-side-effect live check |
| Audit chain + signed checkpoints | verified | tamper + full-rewrite tests + live check |
| Audit key rotation + trust-anchor status | verified | live rotation executed (`rotate-audit-key`) |
| Retention with chain anchor | verified | retention suite |
| Provenance graph + exposure-path findings | verified | live run (critical finding with evidence chain) |
| Privacy detect/redact/reveal + honest capabilities | verified | live run |
| Handoff (X25519+HKDF+ChaCha20Poly1305) | verified | adversarial suite |
| Windows Event Log collector | verified (probe) | honest provider states; coverage = enabled providers |
| Clipboard sensor (Windows) | verified | post-hoc; race documented |
| API mapper (pcap/HAR passive) | verified | pcap suite |
| Attack-path graph with evidence-linked edges | verified | graph + findings (Feature 1 core) |
| Control coverage matrix | verified | docs/CONTROL_COVERAGE.md (Feature 6) |
| Evidence-constrained AI investigator (Feature 3) | not-implemented | design notes in docs/REMEDIATION_ROADMAP.md — no model calls exist in this release |
| Automated remediation loop (Feature 4) | partial | test discipline + register exist; loop automation future work |
| Off-host attestation destination (Feature 5) | partial | rotation + trust-status groundwork; push destination future work |
| Linux audit/eBPF telemetry | not-implemented | documented non-feature |
| Active API validation against targets | not-implemented | requires authorized-target consent framework |
