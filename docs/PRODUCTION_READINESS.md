# Production Readiness — Tracevoryx 0.3.0

## Gate status

| Criterion | Status |
|---|---|
| No unresolved P0 | PASS (register: all P0 FIXED with retest evidence) |
| No exposed credentials/runtime DBs in the release package | PASS (staging deny rules + 29 hygiene tests + CI scan; dist secret scan clean) |
| Auth + role separation verified on every sensitive endpoint | PASS (role matrix tests + live checks) |
| Denied tool calls never execute | PASS (enforce deny + shadow withholding tests, live check) |
| Approval binding/replay protections pass adversarial tests | PASS (binding suite + 8-thread single-winner race test) |
| SSRF + filesystem boundaries pass regression tests | PASS (SSRFGuard + FSDenylist suites; local mocks only) |
| Audit integrity claims match the trust model | PASS (anchor + checkpoints + rotation tests; honesty documented) |
| Resource/request limits verified | PASS (body caps, limiter bounds, SSE caps, executor timeout) |
| No release-blocking dependency vulnerability | PASS (pip-audit clean after certifi upgrade) |
| Clean install works without developer environment | PASS (fresh venv → wheel install: imports, shim, dashboard asset, CLI demo verified; wheel + sdist built) |
| Original + new tests pass | PASS (241/241 full suite incl. 3 perf; perf also run separately — docs/TEST_RESULTS.md) |
| Known limitations documented | PASS (KNOWN_LIMITATIONS.md + CONTROL_COVERAGE.md) |
| Every confirmed finding has status + retest evidence | PASS (VULNERABILITY_REGISTER.md) |
| Name checked before publication | PASS (Tracevoryx: PyPI 404 + 0 GitHub repos; traceloom and trustweave both taken — see RENAME_MIGRATION.md) |
| Existing user data preserved | PASS (no schema/kv/token-format changes; shims; migration doc) |

## Deployment guidance (minimum bar)

- Bind loopback (`TW_API_HOST=127.0.0.1`). Remote exposure requires a TLS
  terminating reverse proxy, OS-level network ACLs, and a threat-model
  review — the application does not ship TLS.
- Run as a dedicated low-privilege OS user; protect `data/`
  (contains the audit key and token hashes).
- Schedule `POST /api/v1/audit/checkpoint` (or CLI) and export signed
  JSONL off-host periodically.
- Enable enforcement only after a shadow-mode evaluation window
  (`tracevoryx enforce` / dashboard toggle; the choice now persists).
- Rotate the bootstrap admin token after first login
  (`POST /api/v1/auth/rotate`), delete `data/bootstrap_token.txt` if
  present, and issue role-scoped tokens with TTLs.

## Not ready for (be honest)

- Internet-exposed multi-tenant service (SQLite single-writer, no TLS,
  no clustering).
- Substitute for EDR/anti-malware (sampling telemetry only).
- Any claim of universal DLP or prevention of already-executed actions.
