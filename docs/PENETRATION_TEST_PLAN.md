# Penetration Test Plan — Tracevoryx

## Authorization and scope

- **Targets:** local Tracevoryx instances started by the tester (TestClient
  or `tracevoryx serve` on loopback), disposable per-test environments.
- **Explicitly out of scope:** any host the tester does not own; real cloud
  metadata endpoints; production deployments; any destructive action
  against non-test data.
- **Rules of engagement:** non-destructive first; all malicious-file and
  race tests run against isolated fixtures; bounded test durations; no
  flood tests; secrets never printed.

## Stage A — attack-surface inventory

Routes and auth matrix (verified, see reports):

| Surface | Method | Auth | Role |
|---|---|---|---|
| /api/v1/health | GET | none | — (version + shadow flag only) |
| /mcp | GET | none | 405 info response (no data) |
| /mcp | POST | bearer | agent/analyst/admin (agent bound to label) |
| /api/v1/status, events, findings, graph, approvals(read), registry(read), privacy(inspect/capabilities), apimapper/*, audit/verify+integrity, policy/simulate, stream/ticket | POST/GET | bearer | analyst+ |
| /api/v1/agent/inspect-call, execute-call | POST | bearer | analyst+ (policy still gates) |
| shadow-mode, registry write, approvals decide, token issue/revoke, clipboard control, telemetry scans, retention, audit checkpoint+export, auth rotate | POST | bearer | admin |
| privacy/reveal | POST | bearer | admin |
| /api/v1/stream | GET | stream ticket (deprecated raw token) | ticket audience |
| dashboard / | GET | client-side token entry | static assets |

Trust boundaries: HTTP ↔ gateway (token → role/identity), gateway ↔
executors (policy decision → sandboxed builtin / delegated contract),
sensors → pipeline (bounded queue), DB ↔ audit key (separate file),
process ↔ filesystem (allowed roots + denylist).

## Stage B — static and dependency analysis

- ruff (E/F/W), bandit (-ll, medium+ gate), pip-audit (fail on findings),
  Semgrep/CodeQL optional in GitHub Advanced Security (not required for
  the gate), Gitleaks-equivalent custom scanner in
  `tests/test_release_hygiene.py` + CI.
- All scanner findings triaged with written justification.

## Stage C — dynamic tests (local only)

| Area | Tests |
|---|---|
| Auth | missing/malformed/revoked/expired tokens; lockout; rate limits; timing-shape review (hash-then-lookup) |
| Authz | role matrix above on every route; agent token vs admin data; cross-identity claims |
| MCP | malformed JSON-RPC; deep nesting; invalid params; unregistered tools; identity spoof; oversized args; duplicate keys; notifications; forged tools/result |
| Approvals | reuse w/ modified args; reuse by other identity; expired reuse; concurrent redemption; decide-then-replay |
| Executors | fs traversal/abs/UNC/junction/sensitive files; SSRF ranges, encodings, redirects, proxies, size/time caps (local mocks only) |
| Uploads | pcap/HAR size caps; malformed documents; parser crash resistance |
| DoS | oversized bodies (content-length + chunked); SSE client caps; limiter state bounds; retention/DB failure paths |
| Audit | row tamper; middle deletion; truncation; full rewrite incl. sequence reset; export tamper; key rotation epochs |
| Headers/CORS | security headers; CORS allow-list; method exposure |

## Stage D — manual verification

Every finding: minimal reproducer → request/response captured (secrets
redacted) → affected code path confirmed → exploitability assessed with
preconditions → regression test → severity vs realistic impact → linked
remediation.

## Stage E — retesting

After each remediation batch: rerun reproducer, rerun regression suite,
full pytest, live validation script, scanners; results recorded in
`reports/security-findings.json` and
`reports/PENETRATION_TEST_REPORT.md`.
