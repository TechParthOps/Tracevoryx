# Changelog

## 0.3.0 — security hardening release (Tracevoryx)

Renamed from **TrustWeave** to **Tracevoryx**. `import trustweave`,
the `trustweave` CLI command, and existing `data/` state keep working
(compatibility shims; no data migration needed).

### Security fixes (P0)

- **Executors: cloud-metadata SSRF closed.** Built-in `http.get` now blocks
  link-local/metadata ranges (169.254.169.254, fd00:ec2::254, etc.),
  multicast, reserved, and unspecified addresses; validates the ACTUAL peer
  address after connect (DNS-rebinding resistant); revalidates every
  redirect hop with a hard redirect cap; ignores proxy environment
  variables; rejects embedded credentials and non-http(s) schemes; caps
  response size at 256 KiB. Previously the guard allowed the entire
  link-local range and never re-checked redirects or post-resolution DNS.
- **Executors: runtime secrets denied to `fs.read`.** The audit key, token
  store, databases/WAL/SHM, exports, instance markers, and logs are refused
  even inside allowed roots. Previously the default allowed roots included
  the data directory, so a permitted tool call could read the audit trust
  anchor and token hashes.
- **Approvals: atomic single-use consumption.** Consumption is now a single
  compare-and-swap in the store; concurrent consumers cannot both win
  (previously a read-check-write race allowed double execution of one
  approved call).
- **Identity binding.** Agent-role tokens are bound to their label identity;
  a claim of another `_agent` is refused (invalid_params) for `tools/call`
  and `tools/result`. Cross-identity approval replay is closed at the
  transport layer.
- **Shadow mode must not become a bypass.** A call that would be denied (or
  requires approval) is logged but NOT executed in shadow mode by default
  (`agent_guard.shadow_execute_would_deny=false`); an explicit opt-in
  restores the old observe-and-execute behavior.

### Security fixes (P1/P2)

- **SSE stream tickets.** Short-lived (120 s) tickets bound to the issuing
  token's hash replace long-lived bearer tokens in stream URLs; revoked
  tokens kill their tickets. Raw `?token=` remains only as a documented
  deprecated fallback.
- **Caller-reported results distinguished.** `tools/result` records are
  audited as `observed=false, reported=true` with explicit limitations;
  the audit trail no longer conflates witnessed execution with client
  claims.
- **Token expiry.** Optional per-token TTL (`POST /api/v1/auth/tokens`
  `ttl_s`); expired tokens are rejected lazily.
- **Enforcement choice persists.** Shadow/enforce toggles survive restarts
  (`data/runtime_state.json`); a restart can no longer silently revert
  enforcement to observe mode.
- **Bounded limiter state.** Rate-limit and auth-failure maps are LRU-bounded
  (identity floods cannot grow memory without limit).
- **Request hardening.** Streamed-body cap (chunked requests included),
  malformed `Content-Length` rejected, deep-JSON parse fails safe,
  MCP param validation (argument object, size caps, identity/summary
  lengths), security headers (nosniff, DENY, no-referrer, CSP for HTML),
  uvicorn server header disabled.
- **Retention keeps the chain verifiable.** Cleanup anchors the chain at the
  first remaining row; middle-row deletion and full rewrites are still
  detected; checkpoints signed before an anchor remain valid.
- **Audit key handling.** 0600 creation on POSIX, no symlink following,
  documented rotation command (`rotate-audit-key`) with retired-key epochs
  and explicit trust-anchor status in verification output.
- **Handoff open token.** Random 256-bit token returned at seal time; the
  open token is no longer derivable from the public record; bounded session
  store; malformed-record handling.
- **Policy regex cap** (256 chars) against ReDoS in admin-supplied rules.

### Features

- **Policy what-if simulator** — API (`/api/v1/policy/simulate`) and CLI
  (`tracevoryx simulate`): decision-only evaluation with zero side effects.
- **Control coverage matrix** (`docs/CONTROL_COVERAGE.md`) mapping controls
  to evidence sources and blind spots.
- Dependency inventory generated at packaging time; release-artifact
  inspection test; clean-environment staging script
  (`scripts/package_release.py`).

### Repository baseline cleanup (pre-publication, 2026-10-26)

Not shipped code changes — publication-gate work on the same 0.3.0:

- **Store close-race fixed:** `Store.append_event` now re-checks the
  closed flag under the store lock; a racing `close()` can no longer
  interleave between the open-check and the first SQLite statement
  (previously surfaced as a bare `sqlite3.ProgrammingError` in a
  background writer instead of the documented `StoreClosedError`).
  Regression strengthened in `tests/test_lifecycle.py`.
- **Encoding repairs:** 288 CP1252-mojibake sequences in 37 files
  restored to the intended glyphs; 107 stray UTF-8 BOMs removed; PS 5.1
  ANSI-misdecode risk removed from ops scripts; guarded by
  `tests/test_encoding_hygiene.py`.
- **Test robustness:** explicit per-suite timeout budgets
  (`pytest.mark.timeout`) for PowerShell-probe, live-app, lifecycle and
  performance suites; timeout config documented in `pyproject.toml`.
- **Packaging hardening:** symlink rejection in release staging; dead
  code removed; CI bandit gate triaged (verified-parameterized SQL
  annotated `# nosec B608` with rationale).
- **CLI copy fix:** `--help` description said "formerly traceweave"
  (lowercase) — corrected to TrustWeave.

### Compatibility notes

- `trustweave` remains a valid import path and CLI alias (shims included).
- Data directory, DB schema, `tw_*` kv keys, `tw_` token prefix, and
  `[TW:REDACT:*]` placeholders are unchanged — existing databases, tokens,
  policies, and audit history carry over with no migration.
- Shadow-mode execution semantics changed as described above; operators who
  depended on would-be-deny execution must set
  `agent_guard.shadow_execute_would_deny=true` explicitly.

## 0.2.0 — TrustWeave

Initial hardened release: hashed token auth with roles, bounded pipeline,
deny-by-default registry, approval binding, signed checkpoints, Windows
Event Log collector, SSE dashboard. See docs/ from that release for details.
