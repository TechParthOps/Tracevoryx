# Security Audit — Tracevoryx 0.3.0

## Scope

Complete source review of every module (not documentation-driven), plus
adversarial testing of the enforcement boundary, executed against:

- the local repository on Windows 11 / Python 3.11.9,
- disposable per-test isolated environments (temp data dirs),
- the FastAPI TestClient and a live uvicorn-capable validation script.

**Authorized boundary:** local instances only. No external host, cloud
metadata service, or third-party system was probed. SSRF evidence uses a
localhost mock server; metadata-range behavior is asserted at the policy
function level (`_validate_dest_ip`) — the guard refuses the destination
before any connection is attempted.

## Method

1. **Static review** of all 35 package modules, tests, scripts, CI, config,
   docs, and the runtime state included in the 0.2.0 archive.
2. **Threat-model mapping** against A1–A6 (docs/SECURITY_THREAT_MODEL.md),
   verifying each claimed control with a test, not trust.
3. **Adversarial reproduction** of every hypothesis (malformed input, race
   windows, identity claims, path/URL shapes) with minimal reproducers.
4. **Layered testing:** unit → integration → adversarial → live local pen
   test (`scripts/live_validate.py`, 31 checks) → release verification
   (clean staging + secret scan + dependency audit).
5. **Tooling:** ruff (lint), bandit (Python security), pip-audit
   (dependencies), custom release-artifact scanner. Scanner outputs were
   triaged individually (docs/VULNERABILITY_REGISTER.md); no finding was
   accepted on the scanner's word alone, and zero scanner findings were
   treated as proof of safety.

## Findings summary

| Severity | Confirmed | Fixed in 0.3.0 | Accepted boundaries |
|---|---|---|---|
| Critical | 2 | 2 | — |
| High | 5 | 5 | — |
| Medium | 7 | 7 | — |
| Hardening | 12 | 12 | — |

Full detail, evidence, and retest status: `docs/VULNERABILITY_REGISTER.md`.
Executed test matrix + results: `reports/PENETRATION_TEST_REPORT.md`.

## What the audit changed structurally

- The executor boundary is now peer-validated and denylist-protected
  (executors.py rewritten around `_parse_url` / `_validate_dest_ip` /
  `_check_peer` / `_safe_path`).
- Single-use semantics moved into the store as an atomic CAS
  (`Store.kv_consume_if_unused`).
- Identity is a property of the credential (agent tokens), not a request
  field.
- Observe mode cannot execute would-be-denied calls by default.
- The audit chain survives retention; the trust anchor reports its own
  status; rotation is evidence-safe.
- The HTTP layer caps streamed bodies, bounds limiter state, and adds
  security headers.

## Honesty notes

- No vulnerability is claimed without a reproducer; scanner leads that
  could not be reproduced are marked TRIAGED-FP with reasoning, not
  silently dismissed.
- The audit did NOT include: multi-node deployment testing, other OS
  collectors beyond Windows probes, kernel-level telemetry validation, or
  formal verification. These remain documented limitations.
- The 0.2.0 archive contained live runtime credentials. That incident is
  handled in `docs/SECRET_CLEANUP.md`; no credential values are reproduced
  anywhere in this documentation set.
