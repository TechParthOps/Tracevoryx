# Penetration Test Report — Tracevoryx 0.3.0

**Scope compliance:** all testing executed against local instances and
disposable fixtures on Windows 11 / Python 3.11.9. No external host, cloud
metadata endpoint, or production system was contacted. SSRF redirect
evidence uses a localhost mock HTTP server. Secrets are excluded from this
report.

## Executive summary

14 confirmed vulnerabilities were found in TrustWeave 0.2.0 (2 critical,
5 high, 7 medium) plus 12 hardening defects. All 14 are fixed in
Tracevoryx 0.3.0 with regression tests; retest evidence is recorded in
`docs/VULNERABILITY_REGISTER.md`. The release package passed staging,
secret-scan, and dependency-audit gates.

## Test execution log

| Stage | Tooling | Result |
|---|---|---|
| A — surface inventory | manual route matrix | complete; matrix in docs/PENETRATION_TEST_PLAN.md |
| B — static/deps | ruff 0.x, bandit, pip-audit, custom release scanner | ruff clean; bandit 2×B608 triaged FP (placeholder-only SQL); pip-audit 1 finding (certifi) → upgraded → clean; release scan clean |
| C — dynamic | pytest adversarial suite (33 tests) + TestClient + local mock servers | all pass |
| D — manual verification | minimal reproducers per finding | 14 confirmed; every scanner lead triaged |
| E — retest | full suite + live validation | 238/238 (fast mode), 31/31 live |

## Key reproduced attacks (pre-fix, 0.2.0 code)

1. **Audit-key exfiltration via permitted tool** — `tools/call fs.read
   {"path": "data/audit_key"}` returned the HMAC key; the same call shape
   read `api_tokens.json`. (TVX-001)
2. **Cloud-metadata fetch via built-in HTTP tool** — policy-level proof:
   `_validate_dest_ip`-predecessor accepted 169.254.169.254 as private; a
   localhost mock demonstrated the redirect path reached a second
   destination without revalidation. (TVX-002)
3. **Approval double-spend** — 8 concurrent consumers of one approved
   binding: pre-fix read-check-write allowed multiple winners
   (demonstrable race); post-fix exactly 1. (TVX-003)
4. **Identity spoofing** — agent token + `_agent: "victim"` accepted
   pre-fix; post-fix → `-32602`. (TVX-004)
5. **Shadow-mode execution of denied privileged calls** — observe mode ran
   would-be-deny calls (live-checked pre/post). (TVX-101)

## Post-fix verification (this release)

- Full suite: **238 passed, 0 failed** (3 perf tests deselected in fast
  CI mode; run separately via `pytest tests/test_perf.py`).
- Live local pen test: **31/31 PASS** (`python scripts/live_validate.py`)
  covering auth, roles, MCP handshake/discovery/execution/denial, shadow
  withholding, fs boundary, identity binding, SSE tickets, security
  headers, what-if simulator, approval binding, provenance findings,
  privacy redaction/reveal/capabilities, checkpoint tamper detection,
  dashboard serving, restart persistence.
- Release: `python scripts/package_release.py` → 122 files staged, secret
  scan clean, MANIFEST.sha256 + dependency inventory + zip produced;
  29/29 hygiene tests.

## Known limitations after remediation

See docs/KNOWN_LIMITATIONS.md and docs/CONTROL_COVERAGE.md. Highlights:
gateway-boundary-only enforcement, caller-reported delegated results,
DB+key attacker defeats checkpoints, deterministic DLP evadable,
post-hoc clipboard, single-node SQLite.
