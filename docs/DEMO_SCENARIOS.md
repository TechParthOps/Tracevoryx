# Demonstration Scenarios (evidence-backed)

Each scenario below is executable and covered by tests. Run `python -m
Tracevoryx (formerly TrustWeave).cli demo` for scenario 1 in one command.

## Scenario 1 — Injected agent exfiltration chain (the differentiator)
Steps (synthetic, via `tests/test_provenance.py::test_full_chain_detected`):
1. Agent `doc-agent` ingests `http://untrusted.example/payload`
   → node labelled `UNTRUSTED_EXTERNAL_CONTENT`, edge `fetched` (observed).
2. Same agent reads `C:/u/.ssh/id_rsa` → `SENSITIVE_DATA`, edge `read`.
3. Same agent connects to `203.0.113.9:443` → `opened_connection`.

Result: **TW-EXPOSURE-PATH v1.0.0, severity critical**, confidence 1.0,
timeline of 3 steps, 2 supporting event ids, blind spots listed (sampling,
encrypted content, detective-not-preventive), suggested response (revoke
destination approval, rotate credential). Control test: the same read+connect
pair **without** untrusted taint yields *medium* with contradictory evidence
recorded; unrelated actors produce **no** finding.

## Scenario 2 — Prompt-injection → privileged tool call
Gateway (shadow mode ON): `shell.exec` unregistered/privileged → decision
`audit_only` with reason "would be 'deny' when enforcement is on".
Shadow OFF: JSON-RPC error **-32050 blocked**, the call never reaches a
downstream executor. (`tests/test_agent_guard.py::TestShadowVsEnforce`)

## Scenario 3 — Secrets in tool arguments
`http.post` with body containing an AWS key → detectors flag `api_key`,
decision recorded, and the raw key is **absent from storage**
(`test_secret_in_arguments_flagged`).

## Scenario 4 — Human-in-the-loop approval
Unregistered tool → `require_approval`, pending approval visible via
`GET /api/v1/approvals`; approving changes state; deny path returns denial.
(`TestApprovals`)

## Scenario 5 — Reversible redaction
Clipboard text with a GitHub token → redacted with `[TW:REDACT:…]`
placeholder; original recoverable only via authenticated reveal within the
session TTL; originals never written to the event store. (`test_privacy.py`)

## Scenario 6 — Passive API discovery
PCAP with `GET /api/open/data` (no auth header) → endpoint inventory entry +
the honest label ladder: `OBSERVED_ENDPOINT`, `AUTHENTICATION_NOT_OBSERVED`,
`POTENTIALLY_UNPROTECTED`, `NEEDS_VALIDATION` — never "vulnerable".
Header values (secrets) are dropped at ingest. (`test_api_mapper.py`)

## Scenario 7 — Adversarial inputs
Malformed JSON-RPC (-32700/-32600/-32601), invalid params, garbage PCAPs
(rejected with counts), tampered audit chain (verify reports broken seq),
unregistered tools, expired approvals. (`test_agent_guard.py`,
`test_api_mapper.py`, `test_integration.py`)

## Measured behavior
See `docs/BENCHMARKS.md` — synthetic-load ingest latency, exposure-query
latency, memory, and chain integrity under sustained volume.
