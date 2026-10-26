# Remediation Roadmap — Tracevoryx

## P0 — release blockers (exit: all FIXED with retest evidence)

| Item | Status |
|---|---|
| Runtime credentials/keys/DBs in the 0.2.0 archive | DONE — revoked, rotated, destroyed plaintext, `.gitignore` + packaging deny rules + artifact test (docs/SECRET_CLEANUP.md) |
| SSRF to prohibited destinations (TVX-002) | DONE — peer validation, metadata block, redirect revalidation |
| fs.read reaches audit key/token store (TVX-001) | DONE — denylist + narrowed roots |
| Privileged execution after deny decision (TVX-101, enforce+shadow) | DONE — enforce denies; shadow withholds by default |
| Approval double-spend (TVX-003) | DONE — atomic CAS |
| Cross-identity approval replay (TVX-004) | DONE — token-bound identity |
| Unbounded resource consumption (TVX-104, TVX-203) | DONE — bounded state + streamed-body cap |

Exit evidence: 238/238 pytest (incl. 33 adversarial), 31/31 live checks,
pip-audit clean, release scanner clean.

## P1 — high-risk (exit: fixed + regression tests)

TVX-102 (SSE tickets), TVX-103 (reported vs observed), TVX-105 (persisted
enforcement), TVX-106 (retention anchor), TVX-107 (handoff token),
TVX-108 (expiry/lockout) — ALL DONE. Remaining P1 work (post-0.3.0):
TLS termination guidance for non-loopback deployments, multi-process
lockout state, CSRF review if cookie-based auth is ever added.

## P2 — hardening (next)

- External attestation destination (push signed checkpoints off-host; the
  key rotation + trust-anchor status groundwork is in place).
- Security telemetry dashboard for auth failures/lockouts.
- Semgrep + CodeQL workflows in CI (bandit + custom scanner already gate).
- Bounded traversal cache for exposure-path queries on very large graphs.
- Concurrency fuzzing of the MCP path under load.

## P3 — differentiation (design docs, no P0/P1 open)

1. Evidence-backed agent attack-path graph — extend edges with finding IDs
   and time ranges (graph already carries evidence_event_ids, observed
   flags, confidence).
2. Policy what-if simulator — SHIPPED in 0.3.0 (API + CLI, side-effect
   free); next: replay against recorded event batches.
3. Evidence-constrained AI investigator — design-only: local-model
   preferred, evidence-cited summaries, prompt-injection-in-logs treated as
   untrusted data, no policy-write or self-approval capability. NOT
   SHIPPED — must not be presented as present.
4. Remediation regression loop — the test discipline exists (adversarial
   suite + register); automation of the loop is future work.
5. Control coverage matrix — SHIPPED (docs/CONTROL_COVERAGE.md).

Rule observed during this engagement: no feature work started while P0
items were open.
