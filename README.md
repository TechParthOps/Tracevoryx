# Tracevoryx

**Local-first cross-layer AI security & data-flow defense — v0.3.0**
(formerly TrustWeave; see `docs/RENAME_MIGRATION.md`).

Tracevoryx connects evidence across AI tool calls, OS activity, sensitive
data, and network destinations into one **provenance graph** — then enforces
policy at the agent-to-tool boundary with **real execution** of built-in
tools. Its differentiator is not any single detector but the **connected
chain**:

```
Untrusted Input → AI Session → Tool Call → Process/File/Clipboard Access
                                          → Network/API Activity → Outcome
```

## Security model (read first)

- **Enforcement boundary:** only tool calls routed through the gateway are
  enforced. Tools executed outside it are observed (sampled), not blocked.
- **Auth:** hashed bearer tokens (admin / analyst / agent), optional
  per-token expiry, brute-force lockout, per-identity rate limits with
  bounded state, loopback-only binding by default.
- **Agent identity:** agent-role tokens are bound to one agent identity —
  an agent token cannot act as another agent or replay another agent's
  approval.
- **Approvals:** bound to exactly (agent, tool, args-hash), single-use
  (atomic), expiring; modified arguments or another identity require a new
  human decision.
- **Shadow mode is not a bypass:** would-be-denied calls are logged but not
  executed in observe mode by default.
- **Executors:** `fs.read` confined to allowed roots + a sensitive-file
  denylist (audit key, tokens, DBs, logs); `http.get` blocks cloud
  metadata/link-local, validates the actual peer address (rebinding
  resistant), revalidates redirects, ignores proxies, caps size/time.
- **Audit integrity:** hash-chained events + HMAC-signed checkpoints with a
  separately stored key; signed exports; rotation with retired-key epochs;
  verification reports the trust-anchor status. A local attacker who
  controls BOTH the database and the key file defeats this — documented,
  not hidden.
- **What we never claim:** universal DLP detection, kernel-audited process
  coverage, or prevention of actions that already happened. See
  `docs/KNOWN_LIMITATIONS.md` and `docs/CONTROL_COVERAGE.md`.

## What's real in 0.3.0

- Real pipeline: bounded queue with backpressure, event dedup, drop
  counters, per-sensor health + staleness — visible in `/api/v1/status`.
- Real gateway execution: built-in executors (`fs.read`, `sys.echo`,
  `http.get` with a hardened SSRF guard) run inside Tracevoryx with
  timeouts and fail-closed errors; delegated tools follow a documented
  adapter contract and their reports are audited as *reported*, not
  *observed*.
- Approvals that bind: approval authorizes exactly (agent, tool,
  args-hash), is single-use (atomic), expires, and is consumed at decision
  time.
- Policy what-if simulator: replay a hypothetical call against the current
  policy with zero side effects (API + `tracevoryx simulate`).
- Signed audit checkpoints + evidence-safe key rotation
  (`tracevoryx rotate-audit-key`).
- Windows Event Log collector (Security 4688 + Sysmon 1/3/11) with honest
  provider probes; live SSE dashboard with short-lived stream tickets.

## Quick start

```powershell
pip install -e ".[dev]"
tracevoryx demo                     # end-to-end attack chain + enforcement
tracevoryx serve                    # shadow mode ON (observe first)
tracevoryx enforce                  # enforcement ON
python scripts/live_validate.py     # 31-check acceptance run
python -m pytest tests/ -q          # full suite (244 tests)
python scripts/package_release.py   # clean release staging + secret scan
```

Linux/macOS: `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"`
and `.venv/bin/tracevoryx …`.

The first `serve` prints a one-time admin token. Issue role tokens with
`POST /api/v1/auth/tokens` (agent tokens: the `label` becomes the caller's
bound gateway identity).

## Documentation

| Doc | Content |
|---|---|
| docs/SECURITY_AUDIT.md | 0.3.0 audit methodology + scope |
| docs/VULNERABILITY_REGISTER.md | findings, severity, evidence, status, retest |
| docs/PENETRATION_TEST_PLAN.md | authorized scope + test matrix |
| reports/PENETRATION_TEST_REPORT.md | executed tests + results |
| docs/REMEDIATION_ROADMAP.md | P0–P3 plan with exit criteria |
| docs/PRODUCTION_READINESS.md | gate status |
| docs/RELEASE_CHECKLIST.md | release gate |
| docs/CONTROL_COVERAGE.md | control → evidence → blind spots matrix |
| docs/ARCHITECTURE.md | pipeline, execution model, boundaries |
| docs/SECURITY_THREAT_MODEL.md | adversaries + controls |
| docs/KNOWN_LIMITATIONS.md | bypasses + non-features |
| docs/RENAME_MIGRATION.md | TrustWeave → Tracevoryx compatibility |
| docs/SECRET_CLEANUP.md | incident cleanup for the 0.2.0 archive |
| docs/FEATURE_STATUS.md | per-feature status + evidence |

## License

MIT — see `LICENSE`.
