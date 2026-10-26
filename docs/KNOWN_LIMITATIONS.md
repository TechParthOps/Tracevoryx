# Known Limitations — Tracevoryx 0.3.0

## Enforcement boundary (the most important list)
1. **Only routed calls are enforced.** Tools executed outside the gateway
   (native exec, direct imports) are never intercepted. OS sensors give
   sampled *observation*, labelled with confidence and limitations.
2. **Delegated tools are trusted-reported.** The gateway audits
   `tools/result` reports as *reported* (observed=false) but cannot
   independently verify external execution.
3. **Denial ≠ undo.** If an action already executed elsewhere, we record
   the violation; we cannot reverse it.
4. Approval consumption is atomic with the decision; a failed execution
   after consumption requires a fresh human approval (fail-closed, by
   design).
5. Shadow mode logs would-be-deny decisions but does not execute them by
   default; the explicit opt-in
   (`agent_guard.shadow_execute_would_deny=true`) restores execution for
   evaluation purposes and is audited.
6. Admin/analyst tokens may simulate any agent identity via the gateway
   (an analysis feature); every simulated decision is audited with the
   asserted identity.

## Telemetry (Windows 11)
7. psutil sensors sample; short-lived processes/connections can be missed.
8. Windows Event Log coverage equals the enabled providers: Security 4688
   needs Audit Process Creation; Sysmon must be installed separately
   (probed honestly: `provider_missing` / `permission_denied` / etc.).
9. No ETW file-access telemetry, no DNS-query collection in this version.
10. Linux: no audit/eBPF collector implemented — documented non-feature.

## Privacy
11. Deterministic DLP is evadable (encodings, images, novel formats). No
    local NER yet. Never promise universal detection.
12. Clipboard protection is post-hoc on Windows (race disclosed in every
    clipboard event); reversible vault is memory-only and lost on restart
    by design; pagefile exposure cannot be excluded.

## Audit & storage
13. Signed checkpoints detect DB-only rewrites; an attacker controlling
    BOTH the database and the current `data/audit_key` defeats them.
    Rotate keys, export signed JSONL off-host, and read the trust-anchor
    status from `/api/v1/audit/verify` before relying on it.
14. After retention cleanup, events older than the chain anchor are not
    independently verifiable from the DB alone; the signed checkpoints
    made before cleanup remain the evidence for that period.
15. Single-host SQLite; single-writer per process. Not a fleet collector.
16. Windows: file ACL hardening relies on directory permissions; audit-key
    0600 enforcement is POSIX-only (documented).
17. Lockout/rate-limit state is per-process (resets on restart; not shared
    across instances).

## Deployment
18. No native TLS: bind loopback, or terminate TLS at a reverse proxy you
    operate; remote exposure without TLS is unsupported.
19. Token auth only — no CSRF-protected cookie sessions by design.
20. Release artifacts are checksummed (`MANIFEST.sha256`) but not
    cryptographically signed; the checksum establishes integrity of the
    file, not publisher identity. PyPI trusted publishing provides the
    stronger provenance path.

## Not implemented (explicitly)
21. Active API validation (requires authorized targets + consent;
    passive-only).
22. Multi-node clustering, external key-management integration, and
    automated certificate management.
