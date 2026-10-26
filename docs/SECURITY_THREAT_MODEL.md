# Security Threat Model — Tracevoryx 0.3.0

## Trust base
The OS user running Tracevoryx. Loopback binding by default. Tokens are
stored as SHA-256 hashes only (plaintext never at rest); optional per-token
expiry; the legacy plaintext `data/api_token` / `data/current_admin_token.txt`
files are retired artifacts and must be treated as compromised if ever seen
(see docs/SECRET_CLEANUP.md).

## Adversaries
| ID | Adversary | Primary defenses (verified in 0.3.0) |
|---|---|---|
| A1 | Prompt-injected agent | Taint graph + exposure-path findings; gateway approval; deny-by-default privileged tools; shadow mode does NOT execute would-be-denied calls |
| A2 | Malicious MCP client | Role separation; agent tokens BOUND to one identity (spoofing refused); approval bound to (identity, tool, args-hash), atomic single-use, expiring; rate limits with bounded state; request caps incl. streamed bodies |
| A3 | Local malware (same user) | Loopback + hashed tokens; CAN read DB/hash-store/memory — accepted, documented; audit key file separated from DB (0600 POSIX, O_NOFOLLOW); fs executor refuses runtime secrets |
| A4 | Log forger (insider with DB write) | Signed checkpoints (HMAC key in separate file) + retention-aware chain anchor + signed exports; documented limit: attacker with BOTH DB and current key file wins; rotation limits future forgery; export off-host for stronger guarantees |
| A5 | Capture/document smuggler | Strict pcap/HAR parsers, size caps, no eval, generic parse errors |
| A6 | Remote attacker | Loopback default; remote mode requires explicit config + TLS termination at proxy + strong tokens; lockout + bounded rate limits; security headers; CORS locked to loopback origins |

## Key boundaries (what we do NOT claim)
- The gateway does not intercept processes or tool calls that bypass it;
  enforcement exists only for calls routed through the gateway.
- Delegated tools: the gateway audits CALLER-REPORTED results
  (`observed=false, reported=true`); it cannot verify external execution.
- psutil sampling ≠ kernel audit. Windows Event Log coverage equals the
  enabled providers, probed honestly at startup.
- Detection ≠ prevention for clipboard (post-hoc race) and OS-level flows.
- Hash chain + checkpoints DETECT tampering; they cannot prevent a local
  attacker who controls both the DB and the checkpoint key file.
- Deterministic DLP is evadable (encodings, images).

## 0.3.0 hardening summary
Peer-validated SSRF guard (metadata/link-local always blocked, redirects
revalidated, proxies ignored), sensitive-file denylist for fs.read, atomic
single-use approvals, token-bound agent identity, shadow-withhold default,
SSE stream tickets, persisted enforcement choice, bounded limiter state,
streamed-body caps, security headers, audit-key rotation with retired
epochs, retention-safe chain verification.
