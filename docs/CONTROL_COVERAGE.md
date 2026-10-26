# Control Coverage Matrix — Tracevoryx 0.3.0

Truthful coverage: every control lists what enforces it, the evidence
source, last verification, and known blind spots. This is a coverage model,
not a compliance badge.

| # | Control | Enforced at | Evidence source | Coverage | Last verified | Blind spots |
|---|---|---|---|---|---|---|
| 1 | Bearer-token auth (hashed-only storage) | `api_app.require_auth` → `state.authenticate_record` | events (401s not stored; failures tracked in-memory), token store = hashes only | all API routes except /health, /mcp GET | 0.3.0 live run (31/31) | in-memory failure state resets on restart; loopback trust base |
| 2 | Role separation (admin/analyst/agent) | route dependencies | role check code + tests | every sensitive route | 0.3.0 suite | simulation abilities of analyst (audited, by design) |
| 3 | Agent identity binding | gateway `_identity_mismatch` | tool_call events; tests | /mcp tools/call + tools/result | 0.3.0 suite + live | admin/analyst can simulate any identity (documented) |
| 4 | Brute-force lockout | `require_auth` failure tracking | in-memory counters | per-IP 10/5min | 0.3.0 | single-process; resets on restart; behind proxies IP = proxy |
| 5 | Rate limiting (bounded state) | RateBucket (LRU 10k) | status endpoint; tests | API + MCP | 0.3.0 | per-identity within TTL window; no cross-process sharing |
| 6 | Request size caps | middleware (headers + streamed) | 413 responses; tests | all routes | 0.3.0 suite | none known for HTTP path |
| 7 | Deny-by-default registry | `registry.tool_action` | tool_call decision events | gateway calls | 0.3.0 | only gateway-routed calls |
| 8 | Approval binding + single use | `approvals` + `kv_consume_if_unused` CAS | approvals table + events | tools/call require_approval | 0.3.0 (race test) | human approver identity is the API token holder |
| 9 | Shadow-no-bypass | `execute_approved` withholding | decision events w/ shadow flag | built-in executors | 0.3.0 (live) | delegated tools: decision returned, external execution out of boundary |
| 10 | fs executor confinement | `_safe_path` roots + denylist | ExecutionResult audits | fs.read | 0.3.0 (live: audit_key refused) | TOCTOU window if attacker has same-user FS write access (documented) |
| 11 | SSRF guard | `_parse_url` + `_validate_dest_ip` + peer check | ExecutionResult audits | http.get | 0.3.0 (mock server tests) | no TLS-inspection of content; DNS-over-HTTPS names resolve normally then are validated |
| 12 | Delegated-tool honesty | `record_tool_result` reported flags | tool_result events (source=delegated_adapter) | reported outcomes | 0.3.0 | cannot verify external execution (by design) |
| 13 | Event hash chain | `Store.append_event` | verify_chain | all events | 0.3.0 | DB-writer attacker can rewrite (checkpoints close part) |
| 14 | Signed checkpoints | `AuditCheckpoints` | verify() + trust_anchor status | chain head | 0.3.0 (tamper + rewrite tests) | attacker with DB+key defeats; mitigations: rotation, off-host export |
| 15 | Key hygiene/rotation | `ensure_key` 0600, `rotate_key` | retired-key epochs | audit key | 0.3.0 (live rotation executed) | Windows ACLs rely on directory permissions (documented) |
| 16 | Retention-safe verification | `retention_cleanup` + chain anchor | verify_chain | events | 0.3.0 (tests) | pre-anchor events unverifiable except via checkpoints |
| 17 | DLP detection/redaction | detectors + `_redact_dict` (lists now) | privacy events, receipts | gateway args, clipboard, text API | 0.3.0 | deterministic only; encodings/images evade; documented |
| 18 | Reversible vault | RedactionVault (memory-only) | reveal API (admin) | session TTL 30min | 0.3.0 | lost on restart (by design) |
| 19 | Provenance exposure paths | graph + EXPOSURE_PATH_RULE | findings table | sensitive→actor→external | 0.3.0 | O(sensitive) queries; sampling telemetry only |
| 20 | Handoff crypto | X25519+HKDF+ChaCha20Poly1305 | receipts | seal/open | 0.3.0 (adversarial suite) | single host memory key; restart loses sessions |
| 21 | Security headers | middleware | response headers | HTML+API | 0.3.0 (live) | CSP only on HTML; API JSON unproblematic |
| 22 | Release hygiene | package_release + hygiene tests + CI | dist scan, MANIFEST | release artifacts | 0.3.0 | does not scan untracked local files outside packaging |

**Coverage statement:** 22 controls, all verified in 0.3.0. Enforcement
boundaries are truthful: this product enforces what passes through the
gateway and observes (samples) the rest.
