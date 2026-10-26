# LIVE DEPLOYMENT GUIDE — Tracevoryx (formerly TrustWeave) 0.2.0 (Windows 11)

## 1. Install

```powershell
cd E:\Tracevoryx (formerly TrustWeave)
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

The install script: checks Python, creates `.venv`, installs pinned deps,
creates `data/`, and **prints the bootstrap admin token once** (only its
SHA-256 hash is stored in `data/api_tokens.json`). Copy it immediately.

Note: any v0.1.0 plaintext `data/api_token` is treated as compromised and is
deleted at first 0.2.0 start.

## 2. Start / stop

```powershell
.\scripts\start.ps1                 # shadow mode (observe only)
.\scripts\start.ps1 -Enforce        # enforcement ON (blocks / holds)
.\scripts\start.ps1 -WithClipboard  # + Windows clipboard DLP sensor
.\scripts\stop.ps1                  # stops only the process listening on 8640
```

Manual equivalent: `.\.venv\Scripts\python.exe -m Tracevoryx (formerly TrustWeave).cli serve`

## 3. Verify the deployment (60 seconds)

```powershell
# health (no auth)
curl http://127.0.0.1:8640/api/v1/health

# authenticated status — pipeline, sensors, chain
$h = @{ Authorization = "Bearer <TOKEN>" }
Invoke-RestMethod http://127.0.0.1:8640/api/v1/status -Headers $h

# full acceptance suite (starts its own instance)
.\.venv\Scripts\python.exe scripts\live_validate.py
```

Dashboard: open `http://127.0.0.1:8640/`, paste the admin token.

## 4. Issue role tokens

```powershell
# analyst (read-only) and agent (gateway-only) tokens, via API:
Invoke-RestMethod -Method Post http://127.0.0.1:8640/api/v1/auth/tokens `
  -Headers $h -ContentType "application/json" `
  -Body '{"role":"analyst","label":"soc-viewer"}'
```

Roles: `admin` (all), `analyst` (read-only), `agent` (`/mcp` + result
reporting only). Tokens are shown once; rotate with `POST /api/v1/auth/rotate`
(revokes the caller's token) or `Tracevoryx (formerly TrustWeave) rotate-token`.

## 5. Connect an MCP client / agent

**Transport:** HTTP JSON-RPC 2.0 (MCP-compatible) at `POST /mcp`.
**A browser `GET /mcp` intentionally returns 405** with a usage document -
the gateway is POST-only; that response comes from the API itself, not the
static file mount.

```powershell
$h = @{ Authorization = "Bearer <agent-token>" }
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8640/mcp" -Headers $h `
  -ContentType "application/json" `
  -Body '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}'
```

Supported sequence (verified live):
1. `initialize` - server replies with the `protocolVersion` it supports
   (`2024-11-05`); incompatible clients disconnect per the MCP spec.
2. `notifications/initialized` - HTTP 202 (notifications are not answered).
3. `tools/list` - registry with per-tool `execution` kind (builtin/delegated).
4. `tools/call` - decision + execution:
   - builtin tools (`fs.read`, `sys.echo`, `http.get`) run inside Tracevoryx (formerly TrustWeave)
   - delegated tools return the decision; report outcomes via
     `tools/result` (adapter contract below)
5. Error codes: `-32050` blocked, `-32051` approval required, `-32052`
   execution failed; `-32700/-32600/-32601/-32602` for protocol violations.

**Delegated-tool adapter contract:** the gateway returns the decision
(`action`, `reason`, `policy_version`, `event_id`, `args_hash`). The
integrating agent executes only on allow/audit_only and MUST report the
outcome via `tools/result` with the same `agent`/`tool`. Tracevoryx (formerly TrustWeave) audits
the report but cannot independently verify delegated execution - those
events are labelled `source=delegated_adapter` (documented boundary).

**Role rules:** agent tokens may call `/mcp` and report results; they cannot
read events/findings or reach admin endpoints. Privileged tools stay
deny-by-default regardless of which client asks.

### CLI tool-call command (Windows quoting)

`Tracevoryx (formerly TrustWeave) call` accepts inline JSON and repairs the well-known
Windows quote-stripping artifact **loudly** (a note is printed; keys/values
are never altered). For complex arguments prefer a file:

```powershell
# PowerShell 5.1 / 7 - inline (repair kicks in, a note is printed)
Tracevoryx (formerly TrustWeave) call test-agent sys.echo --params '{"message":"hello"}'

# doubled-quote form (arrives intact, no repair note)
Tracevoryx (formerly TrustWeave) call test-agent sys.echo --params '{""message"":""hello""}'

# reliable: JSON file (works for every shape incl. nested objects/arrays)
Tracevoryx (formerly TrustWeave) call test-agent sys.echo --params-file args.json
```

Exit codes: 0 allow/audit_only, 2 invalid input (concise message, no
traceback), 3 denied.

### Gateway troubleshooting
| Symptom | Cause | Fix |
|---|---|---|
| GET /mcp -> 405 + usage JSON | expected (POST-only transport) | use POST |
| 401 | missing/revoked token | issue an agent token (admin API) |
| 429 | gateway rate limit | default 120 req/min per identity |
| -32050 | policy denied the call | check registry + shadow mode |
| -32051 | approval required | approve via dashboard/API; single-use |
| -32052 | executor failed (timeout, path outside roots) | inspect event evidence |

## 6. Windows Event Log telemetry: states, diagnostics, enablement

Tracevoryx (formerly TrustWeave) distinguishes these provider states (visible in
`/api/v1/status` under `sensors[]` with `probe_status` + `probe_detail`):

| State | Meaning | What resolves it |
|---|---|---|
| `healthy` | accessible, events flowing | nothing - collecting |
| `no_events` | accessible, zero matching events yet | wait, or enable auditing |
| `audit_policy_disabled` | readable, but auditpol shows Process Creation = No Auditing | admin enables via auditpol (consent) |
| `audit_policy_unknown` | readable, but auditpol needs elevation to determine | run diagnostics elevated |
| `permission_denied` | OS refused log access | elevated session or Event Log Readers |
| `provider_missing` | Sysmon service not installed (checked via service enumeration, which needs no elevation) | install/configure Sysmon separately |

**Diagnostic (report-only, safe):**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate_win_eventlog.ps1
```

It reports session elevation, audit policy (elevated only - `auditpol /get`
requires admin), Security log readability, and Sysmon service/log status.
Observed on a standard-user session: `permission_denied` for Security and
Sysmon-log access while the Sysmon SERVICE was correctly detected as
present+running - i.e. a permission issue, not a missing prerequisite.

**Optional remediation (explicit consent, never automatic):**

```powershell
# elevated session; dry run shows the exact command, nothing changes:
powershell -File scripts\validate_win_eventlog.ps1 -EnableProcessCreationAuditing
# apply:
powershell -File scripts\validate_win_eventlog.ps1 -EnableProcessCreationAuditing -Apply
```

Tracevoryx (formerly TrustWeave) never runs auditpol /set or installs Sysmon itself.

**Enabling full telemetry (owner checklist):**
1. Elevated session or Event Log Readers membership for the service account.
2. `auditpol /set /subcategory:"Process Creation" /success:enable` (4688).
3. Install Sysmon with a config covering EIDs 1/3/11 (optional, separate).
4. Restart Tracevoryx (formerly TrustWeave); the probe re-runs and states flip to
   `no_events`/`healthy`.

The core API and all other sensors keep operating when Windows telemetry is
unavailable; degraded providers remain visibly degraded with the real OS
error recorded.

## 7. Backup / restore / upgrade

```powershell
# backup (stop first or accept in-flight WAL)
Copy-Item data\Tracevoryx (formerly TrustWeave).db  E:\backups\tw-$(Get-Date -Format yyyyMMdd).db
Copy-Item data\audit_key      E:\backups\audit-key-$(Get-Date -Format yyyyMMdd).key

# restore: stop, replace db + audit_key pair (they must match!), restart
# upgrade: pip install -e . ; migrations run automatically at startup
#   (schema_migrations table; safe to re-run)
```

Signed evidence export: `POST /api/v1/audit/export` (admin) → JSONL with
per-record HMACs + a checkpoint line; verify with
`AuditCheckpoints.verify_export(path)`.

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| 401 on everything | token revoked/rotated | issue a new token (admin CLI/API) |
| 429 responses | rate limit / auth lockout (10 bad attempts = 5-min lockout per IP) | wait, or restart with correct token |
| `winlog:Security` = degraded | non-elevated shell | run elevated or grant Event Log Readers |
| dashboard "stream: polling" | SSE blocked | check token in URL, loopback binding |
| pipeline dropped > 0 | queue overflow under burst | raise `pipeline.max_queue`; drops are counted, never silent |
| DB locked errors | two writers | Tracevoryx (formerly TrustWeave) serializes via WAL+BEGIN IMMEDIATE; avoid third-party writers |

## 9. Uninstall

`scripts\stop.ps1`, remove the directory. **`data/` is user evidence — the
uninstaller never deletes it.**
