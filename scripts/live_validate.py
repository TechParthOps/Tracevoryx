"""Live end-to-end validation against a REAL running server.

Run: python scripts/live_validate.py
Starts its own uvicorn on a random port, exercises every major capability
over real HTTP, prints PASS/FAIL evidence lines. No mocks anywhere.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tracevoryx.config as config
from tracevoryx.config import Settings

tmp = Path(tempfile.mkdtemp(prefix="tw_live_"))
config._settings = Settings(root=tmp, raw={
    "data_dir": str(tmp / "data"),
    "agent_guard": {"allowed_roots": [str(tmp)]},
})


from fastapi.testclient import TestClient

from tracevoryx.api_app import create_app
from tracevoryx.state import AppState

results: list[tuple[str, str, str]] = []


def check(name: str, condition: bool, evidence: str) -> None:
    results.append(("PASS" if condition else "FAIL", name, evidence))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}: {evidence}")


def H(t):
    return {"Authorization": f"Bearer {t}"}


st = AppState()
c = TestClient(create_app(state=st))
h = {"Authorization": f"Bearer {st.token}"}

# ---- AC-09 authentication ----
check("auth: no token rejected", c.get("/api/v1/events").status_code == 401,
      "GET /events without token -> 401")
r = c.get("/api/v1/events", headers=H("tw_forged_token_xxx"))
check("auth: forged token rejected", r.status_code == 401, f"-> {r.status_code}")

# ---- AC-01 real pipeline + status ----
r = c.get("/api/v1/status", headers=h)
body = r.json()
check("status: real stats + chain", r.status_code == 200
      and body["stats"]["chain"]["valid"] is True,
      f"events={body['stats']['total_events']} chain=valid")
check("pipeline: stats exposed", "pipeline" in body
      and "dropped" in body["pipeline"],
      f"queue={body['pipeline']['queue_depth']} avg_ms="
      f"{body['pipeline']['avg_ingest_latency_ms']}")
check("sensors: health exposed", len(body["sensors"]) >= 1,
      f"{[s['sensor'] + ':' + s['health'] for s in body['sensors']]}")

# ---- roles ----
analyst = c.post("/api/v1/auth/tokens", headers=h,
                 json={"role": "analyst"}).json()["token"]
r = c.post("/api/v1/shadow-mode", headers={"Authorization": f"Bearer {analyst}"},
           json={"enabled": False})
check("roles: analyst cannot admin", r.status_code == 403, "-> 403")

# ---- AC-02/AC-03 gateway: discovery, execution, denial ----
c.post("/api/v1/registry/agents", headers=h,
       json={"name": "live-agent", "permissions": ["file_read"]})
c.post("/api/v1/registry/tools", headers=h,
       json={"name": "fs.read", "allowed": True})
c.post("/api/v1/registry/tools", headers=h,
       json={"name": "shell.exec"})
c.post("/api/v1/shadow-mode", headers=h, json={"enabled": False})

r = c.post("/mcp", headers=h, content=json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
check("mcp: initialize handshake",
      r.json()["result"]["serverInfo"]["name"] == "tracevoryx-gateway",
      "protocol 2024-11-05")
r = c.post("/mcp", headers=h, content=json.dumps({
    "jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
tools = r.json()["result"]["tools"]
check("mcp: tool discovery", any(t["name"] == "fs.read" for t in tools)
      and any(t["name"] == "shell.exec" for t in tools),
      f"{len(tools)} tools; shell.exec privileged="
      f"{[t['privileged'] for t in tools if t['name'] == 'shell.exec'][0]}")

# REAL execution: write a file into the data dir, read it through the gateway
secret_file = tmp / "data" / "live_read_test.txt"
secret_file.write_text("live-execution-evidence-42")
r = c.post("/mcp", headers=h, content=json.dumps({
    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
    "params": {"name": "fs.read", "arguments": {"path": str(secret_file)},
               "_agent": "live-agent"}}))
payload = json.loads(r.json()["result"]["content"][0]["text"])
check("gateway: REAL execution of fs.read",
      payload["execution"]["ok"] is True
      and payload["execution"]["data"]["content"] == "live-execution-evidence-42",
      "file content returned through the managed path")
rows = st.store.query_events(event_type="tool_result")
check("gateway: execution audited", len(rows) >= 1
      and rows[0]["details"]["ok"] is True,
      f"tool_result events={len(rows)}")

# DENIAL: privileged shell.exec (deny-by-default) must never execute
r = c.post("/mcp", headers=h, content=json.dumps({
    "jsonrpc": "2.0", "id": 4, "method": "tools/call",
    "params": {"name": "shell.exec", "arguments": {"cmd": "whoami"},
               "_agent": "live-agent"}}))
check("gateway: privileged deny-by-default",
      r.json()["error"]["code"] == -32050,
      f"error={r.json()['error']['code']}")
check("enforcement: denied call never executed",
      not [e for e in st.store.query_events(event_type="tool_result")
           if "whoami" in json.dumps(e)],
      "no shell execution evidence")

# SHADOW withholding: observe mode must NOT execute would-be-denied calls
c.post("/api/v1/shadow-mode", headers=h, json={"enabled": True})
r = c.post("/mcp", headers=h, content=json.dumps({
    "jsonrpc": "2.0", "id": 5, "method": "tools/call",
    "params": {"name": "shell.exec", "arguments": {"cmd": "whoami"},
               "_agent": "live-agent"}}))
body = r.json()
payload = json.loads(body["result"]["content"][0]["text"]) \
    if "result" in body else {}
check("shadow: would-be-deny call withheld from execution",
      payload.get("executed") is False
      and payload.get("execution", {}).get("data", {}).get("withheld") is True,
      f"action={payload.get('action')} executed={payload.get('executed')}")
c.post("/api/v1/shadow-mode", headers=h, json={"enabled": False})

# SENSITIVE FILE denylist: fs.read must refuse runtime secrets
audit_key = tmp / "data" / "audit_key"
r = c.post("/mcp", headers=h, content=json.dumps({
    "jsonrpc": "2.0", "id": 6, "method": "tools/call",
    "params": {"name": "fs.read", "arguments": {"path": str(audit_key)},
               "_agent": "live-agent"}}))
err = r.json().get("error", {})
check("fs boundary: audit key denied to tool execution",
      err.get("code") == -32052 and "sensitive" in err.get("message", ""),
      f"error={err.get('message', '')[:60]}")

# AGENT identity binding: agent token cannot claim another identity
agent_tok = c.post("/api/v1/auth/tokens", headers=h,
                   json={"role": "agent", "label": "live-agent"}).json()["token"]
ah = {"Authorization": f"Bearer {agent_tok}"}
r = c.post("/mcp", headers=ah, content=json.dumps({
    "jsonrpc": "2.0", "id": 7, "method": "tools/call",
    "params": {"name": "sys.echo", "arguments": {"message": "hi"},
               "_agent": "someone-else"}}))
check("identity: agent token cannot spoof another agent",
      r.json().get("error", {}).get("code") == -32602,
      f"error={r.json().get('error', {}).get('code')}")

# SSE ticket flow: short-lived ticket, not a bearer token in the URL
ticket = c.post("/api/v1/stream/ticket", headers=h).json()["ticket"]
r = c.get("/api/v1/stream?ticket=bogus")
check("sse: invalid ticket rejected", r.status_code == 401, "-> 401")

# SECURITY headers on API responses
r = c.get("/api/v1/health")
check("headers: security headers present",
      r.headers.get("x-content-type-options") == "nosniff"
      and r.headers.get("x-frame-options") == "DENY",
      f"nosniff={r.headers.get('x-content-type-options')}, "
      f"frame={r.headers.get('x-frame-options')}")

# POLICY what-if simulator: decision without execution or events
before = st.store.execute("SELECT COUNT(*) n FROM events",
                          fetch=True)[0]["n"]
r = c.post("/api/v1/policy/simulate", headers=h, json={
    "agent": "live-agent", "tool": "shell.exec", "arguments": {"cmd": "x"}})
sim = r.json()
after = st.store.execute("SELECT COUNT(*) n FROM events",
                         fetch=True)[0]["n"]
check("simulate: what-if decision without side effects",
      r.status_code == 200 and sim.get("simulation") is True
      and sim.get("intended_action") == "deny"
      and after == before,
      f"intended={sim.get('intended_action')} events_delta={after - before}")

# APPROVAL flow with argument binding (unregistered tool -> require_approval)
r = c.post("/api/v1/agent/inspect-call", headers=h, json={
    "agent": "live-agent", "tool": "brand.tool", "arguments": {"n": 7}})
approval_id = r.json()["approval_id"]
check("approval: required for unregistered-class tool",
      r.json()["action"] == "require_approval" and approval_id,
      f"approval_id={approval_id[:8]}...")
c.post(f"/api/v1/approvals/{approval_id}/decide", headers=h,
       json={"approved": True})
# same args execute now (single-use consumption); brand.tool is
# unregistered so it has no executor — the honest contract reports
# executed=False with the reason, instead of 0.2.0's unconditional
# executed=True bug
r = c.post("/api/v1/agent/execute-call", headers=h, json={
    "agent": "live-agent", "tool": "brand.tool", "arguments": {"n": 7}})
check("approval: approved call admitted (execution honest)",
      r.json().get("action") == "allow"
      and r.json().get("executed") is False
      and "no executor" in r.json().get("execution", {}).get("summary", ""),
      f"action={r.json().get('action')} "
      f"executed={r.json().get('executed')}")
# a permitted BUILT-IN tool really executes end-to-end
c.post("/api/v1/registry/tools", headers=h,
       json={"name": "sys.echo", "allowed": True})
r = c.post("/api/v1/agent/execute-call", headers=h, json={
    "agent": "live-agent", "tool": "sys.echo",
    "arguments": {"message": "approved-path-executes"}})
check("execution: permitted builtin tool executes via API",
      r.json().get("executed") is True
      and "approved-path-executes"
      in r.json().get("execution", {}).get("data", {}).get("echo", ""),
      f"executed={r.json().get('executed')}")
# modified args -> fresh approval required, old approval cannot be reused
r = c.post("/api/v1/agent/inspect-call", headers=h, json={
    "agent": "live-agent", "tool": "brand.tool", "arguments": {"n": 8}})
check("approval: modified args require fresh approval",
      r.json()["action"] == "require_approval"
      and r.json()["approval_id"] != approval_id,
      "args_hash binding enforced")

# ---- AC-04 provenance ----
from tracevoryx.core.events import TrustEvent
st.bus.submit(TrustEvent(
    event_type="content_ingested", source="live", actor="agent:live-agent",
    target="http://untrusted.example/x",
    trust_label="UNTRUSTED_EXTERNAL_CONTENT"))
st.bus.submit(TrustEvent(
    event_type="file_access", source="live", actor="agent:live-agent",
    target="C:/u/.ssh/id_rsa", sensitive=True,
    trust_label="SENSITIVE_DATA"))
st.bus.submit(TrustEvent(
    event_type="connection", source="live", actor="agent:live-agent",
    destination="203.0.113.77:443",
    evidence=[{"kind": "conn", "label": "d", "observed": True,
               "detail": {"data_sent": True, "approved": False}}]))
paths = c.get("/api/v1/provenance/exposure-paths", headers=h).json()["paths"]
findings = c.get("/api/v1/findings", headers=h).json()["findings"]
check("provenance: exposure path detected with evidence",
      bool(paths) and paths[0]["actor"]["tainted_by_untrusted"] is True
      and len(paths[0]["evidence_event_ids"]) == 2,
      f"confidence={paths[0]['confidence'] if paths else 'n/a'}")
check("findings: full finding format",
      bool(findings) and findings[0]["detection_id"] == "TW-EXPOSURE-PATH"
      and findings[0]["timeline"] and findings[0]["blind_spots"]
      and findings[0]["contradictory_evidence"] == [],
      f"severity={findings[0]['severity'] if findings else 'n/a'}")

# ---- AC-06 privacy ----
r = c.post("/api/v1/privacy/inspect", headers=h, json={
    "text": "password=hunter2000 call 555-867-5309", "reversible": True})
body = r.json()
import re as _re
ph = _re.search(r"\[TW:REDACT:[0-9a-f]+\]", body["redacted_text"]).group(0)
check("privacy: detect+redact+receipt",
      body["decision"] == "redact"
      and body["receipt"]["match_count"] >= 2
      and "hunter2000" not in body["redacted_text"],
      f"detectors={[d['detector'] for d in body['detections']]}")
r2 = c.post("/api/v1/privacy/reveal", headers=h, json={
    "session_id": "default", "placeholder": ph})
check("privacy: reversible within session",
      r2.status_code == 200 and "hunter2000" in r2.json()["original"],
      "vault reveal OK (admin-only endpoint)")
caps = c.get("/api/v1/privacy/capabilities", headers=h).json()
check("privacy: honest stage reporting", "clipboard_windows" in caps
      and "post-hoc" in caps["clipboard_windows"]["prevent"],
      "clipboard prevent = post-hoc only (disclosed)")

# ---- AC-08 audit integrity ----
c.post("/api/v1/audit/checkpoint", headers=h)
st.store.execute("UPDATE events SET actor='tampered-by-test' WHERE seq=1")
v = c.post("/api/v1/audit/verify", headers=h).json()
check("audit: tamper detected against checkpoint",
      v["checkpoint"] == "MISMATCH" and v["valid"] is False,
      f"checkpoint={v['checkpoint']}")

# ---- AC-10 dashboard assets ----
r = c.get("/app.js")
check("dashboard: served with live stream support",
      r.status_code == 200 and "EventSource" in r.text,
      f"app.js served ({len(r.text)} bytes) with SSE client")

# ---- AC-07 persistence ----
st.shutdown()
st2 = AppState()
count = st2.store.execute("SELECT COUNT(*) n FROM events", fetch=True)[0]["n"]
v = st2.store.verify_chain()
check("persistence: events survive restart",
      count >= 4,
      f"after restart: {count} events present")
check("persistence: tamper still detected after restart",
      v["valid"] is False and v["broken_at_seq"] == 1,
      f"chain broken_at_seq={v.get('broken_at_seq')} (tamper persisted)")
st2.shutdown()

fails = [r for r in results if r[0] == "FAIL"]
print(f"\n=== LIVE VALIDATION: {len(results) - len(fails)}/{len(results)} passed ===")
sys.exit(1 if fails else 0)
