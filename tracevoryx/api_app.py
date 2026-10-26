"""Tracevoryx (formerly tracevoryx) local control API — 0.3.0.

Auth model: hashed bearer tokens with roles; optional per-token expiry.
  admin   — everything incl. token issue + shadow toggle
  analyst — read-only (events/findings/graph/mapper/status) + simulation
  agent   — /mcp + tool result reporting only, bound to its label identity

Production hardening: per-identity token-bucket rate limits (bounded state),
request size caps (content-length AND streamed bytes), CORS allow-list
(loopback only by default), fail-closed executors, SSE live stream via
short-lived stream tickets (long-lived bearer tokens are no longer placed
in URLs), security headers, policy what-if simulation.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections import OrderedDict
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import PROJECT_ROOT
from .state import (AppState, get_state, issue_token,
                    load_token_records)

MAX_TEXT = 1024 * 1024
_STREAM_TICKET_TTL_S = 120
_STREAM_TICKET_CAP = 1000


class RateBucket:
    """Sliding-window rate limiter with BOUNDED identity state: at most
    `max_identities` windows are tracked (LRU eviction), so unique-IP or
    unique-identity floods cannot grow memory without limit."""

    def __init__(self, rate_per_min: int, max_identities: int = 10000):
        self.capacity = max(1, rate_per_min)
        self.max_identities = max(100, max_identities)
        self.tokens: OrderedDict[str, list[float]] = OrderedDict()

    def allow(self, ident: str) -> bool:
        now = time.time()
        window = self.tokens.get(ident)
        if window is None:
            if len(self.tokens) >= self.max_identities:
                self.tokens.popitem(last=False)  # evict oldest
            window = self.tokens.setdefault(ident, [])
        else:
            self.tokens.move_to_end(ident)
        while window and now - window[0] > 60:
            window.pop(0)
        if len(window) >= self.capacity:
            return False
        window.append(now)
        return True


# --- request models (module level: FastAPI + postponed annotations) ---
class InspectCall(BaseModel):
    agent: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)


class RegisterAgent(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    permissions: list[str] = Field(default_factory=list)


class RegisterTool(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    privileged: Optional[bool] = None
    allowed: Optional[bool] = None


class PrivacyIn(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT)
    context: str = Field(default="manual", pattern="^(manual|clipboard|agent)$")
    reversible: bool = False
    session_id: str = Field(default="default", max_length=64)


class RevealIn(BaseModel):
    session_id: str = Field(max_length=64)
    placeholder: str = Field(min_length=1, max_length=128)


class TokenIssue(BaseModel):
    role: str = Field(pattern="^(admin|analyst|agent)$")
    label: str = Field(default="", max_length=64)
    ttl_s: Optional[int] = Field(default=None, ge=1, le=31536000)


class ExecuteCall(BaseModel):
    agent: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)


class HandoffSeal(BaseModel):
    data_b64: str = Field(min_length=1)
    recipient_pub_pem: str = Field(min_length=1)
    ttl_s: Optional[int] = Field(default=None, ge=1, le=86400)


class HandoffOpen(BaseModel):
    record: dict[str, Any]
    open_token: str = Field(min_length=1, max_length=256)


def create_app(state: Optional[AppState] = None) -> FastAPI:
    app = FastAPI(title="Tracevoryx", version="0.3.0", docs_url=None,
                  redoc_url=None)
    st = state or get_state()
    app.state.tw = st
    _max_body = int(st.settings.get("api.max_body_mb", 200)) * 1024 * 1024

    # CORS: loopback origins only unless explicitly configured
    allowed = st.settings.get("api.cors_origins",
                              ["http://127.0.0.1:8640", "http://localhost:8640"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(allowed),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # ------------------------------------------------------------- limits
    read_bucket = RateBucket(int(st.settings.get("api.rate_per_min", 300)))
    mcp_bucket = RateBucket(int(st.settings.get("api.mcp_rate_per_min", 120)))
    auth_failures: OrderedDict[str, list[float]] = OrderedDict()
    AUTH_FAIL_CAP = 5000
    auth_lockdown: OrderedDict[str, float] = OrderedDict()

    def _client(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _record_auth_failure(ip: str) -> None:
        now = time.time()
        fails = [t for t in auth_failures.get(ip, []) if now - t < 300]
        while len(auth_failures) >= AUTH_FAIL_CAP and ip not in auth_failures:
            auth_failures.popitem(last=False)
        fails.append(now)
        auth_failures[ip] = fails
        auth_failures.move_to_end(ip)

    def _auth_locked(ip: str) -> bool:
        now = time.time()
        fails = [t for t in auth_failures.get(ip, []) if now - t < 300]
        if fails:
            auth_failures[ip] = fails
        if len(fails) >= 10:
            auth_lockdown[ip] = max(auth_lockdown.get(ip, 0),
                                    fails[-1] + 300)
            while len(auth_lockdown) >= AUTH_FAIL_CAP:
                auth_lockdown.popitem(last=False)
            return True
        return False

    def _check_token(request: Request) -> tuple[Optional[str], Optional[dict]]:
        token = request.headers.get("Authorization", "").removeprefix(
            "Bearer ").strip()
        rec = st.authenticate_record(token) if token else None
        return (token, rec) if rec else (None, None)

    def require_auth(request: Request, min_role: str = "analyst") -> str:
        ip = _client(request)
        if _auth_locked(ip):
            raise HTTPException(429, "too many auth failures; retry later")
        token, rec = _check_token(request)
        if rec is None:
            _record_auth_failure(ip)
            raise HTTPException(401, "missing or invalid bearer token")
        role = rec["role"]
        rank = {"agent": 0, "analyst": 1, "admin": 2}
        if rank[role] < rank[min_role]:
            raise HTTPException(403, f"role '{role}' insufficient for this "
                                     f"operation")
        if not read_bucket.allow(f"{role}:{token[-8:]}"):
            raise HTTPException(429, "rate limit exceeded")
        return role

    def require_admin(request: Request) -> str:
        return require_auth(request, "admin")

    def require_analyst(request: Request) -> str:
        return require_auth(request, "analyst")

    def require_agent(request: Request) -> tuple[str, Optional[str]]:
        """MCP auth: returns (role, bound_agent_identity). Agent-role tokens
        carry a label that binds the caller to one agent identity."""
        ip = _client(request)
        if _auth_locked(ip):
            raise HTTPException(429, "too many auth failures; retry later")
        token, rec = _check_token(request)
        if rec is None:
            _record_auth_failure(ip)
            raise HTTPException(401, "missing or invalid bearer token")
        if not mcp_bucket.allow(f"mcp:{token[-8:]}"):
            raise HTTPException(429, "gateway rate limit exceeded")
        return rec["role"], (rec.get("label") or None
                             if rec["role"] == "agent" else None)

    # ------------------------------------------------- security headers
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        ctype = resp.headers.get("content-type", "")
        if ctype.startswith("text/html"):
            resp.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; script-src 'self'; "
                "connect-src 'self'")
        return resp

    # ------------------------------------------------------------- limits
    @app.middleware("http")
    async def size_guard(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > _max_body:
                    return JSONResponse({"error": "payload too large"},
                                        status_code=413)
            except ValueError:
                return JSONResponse({"error": "invalid content-length"},
                                    status_code=400)
        # chunked/unknown-length bodies are capped while streaming, so the
        # request can never pull unbounded memory into the process
        received = 0
        original_receive = request._receive

        async def capped_receive():
            nonlocal received
            message = await original_receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > _max_body:
                    raise HTTPException(413, "payload too large")
            return message

        request._receive = capped_receive
        return await call_next(request)

    # ------------------------------------------------------------- health
    @app.get("/api/v1/health")
    def health() -> dict:
        return {"status": "ok", "version": app.version,
                "shadow_mode": st.policy.shadow_mode}

    # --------------------------------------------------------------- MCP
    @app.get("/mcp")
    def mcp_get() -> JSONResponse:
        """Intentional GET response: /mcp is POST-only JSON-RPC (MCP
        transport). Without this, the StaticFiles mount at '/' swallows the
        request into a bare 404. Unauthenticated; exposes no data."""
        return JSONResponse(
            {
                "error": "method_not_allowed",
                "transport": "HTTP JSON-RPC 2.0 (MCP-compatible)",
                "detail": "The MCP gateway accepts POST requests only. "
                          "A browser GET cannot speak JSON-RPC.",
                "usage": {
                    "method": "POST /mcp",
                    "auth": "Authorization: Bearer <agent-or-admin-token>",
                    "headers": {"Content-Type": "application/json"},
                    "initialize_example": {
                        "jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2024-11-05"}},
                    "error_codes": {"-32050": "blocked by policy",
                                    "-32051": "approval required",
                                    "-32052": "execution failed",
                                    "-32053": "approval invalid"},
                },
                "health_endpoint": "/api/v1/health",
            },
            status_code=405,
            headers={"Allow": "POST"})

    @app.post("/mcp")
    async def mcp_endpoint(request: Request,
                           auth: tuple = Depends(require_agent)) -> JSONResponse:
        role, bound_agent = auth
        body = await request.body()
        if len(body) > 512 * 1024:
            raise HTTPException(413, "request too large")
        try:
            req = json.loads(body)
        except (json.JSONDecodeError, RecursionError, ValueError):
            # unparseable (or pathologically nested) input: delegate to the
            # gateway so the JSON-RPC parse error is returned in-band
            return JSONResponse(
                st.gateway.handle_jsonrpc(body, bound_agent), status_code=200)
        # JSON-RPC notifications (no id) are accepted, not answered
        is_notification = isinstance(req, dict) and "id" not in req
        resp = st.gateway.handle_jsonrpc(body, bound_agent)
        if is_notification:
            return JSONResponse({"jsonrpc": "2.0",
                                 "result": {"accepted": True}},
                                status_code=202)
        return JSONResponse(resp, status_code=200)

    # ------------------------------------------------------------- status
    @app.get("/api/v1/status", dependencies=[Depends(require_analyst)])
    def status() -> dict:
        return {
            "stats": st.bus.stats(),
            "shadow_mode": st.policy.shadow_mode,
            "policy_version": st.policy.version,
            "sensors": _sensors_with_staleness(),
            "pipeline": st.pipeline.snapshot_stats(),
            "clipboard_running": st.clipboard.running,
            "winlog": st.winlog.probe_status or None,
            "pending_approvals": len(st.store.list_approvals("pending")),
            "executors": st.executors.stats(),
        }

    def _sensors_with_staleness():
        from .core.pipeline import sensor_staleness
        rows = sensor_staleness(st.store)
        # merge Windows probe detail (why a provider is degraded) into the
        # sensor rows so the dashboard explains itself
        for r in rows:
            if r["sensor"].startswith("winlog:"):
                log_name = r["sensor"].removeprefix("winlog:")
                if log_name in st.winlog.probe_status:
                    r["probe_status"] = st.winlog.probe_status[log_name]
                    r["probe_detail"] = st.winlog.probe_detail.get(log_name, "")
        return rows

    @app.post("/api/v1/shadow-mode", dependencies=[Depends(require_admin)])
    def shadow_mode(body: dict) -> dict:
        st.policy.set_shadow_mode(bool(body.get("enabled", True)))
        return {"shadow_mode": st.policy.shadow_mode,
                "note": "shadow ON = decisions logged; would-be-denied calls "
                        "are NOT executed unless "
                        "agent_guard.shadow_execute_would_deny=true"}

    # ------------------------------------------------------ policy what-if
    @app.post("/api/v1/policy/simulate", dependencies=[Depends(require_analyst)])
    def policy_simulate(body: InspectCall) -> dict:
        """Policy what-if simulator: evaluate the CURRENT policy against a
        hypothetical call WITHOUT executing anything, creating approvals, or
        writing events. Answers: what would this call do under this policy?"""
        base_action, base_reason = st.registry.tool_action(body.tool)
        tool_rec = st.registry.tool_record(body.tool) or {}
        det = st.privacy.inspect_deterministic(
            json.dumps(body.arguments, default=str)[:20000]) \
            if body.arguments else []
        sensitive_hits = sorted({d.detector for d in det})
        ctx = {
            "agent": body.agent, "tool": body.tool,
            "tool_privileged": bool(tool_rec.get("privileged", False)),
            "registered": st.registry.tool_record(body.tool) is not None,
            "sensitive_in_args": bool(sensitive_hits),
            "detectors": sensitive_hits,
            "agent_tainted": st.gateway._agent_tainted(body.agent),
            "open_exposure_paths": 0,
            "base_action": base_action,
        }
        decision = st.policy.evaluate(ctx, fallback=base_action)
        if "no rule matched" in decision.reason and base_action != "allow":
            decision.reason = base_reason
        simulated_shadow = st.policy.shadow_mode and decision.action in \
            ("deny", "require_approval")
        return {
            "simulation": True,
            "note": "what-if only: nothing was executed, no approval was "
                    "created, no event was written",
            "agent": body.agent, "tool": body.tool,
            "would_execute": not simulated_shadow,
            "action": ("audit_only (shadow would downgrade)" if simulated_shadow
                       else decision.action),
            "intended_action": decision.action,
            "reason": decision.reason,
            "matched_rules": decision.rules,
            "policy_version": st.policy.version,
            "base_action": base_action,
            "base_reason": base_reason,
            "sensitive_in_args": sensitive_hits,
        }

    # ------------------------------------------------------------ SSE stream
    # Short-lived stream tickets replace long-lived bearer tokens in URLs.
    # A ticket is: issued only to an authenticated analyst/admin, bound to
    # the issuing token's hash (audience), valid for a short TTL, and dies
    # with the token (validity re-checked at connect time). EventSource
    # reconnect uses the same ticket within its TTL; a leaked ticket is
    # worthless after TTL and grants nothing beyond the stream.

    stream_tickets: OrderedDict[str, tuple[str, float]] = OrderedDict()
    active_streams = {"count": 0}
    _max_sse = int(st.settings.get("api.max_sse_clients", 32))

    @app.post("/api/v1/stream/ticket", dependencies=[Depends(require_analyst)])
    def stream_ticket(request: Request) -> dict:
        import hashlib
        token = request.headers.get("Authorization", "").removeprefix(
            "Bearer ").strip()
        while len(stream_tickets) >= _STREAM_TICKET_CAP:
            stream_tickets.popitem(last=False)
        ticket = secrets.token_urlsafe(32)
        # audience = the presenting token (keyed by the same non-reversible
        # SHA-256 digest the token store uses); validity is re-checked
        # against live tokens at connect time, so revoking the token also
        # kills every ticket it issued
        stream_tickets[ticket] = (hashlib.sha256(token.encode()).hexdigest(),
                                  time.time())
        return {"ticket": ticket, "expires_in": _STREAM_TICKET_TTL_S,
                "note": "short-lived stream ticket; use as ?ticket= on "
                        "/api/v1/stream; do not log URLs"}

    @app.get("/api/v1/stream")
    async def stream(request: Request, ticket: str = "", token: str = "",
                     max_events: int = 0) -> StreamingResponse:
        # `token=` (raw bearer in URL) remains only as a deprecated fallback
        # and is scheduled for removal; prefer tickets.
        role = None
        if ticket:
            entry = stream_tickets.get(ticket)
            if entry and time.time() - entry[1] <= _STREAM_TICKET_TTL_S:
                # the bound bearer token must still be valid right now
                records = load_token_records(st.settings.data_dir)
                rec = records.get(entry[0])
                if rec:
                    role = rec["role"]
        elif token:
            role = st.authenticate(token)
        if role is None:
            raise HTTPException(401, "invalid or expired stream credentials")
        if active_streams["count"] >= _max_sse:
            raise HTTPException(429, "too many concurrent streams")
        max_events = min(max(max_events, 0), 5000)
        active_streams["count"] += 1

        async def gen():
            try:
                last_seq = 0
                row = st.store.execute(
                    "SELECT COALESCE(MAX(seq),0) m FROM events", fetch=True)
                last_seq = int(row[0]["m"]) if row else 0
                yield f"event: hello\ndata: {json.dumps({'role': role})}\n\n"
                sent = 0
                idle = 0
                while True:
                    rows = st.store.execute(
                        "SELECT seq, event_id, timestamp, event_type, actor, "
                        "target, trust_label, sensitive FROM events WHERE seq>? "
                        "ORDER BY seq LIMIT 20", (last_seq,), fetch=True)
                    if rows:
                        for r in rows:
                            last_seq = max(last_seq, int(r["seq"]))
                            sent += 1
                            yield f"data: {json.dumps(dict(r), default=str)}\n\n"
                            if 0 < max_events <= sent:
                                return
                        idle = 0
                    else:
                        idle += 1
                        if idle > 100:  # ~50s keepalive
                            yield ": keepalive\n\n"
                            idle = 0
                    await asyncio.sleep(0.5)
            finally:
                active_streams["count"] -= 1

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    # ------------------------------------------------------------ events
    @app.get("/api/v1/events", dependencies=[Depends(require_analyst)])
    def events(event_type: Optional[str] = None, actor: Optional[str] = None,
               since: Optional[str] = None, limit: int = 200,
               page: int = 0) -> dict:
        limit = min(max(limit, 1), 1000)
        rows = st.store.query_events(event_type=event_type, actor=actor,
                                     since=since, limit=limit)
        if page:
            rows = rows[page * limit:(page + 1) * limit]
        return {"events": rows, "count": len(rows), "page": page,
                "limit": limit}

    # ------------------------------------------------------------ mcp api
    @app.post("/api/v1/agent/inspect-call", dependencies=[Depends(require_analyst)])
    def inspect_call(body: InspectCall) -> dict:
        out = st.gateway.inspect_call(body.agent, body.tool, body.arguments)
        d = out["decision"]
        return {**out["public"], "approval_id": d.approval_id}

    @app.post("/api/v1/agent/execute-call", dependencies=[Depends(require_analyst)])
    def execute_call(body: ExecuteCall) -> dict:
        """Full decision+execution path via HTTP (built-in executors only)."""
        out = st.gateway.inspect_call(body.agent, body.tool, body.arguments)
        action = out["decision"].action
        if action in ("deny", "require_approval"):
            return {**out["public"], "approval_id":
                    out["decision"].approval_id, "executed": False}
        exec_out = st.gateway.execute_approved(
            body.agent, body.tool, body.arguments, out)
        result = exec_out["result"]
        withheld = bool(getattr(result, "withheld", False))
        return {**out["public"], "executed": bool(result.ok and not withheld),
                "execution": result.to_dict()}

    # ----------------------------------------------------------- registry
    @app.get("/api/v1/registry", dependencies=[Depends(require_analyst)])
    def registry() -> dict:
        return {"agents": list(st.registry.agents.values()),
                "tools": [dict(t, execution=st.executors.kind(name))
                          for name, t in st.registry.tools.items()]}

    @app.post("/api/v1/registry/agents", dependencies=[Depends(require_admin)])
    def reg_agent(body: RegisterAgent) -> dict:
        return st.registry.register_agent(body.name, body.permissions)

    @app.post("/api/v1/registry/tools", dependencies=[Depends(require_admin)])
    def reg_tool(body: RegisterTool) -> dict:
        rec = st.registry.register_tool(body.name, body.privileged,
                                        body.allowed)
        if body.name not in st.executors.handlers and \
                body.name not in st.executors.delegated:
            st.executors.register_delegated(body.name)
        return rec

    # ---------------------------------------------------------- approvals
    @app.get("/api/v1/approvals", dependencies=[Depends(require_analyst)])
    def approvals(status: Optional[str] = None) -> dict:
        return {"approvals": st.store.list_approvals(status)}

    @app.post("/api/v1/approvals/{approval_id}/decide", dependencies=[Depends(require_admin)])
    def decide_approval(approval_id: str, body: dict) -> dict:
        approved = body.get("approved")
        if not isinstance(approved, bool):
            raise HTTPException(400, "body must include approved: true|false")
        ok = st.approvals.decide(approval_id, approved)
        if not ok:
            raise HTTPException(404, "no pending approval with that id")
        return {"decided": ok, "approved": approved}

    # ------------------------------------------------------------- privacy
    @app.post("/api/v1/privacy/inspect", dependencies=[Depends(require_analyst)])
    def privacy_inspect(body: PrivacyIn) -> dict:
        return st.privacy.evaluate(body.text, context=body.context,
                                   reversible=body.reversible,
                                   session_id=body.session_id)

    @app.post("/api/v1/privacy/reveal", dependencies=[Depends(require_admin)])
    def privacy_reveal(body: RevealIn) -> dict:
        original = st.privacy.reveal(body.session_id, body.placeholder)
        if original is None:
            raise HTTPException(404, "placeholder unknown or session expired")
        return {"original": original}

    @app.get("/api/v1/privacy/capabilities", dependencies=[Depends(require_analyst)])
    def privacy_capabilities() -> dict:
        """Honest stage report: observe/detect/transform/prevent/verify per
        integration."""
        return {
            "clipboard_windows": {
                "observe": True, "detect": True, "transform": True,
                "prevent": "post-hoc only (race with other apps documented)",
                "verify": False,
                "note": "win32 polling; cannot intercept before delivery"},
            "gateway_arguments": {
                "observe": True, "detect": True, "transform": False,
                "prevent": "policy deny/require_approval before execution",
                "verify": True,
                "note": "args scanned pre-execution; denial blocks the call"},
            "text_inspect": {
                "observe": True, "detect": True, "transform": True,
                "prevent": "n/a (manual)", "verify": False},
        }

    @app.post("/api/v1/privacy/clipboard/control", dependencies=[Depends(require_admin)])
    def clipboard_control(body: dict) -> dict:
        if body.get("action") == "start":
            ok = st.clipboard.start()
            return {"running": st.clipboard.running, "started": ok,
                    "error": st.clipboard.last_error}
        if body.get("action") == "stop":
            st.clipboard.stop()
            return {"running": False}
        raise HTTPException(400, "action must be start|stop")

    # --------------------------------------------------------- provenance
    @app.get("/api/v1/provenance/graph", dependencies=[Depends(require_analyst)])
    def provenance_graph() -> dict:
        return st.graph.graph_snapshot()

    @app.get("/api/v1/provenance/lineage/{node_id}", dependencies=[Depends(require_analyst)])
    def lineage(node_id: str, depth: int = 3) -> dict:
        return st.graph.lineage(node_id, min(max(depth, 1), 5))

    @app.get("/api/v1/provenance/exposure-paths", dependencies=[Depends(require_analyst)])
    def exposure_paths() -> dict:
        return {"paths": st.graph.find_exposure_paths()}

    # ------------------------------------------------------------ findings
    @app.get("/api/v1/findings", dependencies=[Depends(require_analyst)])
    def findings(status: Optional[str] = None) -> dict:
        return {"findings": st.store.list_findings(status)}

    @app.post("/api/v1/findings/{finding_id}/feedback", dependencies=[Depends(require_analyst)])
    def finding_feedback(finding_id: str, body: dict) -> dict:
        fp = body.get("false_positive")
        new_status = body.get("status")
        ok = st.store.mark_finding(
            finding_id,
            status=new_status if new_status in ("open", "closed", "dismissed") else None,
            false_positive=fp if isinstance(fp, bool) else None)
        if not ok:
            raise HTTPException(404, "finding not found")
        return {"updated": ok}

    # --------------------------------------------------------- telemetry
    @app.post("/api/v1/telemetry/winlog/scan", dependencies=[Depends(require_admin)])
    def winlog_scan() -> dict:
        if not st.winlog.probe_status:
            st.winlog.probe()
        events = st.winlog.poll()
        submitted = [st.pipeline.submit_now(e) for e in events]
        return {"collected": len(submitted),
                "providers": st.winlog.probe_status,
                "last_error": st.winlog.last_error}

    @app.post("/api/v1/network/scan", dependencies=[Depends(require_admin)])
    def network_scan() -> dict:
        events = st.collector.agent_connections()
        submitted = [st.pipeline.submit_now(e) for e in events]
        return {"connections": len(submitted),
                "suspicious": sum(1 for e in events
                                  if not e.details.get("approved"))}

    # ----------------------------------------------------------- api mapper
    @app.post("/api/v1/apimapper/ingest/pcap", dependencies=[Depends(require_analyst)])
    async def ingest_pcap(file: UploadFile = File(...)) -> dict:
        cap = int(st.settings.get("api_mapper.max_capture_mb", 200)) * 1024 * 1024
        data = await file.read(cap + 1)
        if len(data) > cap:
            raise HTTPException(413, "capture too large")
        try:
            return st.api_mapper.ingest_pcap(data, (file.filename or "pcap")[:128])
        except ValueError:
            raise HTTPException(400, "invalid pcap document")

    @app.post("/api/v1/apimapper/ingest/har", dependencies=[Depends(require_analyst)])
    async def ingest_har(file: UploadFile = File(...)) -> dict:
        data = await file.read(50 * 1024 * 1024 + 1)
        if len(data) > 50 * 1024 * 1024:
            raise HTTPException(413, "too large")
        try:
            return st.api_mapper.ingest_har(data, (file.filename or "har")[:128])
        except Exception:
            raise HTTPException(400, "invalid HAR document")

    @app.get("/api/v1/apimapper/inventory", dependencies=[Depends(require_analyst)])
    def api_inventory() -> dict:
        return {"endpoints": st.api_mapper.inventory()}

    @app.get("/api/v1/apimapper/findings", dependencies=[Depends(require_analyst)])
    def api_findings() -> dict:
        return {"findings": st.api_mapper.findings()}

    @app.get("/api/v1/apimapper/openapi-draft", dependencies=[Depends(require_analyst)])
    def api_draft() -> dict:
        return st.api_mapper.openapi_draft()

    # ---------------------------------------------------------------- auth
    @app.post("/api/v1/auth/rotate", dependencies=[Depends(require_admin)])
    def auth_rotate(request: Request) -> dict:
        from .state import revoke_token

        new = issue_token(st.settings.data_dir, "admin", "rotated")
        # true rotation: the caller's token is revoked immediately
        old = request.headers.get("Authorization", "").removeprefix(
            "Bearer ").strip()
        revoke_token(st.settings.data_dir, old)
        return {"rotated": True, "token": new,
                "note": "previous token revoked; shown once, hash-stored"}

    @app.post("/api/v1/auth/tokens", dependencies=[Depends(require_admin)])
    def auth_issue(body: TokenIssue) -> dict:
        token = issue_token(st.settings.data_dir, body.role, body.label,
                            ttl_s=body.ttl_s)
        return {"issued": True, "role": body.role, "token": token,
                "ttl_s": body.ttl_s,
                "note": "shown once; only the SHA-256 hash is stored"
                        + ("; agent tokens bind the label as the caller's "
                           "gateway identity" if body.role == "agent" else "")}

    @app.post("/api/v1/auth/revoke", dependencies=[Depends(require_admin)])
    def auth_revoke(body: dict) -> dict:
        """Revoke by presenting the token to revoke (hash-compare server
        side); admin may revoke any token including its own."""
        from .state import revoke_token

        target = str(body.get("token", ""))
        if not target:
            raise HTTPException(400, "body must include token")
        ok = revoke_token(st.settings.data_dir, target)
        return {"revoked": bool(ok)}

    # --------------------------------------------------------- audit
    @app.post("/api/v1/audit/verify", dependencies=[Depends(require_analyst)])
    def audit_verify() -> dict:
        return st.checkpoints.verify()

    @app.post("/api/v1/audit/checkpoint", dependencies=[Depends(require_admin)])
    def audit_checkpoint() -> dict:
        return st.checkpoints.create()

    @app.post("/api/v1/audit/export", dependencies=[Depends(require_admin)])
    def audit_export() -> dict:
        out = st.settings.data_dir / f"audit_export_{int(time.time())}.jsonl"
        return st.checkpoints.export_events(out)

    @app.get("/api/v1/audit/integrity", dependencies=[Depends(require_analyst)])
    def audit_integrity() -> dict:
        return st.store.integrity_check()

    @app.post("/api/v1/retention", dependencies=[Depends(require_admin)])
    def retention() -> dict:
        return {"removed": st.store.retention_cleanup()}

    # ------------------------------------------------------------ handoff
    @app.post("/api/v1/handoff/seal", dependencies=[Depends(require_analyst)])
    def handoff_seal(body: HandoffSeal) -> dict:
        import base64
        try:
            raw = base64.b64decode(body.data_b64, validate=True)
        except Exception:
            raise HTTPException(400, "data_b64 is not valid base64")
        try:
            rec, token = st.handoff.seal(body.recipient_pub_pem.encode(),
                                         raw, body.ttl_s)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"record": rec, "open_token": token}

    @app.post("/api/v1/handoff/open", dependencies=[Depends(require_analyst)])
    def handoff_open(body: HandoffOpen) -> dict:
        import base64
        try:
            out = st.handoff.open(body.record, body.open_token,
                                  st.handoff.private_key_pem())
        except ValueError:
            raise HTTPException(403, "handoff rejected: malformed record")
        except Exception:
            raise HTTPException(403, "handoff rejected")
        return {"receipt": out["receipt"],
                "data_b64": base64.b64encode(out["plaintext"]).decode()}

    # ------------------------------------------------------------ dashboard
    dash = PROJECT_ROOT / "tracevoryx" / "dashboard"
    if dash.exists():
        app.mount("/", StaticFiles(directory=str(dash), html=True),
                  name="ui")

    @app.on_event("shutdown")
    def _down() -> None:
        st.shutdown()

    return app
