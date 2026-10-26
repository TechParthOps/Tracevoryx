"""MCP / JSON-RPC tool-call gateway with REAL execution path.

Full path per tools/call:
  auth → validate → registry (deny-by-default) → args scan → policy v-hash
  → [require_approval: bound to (agent, tool, args_hash), TTL, single-use,
     atomically consumed]
  → execution: built-in executor OR delegated contract
  → result validation → tool_result audit event → response

Identity model: the agent identity in a request is caller-asserted by
default (the MCP transport does not carry identity). When the HTTP layer
authenticates the caller with an AGENT-role token carrying a label, the
gateway is given that bound identity and REJECTS requests whose asserted
`_agent` differs from it — an agent token cannot act as another agent.
Admin/analyst tokens remain able to simulate any identity (simulation is an
analysis feature) and are always audited as such.

Shadow mode: decisions are computed and logged with what WOULD have happened;
enforcement is downgraded to audit_only. By default a call that would be
denied (or require approval) is NOT executed in shadow mode
(agent_guard.shadow_execute_would_deny=false): observe-mode must not become
a bypass. Set that flag true to opt into would-be-deny execution explicitly.

Fail-closed: executor errors produce deny decisions in enforce mode and are
audited; they never fall through to "allow" because something broke.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..core.approvals import ApprovalManager
from ..core.events import TrustEvent
from ..core.policy import Decision, PolicyEngine
from ..core.store import Store
from ..privacy_guard.service import PrivacyService
from ..provenance.graph import ProvenanceGraph
from .executors import ExecutionResult, ExecutorError, ExecutorRegistry
from .registry import AgentRegistry

JSON_RPC_ERRORS = {
    "parse": -32700, "invalid_request": -32600,
    "method_not_found": -32601, "invalid_params": -32602,
    "blocked": -32050, "approval_required": -32051,
    "execution_failed": -32052, "approval_invalid": -32053,
}

SUPPORTED_MCP_VERSIONS = ("2024-11-05",)

_MAX_AGENT_LEN = 128
_MAX_TOOL_LEN = 128
_MAX_ARGS_JSON_BYTES = 256 * 1024
_MAX_SUMMARY_LEN = 2000
_MAX_CALL_ID_LEN = 128


class MCPGateway:
    def __init__(self, store: Store, registry: AgentRegistry,
                 privacy: PrivacyService, graph: ProvenanceGraph,
                 policy: PolicyEngine, approvals: ApprovalManager,
                 executors: ExecutorRegistry | None = None):
        self.store = store
        self.registry = registry
        self.privacy = privacy
        self.graph = graph
        self.policy = policy
        self.approvals = approvals
        self.executors = executors or ExecutorRegistry()

    # ------------------------------------------------------------ JSON-RPC
    def handle_jsonrpc(self, raw: bytes | str,
                       bound_agent: str | None = None) -> dict:
        try:
            req = json.loads(raw)
        except json.JSONDecodeError as exc:
            return self._error(None, JSON_RPC_ERRORS["parse"],
                               f"parse error: {exc}")
        except (RecursionError, ValueError):
            return self._error(None, JSON_RPC_ERRORS["parse"],
                               "parse error: structure too deep or invalid")
        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" \
                or not isinstance(req.get("method"), str):
            return self._error(req.get("id") if isinstance(req, dict) else None,
                               JSON_RPC_ERRORS["invalid_request"],
                               "not a JSON-RPC 2.0 request")
        method = req["method"]
        rid = req.get("id")
        if method == "initialize":
            # MCP version negotiation: server replies with the version it
            # supports; an incompatible client disconnects per MCP spec.
            requested = ""
            if isinstance(req.get("params"), dict):
                requested = str(req["params"].get("protocolVersion", ""))[:64]
            negotiated = (requested if requested in SUPPORTED_MCP_VERSIONS
                          else SUPPORTED_MCP_VERSIONS[-1])
            return self._result(rid, {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "tracevoryx-gateway", "version": "0.3.0"},
                "instructions": "tools/call is policy-gated; built-in tools "
                                "execute here, delegated tools return the "
                                "decision for the integrating agent",
            })
        if method == "notifications/initialized":
            # lifecycle notification: acknowledged by the transport (202),
            # never a JSON-RPC response
            return self._result(None, {"accepted": True})
        if method == "tools/list":
            tools = []
            for t, rec in sorted(self.registry.tools.items()):
                tools.append({
                    "name": t, "description": rec.get("description", ""),
                    "privileged": rec["privileged"], "allowed": rec["allowed"],
                    "execution": self.executors.kind(t),
                })
            return self._result(rid, {"tools": tools})
        if method == "tools/call":
            return self.handle_tools_call(req, rid, bound_agent)
        if method == "tools/result":
            # adapter contract: delegated executors report outcomes here.
            # These are CALLER-REPORTED outcomes, never observed execution.
            params = req.get("params") or {}
            if not isinstance(params, dict):
                return self._error(rid, JSON_RPC_ERRORS["invalid_params"],
                                   "tools/result requires params (object)")
            ok, err = self._validate_result_params(params)
            if err:
                return self._error(rid, JSON_RPC_ERRORS["invalid_params"], err)
            mismatch = self._identity_mismatch(bound_agent,
                                               str(params.get("agent", "")))
            if mismatch:
                return self._error(rid, JSON_RPC_ERRORS["invalid_params"],
                                   mismatch)
            out = self.record_tool_result(
                str(params.get("agent", "unknown")),
                str(params.get("tool", "")),
                bool(params.get("ok", False)),
                str(params.get("summary", "")),
                call_id=str(params.get("call_id", "")))
            return self._result(rid, {"recorded": out["event_id"]})
        return self._error(rid, JSON_RPC_ERRORS["method_not_found"],
                           f"unsupported method: {method}")

    # ---------------------------------------------------------- validation
    @staticmethod
    def _identity_mismatch(bound_agent: str | None, claimed: str) -> str | None:
        """An agent-role token is bound to its label identity; claiming a
        different agent identity with it is refused."""
        if bound_agent and claimed and claimed != bound_agent:
            return (f"agent identity mismatch: token is bound to "
                    f"'{bound_agent}', request claims '{claimed}'")
        return None

    @staticmethod
    def _validate_result_params(params: dict) -> tuple[bool, str | None]:
        if len(str(params.get("agent", ""))) > _MAX_AGENT_LEN:
            return False, "params.agent too long"
        if len(str(params.get("tool", ""))) > _MAX_TOOL_LEN:
            return False, "params.tool too long"
        if len(str(params.get("summary", ""))) > _MAX_SUMMARY_LEN:
            return False, "params.summary too long"
        if len(str(params.get("call_id", ""))) > _MAX_CALL_ID_LEN:
            return False, "params.call_id too long"
        return True, None

    # ---------------------------------------------------------- tools/call
    def handle_tools_call(self, req: dict, rid: Any,
                          bound_agent: str | None = None) -> dict:
        params = req.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return self._error(rid, JSON_RPC_ERRORS["invalid_params"],
                               "tools/call requires params.name (string)")
        tool = params["name"]
        if not tool or len(tool) > _MAX_TOOL_LEN:
            return self._error(rid, JSON_RPC_ERRORS["invalid_params"],
                               "params.name length invalid")
        arguments = params.get("arguments", {})
        if arguments in (None, {}):
            arguments = {}
        if not isinstance(arguments, dict):
            return self._error(rid, JSON_RPC_ERRORS["invalid_params"],
                               "params.arguments must be a JSON object")
        try:
            if len(json.dumps(arguments, default=str)) > _MAX_ARGS_JSON_BYTES:
                return self._error(rid, JSON_RPC_ERRORS["invalid_params"],
                                   "params.arguments too large")
        except (TypeError, ValueError):
            return self._error(rid, JSON_RPC_ERRORS["invalid_params"],
                               "params.arguments not serializable")
        claimed = str(params.get("_agent", "unknown-agent"))
        if len(claimed) > _MAX_AGENT_LEN:
            return self._error(rid, JSON_RPC_ERRORS["invalid_params"],
                               "params._agent too long")
        mismatch = self._identity_mismatch(bound_agent, claimed)
        if mismatch:
            return self._error(rid, JSON_RPC_ERRORS["invalid_params"], mismatch)
        agent = bound_agent or claimed
        outcome = self.inspect_call(agent, tool, arguments)
        decision = outcome["decision"]
        action = decision.action
        if action == "deny":
            return self._error(rid, JSON_RPC_ERRORS["blocked"],
                               "tool call blocked by policy",
                               data=outcome["public"])
        if action == "require_approval":
            return self._error(rid, JSON_RPC_ERRORS["approval_required"],
                               "approval required before this tool call runs",
                               data={**outcome["public"],
                                     "approval_id": decision.approval_id})
        # allow / audit_only → EXECUTE through the real path
        exec_out = self.execute_approved(agent, tool, arguments, outcome)
        result = exec_out["result"]
        if getattr(result, "withheld", False):
            # shadow mode refused to execute a would-be-denied call
            return self._result(rid, {
                "content": [{"type": "text",
                             "text": json.dumps({
                                 **outcome["public"], "executed": False,
                                 "execution": result.to_dict()})}],
                "isError": False})
        if not result.ok:
            return self._error(rid, JSON_RPC_ERRORS["execution_failed"],
                               result.summary,
                               data={**outcome["public"],
                                     "execution": result.to_dict()})
        return self._result(rid, {
            "content": [{"type": "text",
                         "text": json.dumps({
                             **outcome["public"], "executed": True,
                             "execution": result.to_dict()})}],
            "isError": False})

    # ------------------------------------------------------------ inspect
    def inspect_call(self, agent: str, tool: str, arguments: Any) -> dict:
        """Decision path (no execution). Used by /api/v1/agent/inspect-call."""
        base_action, base_reason = self.registry.tool_action(tool)
        args_hash = self.approvals.args_hash(arguments)
        args_text = json.dumps(arguments, default=str)[:20000] if arguments else ""

        sensitive_hits: list[str] = []
        arg_findings: list[dict] = []
        if args_text:
            det = self.privacy.inspect_deterministic(args_text)
            sensitive_hits = sorted({d.detector for d in det})
            arg_findings = [{"detector": d.detector, "preview": d.preview,
                             "confidence": d.confidence} for d in det[:10]]

        tainted = self._agent_tainted(agent)
        exposure_paths = []
        if base_action == "allow" and sensitive_hits:
            exposure_paths = self.graph.find_exposure_paths()

        tool_rec = self.registry.tool_record(tool) or {}
        ctx = {
            "agent": agent, "tool": tool,
            "tool_privileged": bool(tool_rec.get("privileged", False)),
            "registered": self.registry.tool_record(tool) is not None,
            "sensitive_in_args": bool(sensitive_hits),
            "detectors": sensitive_hits,
            "agent_tainted": tainted,
            "open_exposure_paths": len(exposure_paths),
            "base_action": base_action,
        }
        decision = self.policy.evaluate(ctx, fallback=base_action)
        if "no rule matched" in decision.reason and base_action != "allow":
            decision.reason = base_reason

        # approval satisfaction: an approved, unused binding for the EXACT
        # (agent, tool, args_hash) downgrades require_approval -> allow.
        # Consumed HERE (decision time), atomically (single-use) so replays
        # of the same approved call require a fresh human approval.
        if decision.action == "require_approval":
            binding = self.approvals.find_binding(
                f"agent:{agent}" if agent else "unknown-agent", tool, args_hash)
            if binding and not binding.get("used"):
                approval = self.store.get_approval(
                    binding.get("approval_id", ""))
                if approval and approval.get("status") == "approved" and \
                        self.approvals.consume_binding(
                            f"agent:{agent}" if agent else "unknown-agent",
                            tool, args_hash):
                    decision.action = "allow"
                    decision.reason = (
                        f"approved via approval "
                        f"{binding['approval_id'][:8]}… (single-use, consumed)")

        evt = TrustEvent(
            event_type="tool_call", source="mcp_gateway",
            actor=f"agent:{agent}" if agent else "unknown-agent",
            target=tool,
            trust_label="SENSITIVE_DATA" if sensitive_hits else "UNKNOWN",
            sensitive=bool(sensitive_hits),
            evidence=[
                {"kind": "registry", "label": base_reason, "observed": True},
                {"kind": "args_scan",
                 "label": (f"{len(sensitive_hits)} detector type(s) in arguments"
                           if sensitive_hits
                           else "no sensitive data in arguments"),
                 "observed": True, "detail": {"detectors": sensitive_hits}},
                {"kind": "trust_state", "label": f"agent taint: {tainted}",
                 "observed": True, "detail": {"tainted": tainted}},
            ],
            correlation_confidence=1.0,
            collection_limitations=[
                "only calls routed through the gateway are inspected",
                "agent reasoning is not observable; arguments are the input"],
            details={
                "agent": agent, "tool": tool,
                "decision": decision.action,
                "decision_reason": decision.reason,
                "shadow": decision.shadow_applied,
                "policy_version": self.policy.version,
                "sensitive_hits": arg_findings,
                "args_hash": args_hash,
                "file_refs": [v for v in (arguments or {}).values()
                              if isinstance(v, str)
                              and ("/" in v or "\\" in v)][:10],
            })
        stored = self.store.append_event(
            evt, redact_keys=set(self.store.settings.get("redact_keys", [])))
        self.graph.ingest(evt)

        if decision.action == "require_approval" and not self.policy.shadow_mode:
            # reuse an existing unused binding for the exact same call;
            # a modified args_hash gets its own fresh approval
            binding = self.approvals.find_binding(evt.actor, tool, args_hash)
            if binding and not binding.get("used") and \
                    datetime.now(timezone.utc).isoformat() <= \
                    binding.get("expires_at", ""):
                decision.approval_id = binding["approval_id"]
            else:
                existing = self.store.find_pending_approval(evt.actor, tool)
                if existing and not binding:
                    decision.approval_id = existing["approval_id"]
                else:
                    rec = self.approvals.request(
                        agent=evt.actor, tool=tool, reason=decision.reason,
                        summary=(f"{tool} with sensitive args: {sensitive_hits}"
                                 if sensitive_hits else f"{tool} (unregistered)"),
                        event_id=stored["event_id"], args_hash=args_hash)
                    decision.approval_id = rec["approval_id"]
                    self.store.append_event(TrustEvent(
                        event_type="approval_requested", source="mcp_gateway",
                        actor=evt.actor, target=tool,
                        evidence=[{"kind": "approval",
                                   "label": rec["approval_id"],
                                   "observed": True}],
                        details={"approval_id": rec["approval_id"],
                                 "args_hash": args_hash}))

        if self.policy.shadow_mode and decision.action in ("deny", "require_approval"):
            intended = decision.action
            decision.intended_action = intended
            decision.shadow_applied = True
            decision.action = "audit_only"
            decision.reason = (f"shadow mode: would be '{intended}' when "
                               f"enforcement is on — {decision.reason}")

        return {
            "decision": decision,
            "args_hash": args_hash,
            "public": {
                "agent": agent, "tool": tool,
                "action": decision.action,
                "reason": decision.reason,
                "shadow_applied": decision.shadow_applied,
                "policy_version": self.policy.version,
                "sensitive_in_args": sensitive_hits,
                "agent_tainted": tainted,
                "event_id": stored["event_id"],
                "execution_kind": self.executors.kind(tool),
                "note": "arguments were scanned; values are not stored",
            },
        }

    # ------------------------------------------------------ execution path
    def execute_approved(self, agent: str, tool: str, arguments: Any,
                         outcome: dict) -> dict:
        """Execute via the executor registry. In enforce mode a deny path
        never reaches here; require_approval consumes the bound approval
        (exact args_hash, single-use) before executing."""
        decision: Decision = outcome["decision"]
        action = decision.action

        if action == "require_approval":
            # decision-time consumption handles approval satisfaction; reaching
            # here means no valid approved binding existed
            result = ExecutionResult(
                False, "approval missing, expired, already used, or "
                       "bound to different arguments")
            self._audit_result(agent, tool, result, outcome)
            return {"result": result}

        if action == "audit_only" and decision.shadow_applied and \
                decision.intended_action in ("deny", "require_approval") and \
                not self.store.settings.get(
                    "agent_guard.shadow_execute_would_deny", False):
            # Safe observe-mode default: a call the policy would deny (or
            # hold for approval) is logged but NOT executed. This keeps
            # shadow mode from becoming an enforcement bypass.
            result = ExecutionResult(
                False, "withheld: shadow mode does not execute would-be-"
                       "denied calls (agent_guard."
                       "shadow_execute_would_deny=false)",
                {"withheld": True, "intended_action": decision.intended_action})
            result.withheld = True
            self._audit_result(agent, tool, result, outcome)
            return {"result": result}

        kind = self.executors.kind(tool)
        if kind == "builtin":
            try:
                result = self.executors.execute(tool, arguments or {})
            except ExecutorError as exc:
                # fail-closed: audit the failure, do NOT mask as success
                result = ExecutionResult(False, f"execution failed: {exc}")
            self._audit_result(agent, tool, result, outcome)
            return {"result": result}
        if kind == "delegated":
            result = ExecutionResult(
                True, "delegated: decision returned to integrating agent; "
                      "report outcomes via tools/result",
                {"contract": "tools/result"})
            self._audit_result(agent, tool, result, outcome)
            return {"result": result}
        result = ExecutionResult(
            False, f"tool '{tool}' has no executor (register builtin or "
                   f"delegated)")
        self._audit_result(agent, tool, result, outcome)
        return {"result": result}

    def _audit_result(self, agent: str, tool: str, result, outcome: dict) -> dict:
        return self.store.append_event(TrustEvent(
            event_type="tool_result", source="mcp_gateway",
            actor=f"agent:{agent}", target=tool,
            evidence=[{"kind": "execution", "label": result.summary[:200],
                       "observed": True,
                       "detail": {"ok": result.ok,
                                  "policy_version": outcome["public"].get(
                                      "policy_version"),
                                  "shadow": outcome["public"].get(
                                      "shadow_applied")}}],
            details={"ok": result.ok,
                     "call_event_id": outcome["public"].get("event_id")}))

    # ------------------------------------------------------------- helpers
    def _agent_tainted(self, agent: str) -> bool:
        tainted = self.graph.tainted_actors()
        if not tainted:
            return False
        tainted_keys = set()
        for nid in tainted:
            rows = self.graph.store.execute(
                "SELECT key FROM provenance_nodes WHERE node_id=?",
                (nid,), fetch=True)
            if rows:
                tainted_keys.add(rows[0]["key"])
        return f"agent:{agent}" in tainted_keys

    @staticmethod
    def _result(rid: Any, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _error(rid: Any, code: int, message: str, data: Any = None) -> dict:
        err: dict = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": rid, "error": err}

    def record_tool_result(self, agent: str, tool: str, ok: bool,
                           summary: str, call_id: str = "") -> dict:
        """Record a CALLER-REPORTED outcome from a delegated tool adapter.

        Honesty invariant: this is a report, not observed execution. The
        event is marked reported=True / observed=False so the audit trail
        never conflates what the gateway witnessed with what a client claims."""
        evt = TrustEvent(
            event_type="tool_result", source="delegated_adapter",
            actor=f"agent:{agent}", target=tool,
            evidence=[{"kind": "reported_result", "label": summary[:200],
                       "observed": False, "reported": True,
                       "detail": {"note": "caller-reported; not verified by "
                                          "the gateway"}}],
            correlation_confidence=0.5,
            collection_limitations=[
                "delegated execution happens outside the gateway; the report "
                "is trusted input, not observed evidence"],
            details={"ok": ok, "call_id": call_id[:_MAX_CALL_ID_LEN],
                     "reported": True})
        return self.store.append_event(
            evt, redact_keys=set(self.store.settings.get("redact_keys", [])))
