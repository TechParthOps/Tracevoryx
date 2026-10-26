"""Agent & tool registry.

Deny-by-default for privileged tools: a newly registered tool marked
privileged is DENIED for calls until explicitly allowed via config/API.
Non-privileged unregistered tools fall back to the configured default
(require_approval by default).
"""
from __future__ import annotations

from ..core.events import TrustEvent
from ..core.store import Store

PRIVILEGED_TOOL_PATTERNS = (
    "shell", "exec", "command", "process", "write", "delete", "remove",
    "network", "http", "fetch", "request", "clipboard", "eval",
)


def infer_privilege(tool_name: str) -> bool:
    n = tool_name.lower()
    return any(p in n for p in PRIVILEGED_TOOL_PATTERNS)


class AgentRegistry:
    def __init__(self, store: Store):
        self.store = store
        self.agents: dict[str, dict] = store.kv_get("tw_agents", {})
        self.tools: dict[str, dict] = store.kv_get("tw_tools", {})

    def _save(self) -> None:
        self.store.kv_set("tw_agents", self.agents)
        self.store.kv_set("tw_tools", self.tools)

    # ------------------------------------------------------------- agents
    def register_agent(self, name: str, permissions: list[str] | None = None) -> dict:
        rec = {
            "name": name,
            "permissions": sorted(set(permissions or [])),
        }
        self.agents[name] = rec
        self._save()
        self.store.append_event(TrustEvent(
            event_type="agent_registered", source="agent_registry",
            actor=f"agent:{name}", target=name,
            trust_label="TRUSTED_CONFIGURATION",
            details={"permissions": rec["permissions"]}))
        return rec

    def agent_exists(self, name: str) -> bool:
        return name in self.agents

    def agent_permissions(self, name: str) -> list[str]:
        return self.agents.get(name, {}).get("permissions", [])

    # -------------------------------------------------------------- tools
    def register_tool(self, name: str, privileged: bool | None = None,
                      allowed: bool | None = None) -> dict:
        if privileged is None:
            privileged = infer_privilege(name)
        rec = {"name": name, "privileged": privileged,
               # allow state: None = undecided -> default policy applies
               "allowed": allowed}
        self.tools[name] = rec
        self._save()
        self.store.append_event(TrustEvent(
            event_type="tool_registered", source="agent_registry",
            actor="registry", target=name,
            trust_label="TRUSTED_CONFIGURATION",
            details={"privileged": privileged, "allowed": allowed}))
        return rec

    def tool_record(self, name: str) -> dict | None:
        return self.tools.get(name)

    def tool_action(self, name: str) -> tuple[str, str]:
        """(base_action, reason) for a tool before policy rules are applied."""
        rec = self.tools.get(name)
        if rec is None:
            default = self.store.settings.get(
                "policy.unregistered_tool_default", "require_approval")
            return default, (f"tool '{name}' is not registered; "
                             f"unregistered-tool default '{default}' applies")
        if rec["privileged"] and rec["allowed"] is not True:
            default = self.store.settings.get(
                "policy.privileged_tool_default", "deny")
            return default, (f"tool '{name}' is privileged and not explicitly "
                             f"allowed (deny-by-default)")
        if rec["allowed"] is False:
            return "deny", f"tool '{name}' explicitly disallowed"
        return "allow", f"tool '{name}' registered and permitted"
