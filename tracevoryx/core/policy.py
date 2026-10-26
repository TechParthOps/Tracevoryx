"""Policy engine: allow | deny | require_approval | audit_only.

- Shadow mode (default ON at first run): every decision is computed and
  logged with what WOULD have happened, but enforcement is downgraded to
  audit_only so users can evaluate false positives first.
- Rules are JSON files in config/policies/*.json; deny wins over
  require_approval wins over audit_only wins over allow.
- Conditions use dotted paths into the decision context.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from ..config import get_settings

RANK = {"allow": 0, "audit_only": 1, "require_approval": 2, "deny": 3}


class Decision:
    def __init__(self, action: str, reason: str, rules: list[str],
                 shadow_applied: bool = False, approval_id: str | None = None,
                 intended_action: str | None = None):
        self.action = action
        self.reason = reason
        self.rules = rules
        self.shadow_applied = shadow_applied
        self.approval_id = approval_id
        # when shadow mode downgrades a decision, this records what the
        # decision WOULD have been with enforcement on
        self.intended_action = intended_action

    def to_dict(self) -> dict:
        return {
            "action": self.action, "reason": self.reason, "rules": self.rules,
            "shadow_applied": self.shadow_applied, "approval_id": self.approval_id,
            "intended_action": self.intended_action,
        }


class PolicyEngine:
    def __init__(self, policies_dir: Optional[Path] = None):
        self.settings = get_settings()
        self.policies_dir = policies_dir or (self.settings.root / "config" / "policies")
        self.rules: list[dict] = []
        self.version = "0"
        self.load()
        # operator runtime choice (persisted, survives restarts): shadow_mode
        # in the runtime state file overrides the config-file default
        self._apply_runtime_state()

    # --------------------------------------------------- runtime state file
    def _runtime_state_path(self):
        return self.settings.data_dir / "runtime_state.json"

    def _apply_runtime_state(self) -> None:
        p = self._runtime_state_path()
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if "shadow_mode" in data:
                self.settings._data["shadow_mode"] = bool(data["shadow_mode"])
        except (json.JSONDecodeError, OSError):
            pass  # unreadable state file: fall back to config default

    def _persist_runtime_state(self) -> None:
        try:
            p = self._runtime_state_path()
            current = {}
            if p.exists():
                current = json.loads(p.read_text(encoding="utf-8"))
            current["shadow_mode"] = bool(self.settings._data.get("shadow_mode", True))
            current["updated_at"] = self._now_iso()
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(current, indent=2), encoding="utf-8")
            tmp.replace(p)
        except (OSError, json.JSONDecodeError):
            pass  # persistence is best-effort; the in-memory choice stands

    @staticmethod
    def _now_iso() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    def load(self) -> int:
        self.rules = []
        if not self.policies_dir.exists():
            self.version = self._version()
            return 0
        skipped = 0
        for p in sorted(self.policies_dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                for rule in data.get("rules", []):
                    # ReDoS guard: policy regex conditions are admin-supplied,
                    # but cap their length; the stdlib re engine has no timeout
                    when = rule.get("when", {})
                    if isinstance(when, dict):
                        bad = any(
                            isinstance(cond, dict)
                            and cond.get("op") == "regex"
                            and len(str(cond.get("value", ""))) > 256
                            for cond in when.values())
                        if bad:
                            skipped += 1
                            continue
                    rule["_policy_file"] = p.name
                    self.rules.append(rule)
            except Exception:
                continue  # a broken policy file must not kill the engine
        self.version = self._version()
        return len(self.rules)

    def _version(self) -> str:
        """Stable hash of the effective rule set — every decision records it
        so any decision can be reproduced against the same policy content."""
        import hashlib
        return "pv1-" + hashlib.sha256(
            json.dumps(self.rules, sort_keys=True, default=str)
            .encode()).hexdigest()[:12]

    @property
    def shadow_mode(self) -> bool:
        return bool(self.settings.get("shadow_mode", True))

    def set_shadow_mode(self, enabled: bool) -> None:
        """Toggle enforcement. The choice is persisted to
        data/runtime_state.json so a restart cannot silently revert an
        operator's enforcement decision back to shadow (observe) mode."""
        self.settings._data["shadow_mode"] = bool(enabled)
        self._persist_runtime_state()

    def evaluate(self, ctx: dict[str, Any],
                 fallback: str = "allow") -> Decision:
        """Evaluate rules against a decision context (event fields + extras).
        Most restrictive matching rule wins; all matches reported."""
        matched: list[dict] = []
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            when = rule.get("when", {})
            ok = True
            for path, cond in when.items():
                if not _holds(ctx, path, cond):
                    ok = False
                    break
            if ok:
                matched.append(rule)
        if not matched:
            return Decision(
                fallback, f"no rule matched; default '{fallback}' applied", [])
        action = max((r["decision"] for r in matched), key=lambda a: RANK[a])
        rules = [r["id"] for r in matched if r["decision"] == action]
        return Decision(action, f"{len(matched)} rule(s) matched -> '{action}' "
                        f"via {', '.join(rules)}", rules)


def _lookup(obj: Any, dotted: str) -> tuple[bool, Any]:
    node = obj
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return False, None
    return True, node


def _holds(ctx: dict, path: str, cond: dict) -> bool:
    found, val = _lookup(ctx, path)
    op = cond.get("op", "eq")
    want = cond.get("value")
    if op == "exists":
        return found == bool(want)
    if not found:
        return False
    if op == "eq":
        return val == want
    if op == "contains":
        if isinstance(val, str):
            return str(want).lower() in val.lower()
        return want in (val or [])
    if op == "regex":
        try:
            return re.search(str(want), str(val), re.IGNORECASE) is not None
        except re.error:
            return False
    if op == "in":
        try:
            return val in want
        except TypeError:
            return False
    return False
