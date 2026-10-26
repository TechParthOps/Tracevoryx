"""tracevoryx configuration (config/settings.json, safe defaults).

Precedence: environment variables (TW_*) override config/settings.json,
which overrides the built-in defaults below.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULTS: dict[str, Any] = {
    "data_dir": "data",
    "api": {"host": "127.0.0.1", "port": 8640,
            "rate_per_min": 300, "mcp_rate_per_min": 120,
            "max_body_mb": 200, "max_sse_clients": 32},
    "retention_days": 30,
    "shadow_mode": True,  # policy decisions are computed+logged, not enforced, until disabled
    "redact_keys": ["content", "token", "password", "secret", "authorization",
                    "cookie", "clipboard_text", "arguments_text"],
    "policy": {
        "unregistered_tool_default": "require_approval",
        "privileged_tool_default": "deny",
        "approval_ttl_s": 900,
    },
    "agent_guard": {"enabled": True,
                    "shadow_execute_would_deny": False,
                    "http_allow_external": False},
    "privacy": {
        "clipboard_watch": {"enabled": False, "interval_ms": 700},
        "reversible_vault_ttl_s": 1800,
    },
    "network": {
        "scan_interval_s": 15,
        # destinations explicitly approved for agent-related processes
        "approved_destinations": ["localhost", "127.0.0.1", "::1"],
        # hostnames/IPs treated as internal (never "external destination")
        "internal_hosts": ["localhost", "127.0.0.1", "::1"],
    },
    "api_mapper": {"max_capture_mb": 200},
    "handoff": {"session_ttl_s": 600, "storage_mode": "temp"},
}

# Environment overrides: TW_<KEY> maps onto dotted settings; documented in
# .env.example. Values are strings; a handful are typed here.
ENV_OVERRIDES: dict[str, tuple[str, type]] = {
    "TW_LOG_LEVEL": ("log_level", str),
    "TW_API_HOST": ("api.host", str),
    "TW_API_PORT": ("api.port", int),
    "TW_API_RATE_PER_MIN": ("api.rate_per_min", int),
    "TW_API_MCP_RATE_PER_MIN": ("api.mcp_rate_per_min", int),
    "TW_API_MAX_BODY_MB": ("api.max_body_mb", int),
    "TW_PIPELINE_MAX_QUEUE": ("pipeline.max_queue", int),
}


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _apply_env(data: dict[str, Any]) -> dict[str, Any]:
    for env_key, (dotted, typ) in ENV_OVERRIDES.items():
        raw = os.environ.get(env_key)
        if raw is None or raw == "":
            continue
        node = data
        parts = dotted.split(".")
        for part in parts[:-1]:
            if not isinstance(node.get(part), dict):
                node[part] = {}
            node = node[part]
        try:
            node[parts[-1]] = typ(raw)
        except (ValueError, TypeError):
            continue  # malformed env value: keep the file/default value
    return data


class Settings:
    def __init__(self, root: Path | None = None, raw: dict[str, Any] | None = None):
        self.root = root or PROJECT_ROOT
        if raw is None:
            p = self.root / "config" / "settings.json"
            raw = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        self._data = _apply_env(_merge(DEFAULTS, raw))
        self.data_dir = self._resolve(self._data["data_dir"])
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._restrict(self.data_dir)

    def _resolve(self, p: str) -> Path:
        path = Path(p)
        return path if path.is_absolute() else self.root / path

    @staticmethod
    def _restrict(path: Path) -> None:
        try:
            if os.name != "nt":
                os.chmod(path, stat.S_IRWXU)
        except OSError:
            pass

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
