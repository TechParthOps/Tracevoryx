"""Tool executors: the gateway's real execution path.

Two tool kinds:
- Built-in: a Python handler registered here executes INSIDE Tracevoryx with
  timeout, output caps, and fail-closed error handling.
- Delegated: the gateway returns the decision to the integrating agent, which
  executes and reports the outcome via `record_tool_result` (adapter contract:
  docs/LIVE_DEPLOYMENT_GUIDE.md §Delegated tools).

Safety:
- built-in file access is confined to configured allowed roots AND always
  denies sensitive runtime files (audit key, token store, databases, logs)
  even when they sit inside an allowed root;
- built-in HTTP validates the URL, resolves the destination, refuses to
  connect to any address outside the configured destination policy, validates
  the ACTUAL peer address on every connection (DNS-rebinding resistant),
  revalidates every redirect hop, ignores proxy environment variables,
  caps redirects, response size, and total time, and fails closed;
- every execution is audited with execution metadata.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import logging
import socket
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutTimeout
from pathlib import Path
from typing import Callable

from ..config import PROJECT_ROOT, get_settings
from ..core.logging_util import log_error


class ExecutorError(RuntimeError):
    pass


class ExecutionResult:
    def __init__(self, ok: bool, summary: str, data: dict | None = None):
        self.ok = ok
        self.summary = summary
        self.data = data or {}

    def to_dict(self) -> dict:
        return {"ok": self.ok, "summary": self.summary, "data": self.data}


# --------------------------------------------------------------------------
# Filesystem boundary
# --------------------------------------------------------------------------

# Runtime files that must never be readable by tool execution, even inside an
# allowed root: the audit trust anchor, the token store, databases/WAL/SHM,
# instance markers and logs.
_SENSITIVE_NAMES = {
    "audit_key", "api_tokens.json", "current_admin_token.txt",
    "tw_instance.json", "runtime_state.json",
}
_SENSITIVE_SUFFIXES = (".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3",
                       ".sqlite-wal", ".sqlite-shm", ".log", ".pem", ".key")
_DENIED_DIRS = (".git", ".venv", "venv", "logs", "data-bundled-backup")


def _is_sensitive_path(p: Path) -> bool:
    """True when the resolved path points at runtime secrets/DBs/logs."""
    name = p.name.lower()
    if name in _SENSITIVE_NAMES or name.startswith("audit_key.retired"):
        return True
    if name.startswith("audit_export_") and name.endswith(".jsonl"):
        return True
    if name.startswith("tw.log"):
        return True
    if any(name.endswith(sfx) for sfx in _SENSITIVE_SUFFIXES):
        return True
    parts = {part.lower() for part in p.parts}
    return any(d in parts for d in _DENIED_DIRS)


def _allowed_roots() -> list[Path]:
    settings = get_settings()
    roots = settings.get("agent_guard.allowed_roots")
    if not roots:
        # Safe default: the project tree (documentation, fixtures, source).
        # Runtime secrets remain blocked by the sensitive-path denylist.
        roots = [str(PROJECT_ROOT)]
    return [Path(r).expanduser().resolve() for r in roots]


def _safe_path(path: str) -> Path:
    if not path or not path.strip():
        raise ExecutorError("path required")
    p = Path(path).expanduser()
    try:
        p = p.resolve()  # canonicalize: resolves symlinks/junctions/..
    except (OSError, ValueError) as exc:
        raise ExecutorError(f"invalid path: {type(exc).__name__}") from exc
    if _is_sensitive_path(p):
        raise ExecutorError("path denied: sensitive runtime file")
    for r in _allowed_roots():
        try:
            if p.is_relative_to(r):
                return p
        except (ValueError, OSError):
            continue
    raise ExecutorError("path outside allowed roots")


# --------------------------------------------------------------------------
# HTTP boundary (SSRF-hardened)
# --------------------------------------------------------------------------

_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_REDIRECTS = 4
_HTTP_TIMEOUT_S = 10.0

# Destination ranges that are ALWAYS prohibited for built-in HTTP tools,
# regardless of configuration: link-local includes cloud metadata services
# (169.254.169.254, fd00:ec2::254), and broadcast/multicast/reserved space
# has no legitimate tool target.
_METADATA_HOSTS = {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal"}


def _validate_dest_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Raise unless the peer address is inside the configured destination
    policy. Cloud metadata and other link-local space is always blocked.

    Order matters: loopback is checked before the reserved/multicast refusal
    because ::1 technically sits inside Python's IPv6 reserved space."""
    if ip.is_link_local or str(ip) in _METADATA_HOSTS:
        raise ExecutorError(f"destination {ip} is prohibited "
                            f"(link-local/metadata)")
    if ip.is_loopback:
        return
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise ExecutorError(f"destination {ip} is prohibited "
                            f"(multicast/reserved/unspecified)")
    if ip.is_private:
        return
    if get_settings().get("agent_guard.http_allow_external", False):
        extra = get_settings().get("agent_guard.http_allowed_extra_cidrs", [])
        for cidr in extra or []:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return
            except ValueError:
                continue
        return
    raise ExecutorError(
        "external destination not allowed for built-in http tools "
        "(agent_guard.http_allow_external=false)")


def _parse_url(url: str) -> urllib.parse.SplitResult:
    try:
        parts = urllib.parse.urlsplit(url.strip())
        if parts.scheme not in ("http", "https"):
            raise ExecutorError("only http/https URLs")
        if not parts.hostname:
            raise ExecutorError("URL requires a host")
        if parts.username is not None or parts.password is not None:
            raise ExecutorError("embedded credentials are not allowed")
        if any(ord(c) < 0x20 or c.isspace() for c in url):
            raise ExecutorError("invalid characters in URL")
        if parts.port is not None and not (1 <= parts.port <= 65535):
            raise ExecutorError("invalid port")
    except ValueError as exc:
        raise ExecutorError("invalid URL") from exc
    return parts


def _resolve_and_validate_host(hostname: str) -> None:
    """Resolve the host and require EVERY resolved address to satisfy the
    destination policy (a mixed honest/attacker answer is refused)."""
    if hostname.lower() in _METADATA_HOSTS:
        raise ExecutorError("destination is prohibited (cloud metadata)")
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ExecutorError(f"cannot resolve host: {exc}") from exc
    if not infos:
        raise ExecutorError("host did not resolve")
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            raise ExecutorError("unparseable resolved address") from None
        _validate_dest_ip(ip)


def _check_peer(peer_ip: str) -> None:
    """Validate the ACTUAL peer address after connect — this closes the
    DNS-rebinding window between validation and use."""
    try:
        ip = ipaddress.ip_address(peer_ip)
    except ValueError:
        raise ExecutorError("unparseable peer address") from None
    _validate_dest_ip(ip)


class _ValidatedHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        super().connect()
        _check_peer(self.sock.getpeername()[0])


class _ValidatedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        super().connect()  # peer validated inside HTTPConnection.connect
        _check_peer(self.sock.getpeername()[0])


class _HardenedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        # timeout arrives via opener.open(req, timeout=...) -> req.timeout;
        # do not pass it again (do_open forwards req.timeout itself)
        return self.do_open(_ValidatedHTTPConnection, req)


class _HardenedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext | None = None):
        super().__init__(context=context)

    def https_open(self, req):
        return self.do_open(_ValidatedHTTPSConnection, req,
                            context=self._context)


class _CappedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow a bounded number of redirects; every hop opens a fresh
    validated connection, so each destination is re-checked (peer pinning).
    Credentials cannot leak across hops: URLs with userinfo are rejected at
    parse time and urllib strips the Authorization header on cross-host
    redirects via its own redirect_request logic."""

    max_redirections = _MAX_REDIRECTS


def _opener() -> urllib.request.OpenerDirector:
    # Explicitly NO ProxyHandler: proxy environment variables must not
    # influence where built-in tool traffic goes.
    ctx = ssl.create_default_context()
    opener = urllib.request.OpenerDirector()
    opener.add_handler(_HardenedHTTPHandler())
    opener.add_handler(_HardenedHTTPSHandler(context=ctx))
    opener.add_handler(_CappedRedirectHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    opener.add_handler(urllib.request.UnknownHandler())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    return opener


def _http_get(args: dict) -> ExecutionResult:
    url = str(args.get("url", ""))
    parts = _parse_url(url)
    _resolve_and_validate_host(parts.hostname)
    req = urllib.request.Request(
        url, headers={"User-Agent": "Tracevoryx/0.3", "Accept-Encoding": "identity"})
    try:
        with _opener().open(req, timeout=_HTTP_TIMEOUT_S) as resp:
            body = resp.read(_MAX_RESPONSE_BYTES + 1)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise ExecutorError(
                    f"response exceeds {_MAX_RESPONSE_BYTES} byte cap")
            return ExecutionResult(
                True, f"GET {parts.scheme}://{parts.netloc} -> {resp.status}",
                {"status": resp.status,
                 "sha256": hashlib.sha256(body).hexdigest(),
                 "bytes": len(body),
                 "body": body.decode("utf-8", errors="replace")[:4000]})
    except urllib.error.HTTPError as exc:
        # e.g. redirect cap exceeded or final error status — fail closed
        raise ExecutorError(f"http request refused: {exc.code}") from exc
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
        raise ExecutorError(f"http request failed: "
                            f"{type(exc).__name__}") from exc


def _fs_read(args: dict) -> ExecutionResult:
    path = _safe_path(str(args.get("path", "")))
    try:
        with open(path, "rb") as fh:  # open the canonicalized path directly
            data = fh.read(256 * 1024 + 1)
    except OSError as exc:
        raise ExecutorError(f"cannot read file: "
                            f"{type(exc).__name__}") from exc
    if len(data) > 256 * 1024:
        raise ExecutorError("file exceeds 256 KiB read cap")
    return ExecutionResult(True, f"read {len(data)} bytes from {path.name}",
                           {"bytes": len(data),
                            "content": data.decode("utf-8", errors="replace")})


def _sys_echo(args: dict) -> ExecutionResult:
    msg = str(args.get("message", ""))[:2000]
    return ExecutionResult(True, f"echo: {msg!r}", {"echo": msg})


BUILTIN_HANDLERS: dict[str, Callable[[dict], ExecutionResult]] = {
    "fs.read": _fs_read,
    "sys.echo": _sys_echo,
    "http.get": _http_get,
}


class ExecutorRegistry:
    """Bounded execution: a small worker pool with a hard per-call timeout.
    A timed-out handler keeps occupying its worker (Python threads cannot be
    killed), so the pool is bounded and saturation degrades to queueing —
    never unbounded thread growth."""

    def __init__(self):
        self.handlers: dict[str, Callable[[dict], ExecutionResult]] = dict(
            BUILTIN_HANDLERS)
        self.delegated: set[str] = set()
        self._pool = ThreadPoolExecutor(max_workers=4,
                                        thread_name_prefix="tw-exec")
        self.default_timeout_s = 20.0
        self._lock = threading.Lock()

    def register_builtin(self, name: str,
                         handler: Callable[[dict], ExecutionResult]) -> None:
        with self._lock:
            self.handlers[name] = handler

    def register_delegated(self, name: str) -> None:
        with self._lock:
            self.delegated.add(name)

    def kind(self, name: str) -> str:
        with self._lock:
            if name in self.handlers:
                return "builtin"
            if name in self.delegated:
                return "delegated"
        return "unregistered"

    def execute(self, name: str, args: dict, timeout_s: float | None = None
                ) -> ExecutionResult:
        with self._lock:
            handler = self.handlers.get(name)
        if handler is None:
            raise ExecutorError(f"no built-in executor for '{name}'")
        fut = self._pool.submit(handler, args)
        try:
            return fut.result(timeout=timeout_s or self.default_timeout_s)
        except FutTimeout:
            fut.cancel()
            raise ExecutorError(f"execution timed out after "
                                f"{timeout_s or self.default_timeout_s}s")
        except ExecutorError:
            raise
        except Exception as exc:
            log_error(logging.getLogger("tracevoryx.executor"),
                      "executor_error", tool=name, error=str(exc))
            raise ExecutorError(f"executor failed: {type(exc).__name__}") from exc

    def stats(self) -> dict:
        with self._lock:
            return {"builtin": sorted(self.handlers),
                    "delegated": sorted(self.delegated)}
