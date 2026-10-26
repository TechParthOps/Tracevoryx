"""Passive API exposure mapper (spec §9).

Sources: imported PCAPs, HAR files, authorized proxy pushes. Values of
authentication headers are dropped at ingest — only NAMES are recorded.
Findings use the mandated labels:
  OBSERVED_ENDPOINT / AUTHENTICATION_NOT_OBSERVED /
  POTENTIALLY_UNPROTECTED / NEEDS_VALIDATION
Passive traffic never proves an endpoint is vulnerable.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..core.events import TrustEvent
from ..core.store import Store
from .pcap import extract_http

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key",
                     "x-auth-token", "proxy-authorization"}
_AUTH = {"authorization", "x-api-key", "x-auth-token", "cookie"}

_UUID_RX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

_NORMALIZERS = [
    (_UUID_RX, "{uuid}"),
    (re.compile(r"^\d+$"), "{id}"),
    (re.compile(r"^[0-9a-fA-F]{16,}$"), "{hex}"),
]


def normalize_path(path: str) -> str:
    segs = []
    for seg in path.strip("/").split("/"):
        norm = seg
        for rx, tmpl in _NORMALIZERS:
            if rx.match(seg):
                norm = tmpl
                break
        segs.append(norm)
    return "/" + "/".join(segs)


class ApiMapper:
    def __init__(self, store: Store):
        self.store = store
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        self.store.execute("""CREATE TABLE IF NOT EXISTS api_endpoints (
            endpoint_id TEXT PRIMARY KEY,
            host TEXT, method TEXT, path_template TEXT,
            first_seen TEXT, last_seen TEXT, sample_count INTEGER DEFAULT 0,
            status_codes TEXT DEFAULT '[]', params TEXT DEFAULT '[]',
            header_names TEXT DEFAULT '[]', auth_indicators TEXT DEFAULT '[]',
            in_openapi INTEGER DEFAULT 0, deprecated INTEGER DEFAULT 0,
            UNIQUE(host, method, path_template))""")

    # ------------------------------------------------------------- ingest
    def ingest_pcap(self, data: bytes, name: str = "pcap") -> dict:
        parsed, summary = extract_http(data)
        count = 0
        for t in parsed[:5000]:
            if t.request is None:
                continue
            host = next((v for k, v in t.request.headers if k == "host"), "") \
                or t.stream_key.split("->")[1].rsplit(":", 1)[0]
            raw = t.request.path.split("?", 1)
            query = [q.split("=", 1)[0]
                     for q in raw[1].split("&")] if len(raw) > 1 else []
            auth = [k for k, _ in t.request.headers if k in _AUTH]
            self._record(host, t.request.method, normalize_path(raw[0]),
                         t.response.status if t.response else 0, query, auth)
            count += 1
        self.store.append_event(TrustEvent(
            event_type="pcap_ingested", source="api_mapper", actor="mapper",
            target=name, trust_label="TRUSTED_CONFIGURATION",
            evidence=[{"kind": "pcap_summary", "label": name, "observed": True,
                       "detail": summary.__dict__}],
            collection_limitations=[
                "no TLS inspection; only plaintext HTTP captured",
                "reassembly is frame-order; retransmits can distort streams"]))
        return {"ingested": count, "summary": summary.__dict__}

    def ingest_har(self, data: bytes, name: str = "har") -> dict:
        doc = json.loads(data.decode("utf-8", errors="replace"))
        entries = doc.get("log", {}).get("entries", [])
        count = 0
        for e in entries[:5000]:
            req = e.get("request", {})
            resp = e.get("response", {})
            url = req.get("url", "")
            if not url:
                continue
            p = urlparse(url)
            host = p.netloc.split("@")[-1]
            query = [q.split("=", 1)[0]
                     for q in (p.query or "").split("&") if q]
            auth = [h.get("name", "").lower() for h in req.get("headers", [])
                    if h.get("name", "").lower() in _AUTH]
            self._record(host, req.get("method", "GET"),
                         normalize_path(p.path or "/"),
                         int(resp.get("status", 0) or 0), query, auth)
            count += 1
        self.store.append_event(TrustEvent(
            event_type="har_ingested", source="api_mapper", actor="mapper",
            target=name, trust_label="TRUSTED_CONFIGURATION",
            evidence=[{"kind": "har", "label": name, "observed": True,
                       "detail": {"entries": count}}]))
        return {"ingested": count}

    def ingest_openapi(self, data: bytes, name: str = "openapi") -> dict:
        doc = json.loads(data.decode("utf-8", errors="replace"))
        now = datetime.now(timezone.utc).isoformat()
        count = 0
        for path, ops in doc.get("paths", {}).items():
            if not isinstance(ops, dict):
                continue
            dep = any(isinstance(op, dict) and op.get("deprecated")
                      for op in ops.values())
            for m in ops:
                if m.lower() in ("get", "post", "put", "patch", "delete",
                                 "head", "options"):
                    self.store.execute(
                        """INSERT INTO api_endpoints (endpoint_id, host, method,
                           path_template, first_seen, last_seen, sample_count,
                           status_codes, params, header_names,
                           auth_indicators, in_openapi, deprecated)
                           VALUES (?,?,?,?,?,?,0,'[]','[]','[]','[]',1,?)
                           ON CONFLICT(host, method, path_template) DO UPDATE SET
                           in_openapi=1, deprecated=max(deprecated, excluded.deprecated)""",
                        (uuid.uuid4().hex,
                         urlparse((doc.get("servers") or [{"url": ""}])[0]
                                  .get("url", "")).netloc or "localhost",
                         m.upper(), normalize_path(path), now, now,
                         int(bool(dep))))
                    count += 1
        return {"documented": count}

    def _record(self, host: str, method: str, path: str, status: int,
                query: list[str], auth: list[str]) -> str:
        now = datetime.now(timezone.utc).isoformat()
        rows = self.store.execute(
            "SELECT endpoint_id, sample_count, status_codes, params, auth_indicators "
            "FROM api_endpoints WHERE host=? AND method=? AND path_template=?",
            (host, method, path), fetch=True)
        if rows:
            r = rows[0]
            sc = json.loads(r["status_codes"])
            if status and status not in sc:
                sc.append(status)
            params = json.loads(r["params"])
            if isinstance(params, list):
                params = {"query": []}
            for q in query:
                if q not in params["query"]:
                    params["query"].append(q)
            auth_list = json.loads(r["auth_indicators"])
            for a in auth:
                if a not in auth_list:
                    auth_list.append(a)
            self.store.execute(
                "UPDATE api_endpoints SET last_seen=?, sample_count=?, "
                "status_codes=?, params=?, auth_indicators=? WHERE endpoint_id=?",
                (now, r["sample_count"] + 1, json.dumps(sc), json.dumps(params),
                 json.dumps(auth_list), r["endpoint_id"]))
            return r["endpoint_id"]
        eid = uuid.uuid4().hex
        self.store.execute(
            """INSERT INTO api_endpoints (endpoint_id, host, method,
               path_template, first_seen, last_seen, sample_count, status_codes,
               params, header_names, auth_indicators, in_openapi, deprecated)
               VALUES (?,?,?,?,?,?,1,?,?,?,?,0,0)""",
            (eid, host, method, path, now, now,
             json.dumps([status] if status else []),
             json.dumps({"query": query}), json.dumps([]),
             json.dumps(auth)))
        return eid

    # ----------------------------------------------------------- findings
    def findings(self) -> list[dict]:
        internal = set(self.store.settings.get(
            "network.internal_hosts", ["localhost", "127.0.0.1"]))
        out = []
        for ep in self.store.execute(
                "SELECT * FROM api_endpoints ORDER BY host, path_template",
                fetch=True):
            auth = json.loads(ep["auth_indicators"])
            observed = ep["sample_count"] > 0
            if observed and not ep["in_openapi"]:
                out.append(self._f("OBSERVED_ENDPOINT", ep,
                                   f"Undocumented route {ep['method']} "
                                   f"{ep['path_template']} on {ep['host']}",
                                   "Observed in supplied traffic but not in "
                                   "any supplied OpenAPI document."))
            if observed and not auth:
                out.append(self._f("AUTHENTICATION_NOT_OBSERVED", ep,
                                   f"No auth indicator seen on {ep['method']} "
                                   f"{ep['path_template']}",
                                   "Traffic showed no Authorization/API-key/"
                                   "cookie headers. This does NOT mean the "
                                   "endpoint is unauthenticated (cookies/"
                                   "gateway auth may apply)."))
                out.append(self._f("POTENTIALLY_UNPROTECTED", ep,
                                   f"Candidate unprotected endpoint: "
                                   f"{ep['method']} {ep['path_template']}",
                                   "Candidate pending validation; never "
                                   "treated as confirmed from passive "
                                   "traffic alone."))
                out.append(self._f("NEEDS_VALIDATION", ep,
                                   f"Validate auth on {ep['method']} "
                                   f"{ep['path_template']}",
                                   "Requires an explicitly authorized test by "
                                   "the endpoint owner."))
            if observed and ep["in_openapi"] and ep["deprecated"]:
                out.append(self._f("OBSERVED_ENDPOINT", ep,
                                   f"Deprecated route still in use: "
                                   f"{ep['method']} {ep['path_template']}",
                                   "OpenAPI marks deprecated; traffic seen."))
            if ep["host"] and ep["host"] not in internal and \
                    not any(ep["host"].endswith("." + h) for h in internal):
                out.append(self._f("OBSERVED_ENDPOINT", ep,
                                   f"External destination observed: {ep['host']}",
                                   "Not in configured internal host list."))
        return out

    @staticmethod
    def _f(label: str, ep: dict, title: str, explanation: str) -> dict:
        return {"finding_id": uuid.uuid4().hex,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "label": label, "endpoint_id": ep["endpoint_id"],
                "title": title, "explanation": explanation,
                "sample_count": ep["sample_count"]}

    # -------------------------------------------------------------- views
    def inventory(self) -> list[dict]:
        rows = self.store.execute(
            "SELECT * FROM api_endpoints ORDER BY host, path_template",
            fetch=True)
        for r in rows:
            for f in ("status_codes", "params", "header_names", "auth_indicators"):
                r[f] = json.loads(r[f])
        return rows

    def openapi_draft(self) -> dict:
        paths: dict[str, dict] = {}
        for ep in self.inventory():
            if not ep["sample_count"]:
                continue
            item = paths.setdefault(ep["path_template"], {})
            item[ep["method"].lower()] = {
                "summary": f"[OBSERVED {ep['sample_count']}x] "
                           f"{ep['method']} {ep['path_template']}",
                "x-tracevoryx": {
                    "observation": "OBSERVED_ENDPOINT",
                    "auth_indicators": ep["auth_indicators"],
                    "status_codes": ep["status_codes"],
                },
                "responses": {"default": {"description": "observed"}},
            }
        return {"openapi": "3.1.0",
                "info": {"title": "tracevoryx observed API draft",
                         "version": "0.0.0-draft"},
                "paths": paths}
