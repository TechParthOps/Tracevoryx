"""Cross-layer provenance graph.

The product's core: entities (agents, tools, content, files, processes,
destinations) and the relationships *observed* between them.

Design rules:
- An edge exists only when an event evidences it; `observed=False` edges are
  inferences and carry lower confidence. Temporal proximity never becomes an
  edge by itself.
- Trust labels propagate only along supported relations (see TAINT_EDGES).
- find_exposure_paths() answers: "can SENSITIVE_DATA reach an external
  destination through an actor that is itself tainted by untrusted content?"
  Returns full evidence chains for findings.
"""
from __future__ import annotations

import hashlib
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from ..core.events import TrustEvent
from ..core.store import Store, canon

# Relations that propagate taint downstream (data-flow semantics only).
# Anything not listed here does NOT propagate — we do not guess.
TAINT_EDGES = {
    "fetched":          (True, 1.0),   # content -> actor (untrusted enters)
    "read":             (True, 0.9),   # file/content -> actor (data in)
    "wrote":            (False, 0.9),  # actor -> file (data out to file)
    "invoked":          (True, 0.95),  # actor -> tool
    "spawned":          (True, 0.9),   # actor/process -> process
    "opened_connection": (False, 0.9), # actor/process -> destination
    "sent_data":        (False, 0.95), # actor/process -> destination
    "copied":           (True, 0.85),  # clipboard/content -> actor
    "belongs_to":       (False, 1.0),  # process -> agent (attribution)
}

EXTERNAL_RELATIONS = ("opened_connection", "sent_data")

NODE_KINDS = ("agent", "tool", "content", "clipboard", "file", "process",
              "destination", "endpoint")


class ProvenanceGraph:
    def __init__(self, store: Store):
        self.store = store
        self._taint_cache: dict[str, set[str]] = {}

    # ------------------------------------------------------------ helpers
    @staticmethod
    def node_id(kind: str, key: str) -> str:
        return hashlib.sha256(f"{kind}|{key}".encode()).hexdigest()[:16]

    def _node(self, kind: str, key: str, label: str = "",
              trust_label: str = "UNKNOWN", sensitive: bool = False,
              meta: dict | None = None) -> str:
        nid = self.node_id(kind, key)
        now = datetime.now(timezone.utc).isoformat()
        self.store.execute(
            """INSERT INTO provenance_nodes (node_id, kind, key, label,
               trust_label, sensitive, first_seen, last_seen, meta)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(node_id) DO UPDATE SET
               last_seen=excluded.last_seen,
               trust_label=CASE WHEN excluded.trust_label!='UNKNOWN'
                    THEN excluded.trust_label ELSE provenance_nodes.trust_label END,
               sensitive=max(sensitive, excluded.sensitive)""",
            (nid, kind, key, label or key, trust_label, int(sensitive),
             now, now, canon(meta or {})))
        return nid

    def _edge(self, src: str, dst: str, relation: str, event_id: str,
              observed: bool = True, confidence: float = 1.0,
              timestamp: str | None = None) -> None:
        self.store.execute(
            """INSERT INTO provenance_edges (edge_id, src, dst, relation,
               event_id, observed, confidence, timestamp)
               VALUES (?,?,?,?,?,?,?,?)""",
            (hashlib.sha256(f"{src}|{dst}|{relation}|{event_id}".encode()).hexdigest()[:16],
             src, dst, relation, event_id, int(observed),
             confidence, timestamp or datetime.now(timezone.utc).isoformat()))

    # ------------------------------------------------- event -> graph
    def ingest(self, event: TrustEvent) -> list[dict]:
        """Derive nodes/edges from one event. Returns new provenance-derived
        insights (e.g., exposure paths) for the bus to turn into findings."""
        edges_added: list[tuple[str, str, str]] = []
        actor_nid = self._actor_node(event)
        evt_time = event.timestamp

        if event.event_type == "content_ingested":
            c_nid = self._node("content", event.target,
                               trust_label=event.trust_label)
            if actor_nid:
                self._edge(c_nid, actor_nid, "fetched", event.event_id,
                           timestamp=evt_time)
                edges_added.append((c_nid, actor_nid, "fetched"))

        elif event.event_type == "clipboard_content":
            c_nid = self._node("clipboard", event.target or "clipboard",
                               sensitive=event.sensitive,
                               trust_label="SENSITIVE_DATA" if event.sensitive
                               else event.trust_label)
            if actor_nid:
                self._edge(c_nid, actor_nid, "copied", event.event_id,
                           timestamp=evt_time)
                edges_added.append((c_nid, actor_nid, "copied"))

        elif event.event_type == "tool_call":
            t_nid = self._node("tool", event.target,
                               trust_label="TRUSTED_CONFIGURATION",
                               meta={"tool": event.target})
            if actor_nid:
                self._edge(actor_nid, t_nid, "invoked", event.event_id,
                           timestamp=evt_time)
                edges_added.append((actor_nid, t_nid, "invoked"))
            # arguments referencing sensitive/untrusted entities create edges
            for ref in event.details.get("file_refs", []):
                f_nid = self._node("file", ref, sensitive=event.sensitive,
                                   trust_label="SENSITIVE_DATA" if event.sensitive
                                   else "UNKNOWN")
                rel = "wrote" if event.details.get("write") else "read"
                self._edge(t_nid, f_nid, rel, event.event_id,
                           timestamp=evt_time)
                edges_added.append((t_nid, f_nid, rel))
            if event.trust_label == "UNTRUSTED_EXTERNAL_CONTENT":
                c_nid = self._node("content", "tool-args:"
                                   + event.details.get("content_hash", event.event_id),
                                   trust_label="UNTRUSTED_EXTERNAL_CONTENT")
                self._edge(c_nid, actor_nid, "fetched", event.event_id,
                           timestamp=evt_time)
                edges_added.append((c_nid, actor_nid, "fetched"))

        elif event.event_type == "file_access":
            f_nid = self._node("file", event.target,
                               sensitive=event.sensitive,
                               trust_label="SENSITIVE_DATA" if event.sensitive
                               else "UNKNOWN")
            if actor_nid:
                self._edge(f_nid, actor_nid, "read", event.event_id,
                           timestamp=evt_time)
                edges_added.append((f_nid, actor_nid, "read"))

        elif event.event_type == "file_write":
            f_nid = self._node("file", event.target)
            if actor_nid:
                self._edge(actor_nid, f_nid, "wrote", event.event_id,
                           timestamp=evt_time)
                edges_added.append((actor_nid, f_nid, "wrote"))

        elif event.event_type == "process_started":
            p_nid = self._node("process", f"{event.pid}:{event.exe or event.target}",
                               meta={"exe": event.exe})
            if actor_nid:
                self._edge(actor_nid, p_nid, "spawned", event.event_id,
                           timestamp=evt_time)
                edges_added.append((actor_nid, p_nid, "spawned"))

        elif event.event_type == "connection":
            d_nid = self._node("destination", event.destination or event.target,
                               trust_label="TRUSTED_CONFIGURATION"
                               if event.details.get("approved") else "UNKNOWN")
            if actor_nid:
                rel = "sent_data" if event.details.get("data_sent") \
                    else "opened_connection"
                self._edge(actor_nid, d_nid, rel, event.event_id,
                           timestamp=evt_time)
                edges_added.append((actor_nid, d_nid, rel))

        if edges_added:
            self._taint_cache.clear()
        return self.run_detections() if edges_added else []

    def _actor_node(self, event: TrustEvent) -> Optional[str]:
        if not event.actor:
            return None
        if event.actor.startswith("agent:"):
            return self._node("agent", event.actor,
                              trust_label="TRUSTED_CONFIGURATION",
                              meta={"agent": event.actor})
        if event.pid is not None:
            return self._node("process",
                              f"{event.pid}:{event.exe or event.actor}",
                              meta={"exe": event.exe, "actor": event.actor})
        return self._node("process", event.actor, meta={"actor": event.actor})

    # ------------------------------------------------------- taint logic
    def tainted_actors(self, source_label: str = "UNTRUSTED_EXTERNAL_CONTENT") -> set[str]:
        """Node ids reachable *backwards* from any node carrying source_label
        along taint-propagating edges. Cached until the graph changes."""
        if source_label in self._taint_cache:
            return self._taint_cache[source_label]
        seeds = {r["node_id"] for r in self.store.execute(
            "SELECT node_id FROM provenance_nodes WHERE trust_label=?",
            (source_label,), fetch=True)}
        # forward adjacency for taint edges
        adj: dict[str, list[str]] = {}
        for e in self.store.execute("SELECT src, dst, relation FROM provenance_edges", fetch=True):
            info = TAINT_EDGES.get(e["relation"])
            if info and info[0]:
                adj.setdefault(e["src"], []).append(e["dst"])
        tainted: set[str] = set()
        q = deque(seeds)
        seen = set(seeds)
        while q:
            n = q.popleft()
            for m in adj.get(n, ()):
                if m not in seen:
                    seen.add(m)
                    tainted.add(m)
                    q.append(m)
        self._taint_cache[source_label] = tainted
        return tainted

    # ------------------------------------------------- exposure queries
    def find_exposure_paths(self, max_paths: int = 20) -> list[dict]:
        """SENSITIVE_DATA nodes whose readers connect to external destinations.

        A path is: sensitive_node --read--> actor --{connection,sent_data}--> dest
        where dest is external (not in internal_hosts). All edges must exist in
        the graph; each path lists its event evidence.
        """
        internal = set(self.store.settings.get("network.internal_hosts", []))
        nodes = {r["node_id"]: r for r in self.store.execute(
            "SELECT * FROM provenance_nodes", fetch=True)}
        sensitive = [n for n in nodes.values() if n["sensitive"]]
        tainted = self.tainted_actors()
        paths: list[dict] = []
        for s in sensitive:
            # edges point sensitive-file --> actor with relation 'read'/'copied'
            readers = self.store.execute(
                "SELECT * FROM provenance_edges WHERE src=? AND relation IN ('read','copied')",
                (s["node_id"],), fetch=True)
            for r_edge in readers:
                # reader is the dst of the read edge (file --> actor)
                actor = nodes.get(r_edge["dst"])
                if actor is None:
                    continue
                taint_boost = r_edge["dst"] in tainted
                conns = self.store.execute(
                    "SELECT * FROM provenance_edges WHERE src=? AND relation IN "
                    "('opened_connection','sent_data')",
                    (actor["node_id"],), fetch=True)
                for c_edge in conns:
                    dest = nodes.get(c_edge["dst"])
                    if dest is None:
                        continue
                    if self._is_internal(dest["key"], internal):
                        continue
                    confidence = round(min(
                        r_edge["confidence"], c_edge["confidence"]) *
                        (1.0 if taint_boost else 0.6), 3)
                    paths.append({
                        "sensitive_node": {"id": s["node_id"], "kind": s["kind"],
                                           "key": s["key"]},
                        "actor": {"id": actor["node_id"], "kind": actor["kind"],
                                  "key": actor["key"],
                                  "tainted_by_untrusted": taint_boost},
                        "destination": {"id": dest["node_id"], "kind": dest["kind"],
                                        "key": dest["key"]},
                        "relations": [r_edge["relation"], c_edge["relation"]],
                        "confidence": confidence,
                        "all_edges_observed": bool(r_edge["observed"] and c_edge["observed"]),
                        "evidence_event_ids": [r_edge["event_id"], c_edge["event_id"]],
                        "last_seen": max(r_edge["timestamp"], c_edge["timestamp"]),
                    })
                    if len(paths) >= max_paths:
                        return paths
        return paths

    @staticmethod
    def _is_internal(dest_key: str, internal: set[str]) -> bool:
        if "://" in dest_key:
            host = dest_key.split("/")[2].split(":")[0]
        else:
            host = dest_key.split(":")[0]
        host = host.lower().rstrip(".")
        return host in internal or any(host.endswith("." + i) for i in internal
                                       if "." in i)

    # ------------------------------------------------------ detections
    def run_detections(self) -> list[dict]:
        """Run all provenance-based detections; returns finding dicts."""
        findings: list[dict] = []
        findings.extend(self._detect_exposure_paths())
        return findings

    def _detect_exposure_paths(self) -> list[dict]:
        from ..detections.rules import EXPOSURE_PATH_RULE
        return EXPOSURE_PATH_RULE(self.find_exposure_paths())

    # --------------------------------------------------------- views
    def graph_snapshot(self, limit_nodes: int = 200, limit_edges: int = 400) -> dict:
        nodes = self.store.execute(
            "SELECT * FROM provenance_nodes ORDER BY last_seen DESC LIMIT ?",
            (limit_nodes,), fetch=True)
        edges = self.store.execute(
            "SELECT * FROM provenance_edges ORDER BY timestamp DESC LIMIT ?",
            (limit_edges,), fetch=True)
        tainted = self.tainted_actors()
        for n in nodes:
            n["sensitive"] = bool(n["sensitive"])
            n["tainted"] = n["node_id"] in tainted
        for e in edges:
            e["observed"] = bool(e["observed"])
        return {"nodes": nodes, "edges": edges}

    def lineage(self, node_id: str, depth: int = 3) -> dict:
        """Upstream (sources) and downstream (sinks) neighborhood of a node."""
        upstream: list[dict] = []
        frontier = {node_id}
        for _ in range(depth):
            if not frontier:
                break
            q = ",".join("?" for _ in frontier)
            # values are bound parameters; only the placeholder list varies
            rows = self.store.execute(
                f"SELECT * FROM provenance_edges WHERE dst IN ({q})",  # nosec B608
                tuple(frontier), fetch=True)
            frontier = {r["src"] for r in rows} - {node_id}
            upstream.extend(rows)
        downstream: list[dict] = []
        frontier = {node_id}
        for _ in range(depth):
            if not frontier:
                break
            q = ",".join("?" for _ in frontier)
            # values are bound parameters; only the placeholder list varies
            rows = self.store.execute(
                f"SELECT * FROM provenance_edges WHERE src IN ({q})",  # nosec B608
                tuple(frontier), fetch=True)
            frontier = {r["dst"] for r in rows} - {node_id}
            downstream.extend(rows)
        return {"node_id": node_id, "upstream": upstream,
                "downstream": downstream}

    def stats(self) -> dict:
        nodes = self.store.execute(
            "SELECT kind, COUNT(*) n FROM provenance_nodes GROUP BY kind", fetch=True)
        edges = self.store.execute(
            "SELECT relation, COUNT(*) n FROM provenance_edges GROUP BY relation",
            fetch=True)
        return {
            "nodes": {r["kind"]: r["n"] for r in nodes},
            "edges": {r["relation"]: r["n"] for r in edges},
            "tainted_actors": len(self.tainted_actors()),
        }
