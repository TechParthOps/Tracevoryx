"""Deterministic detections over the provenance graph.

Each rule converts graph evidence into a finding per spec §11:
detection id/version, severity, confidence, timeline, supporting events,
contradictory evidence, rule, action taken, blind spots, suggested response.

Rules never treat prompt-injection text alone as compromise, and they state
their blind spots instead of hiding them.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

DETECTION_VERSION = "1.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def EXPOSURE_PATH_RULE(paths: list[dict]) -> list[dict]:
    """Sensitive data reached an external destination through an actor.

    Severity escalates when the actor is itself tainted by untrusted external
    content (the classic injected-agent exfiltration chain) — but only when
    the graph actually shows that taint.
    """
    findings = []
    for path in paths:
        tainted = path["actor"].get("tainted_by_untrusted", False)
        observed_all = path.get("all_edges_observed", False)
        if tainted:
            severity = "critical" if observed_all else "high"
        else:
            severity = "medium"
        title = (
            f"Data-exposure path: {path['sensitive_node']['key']} read by "
            f"{path['actor']['key']} -> external {path['destination']['key']}"
        )
        timeline = [
            {"step": 1,
             "what": f"sensitive {path['sensitive_node']['kind']} "
                     f"'{path['sensitive_node']['key']}' "
                     f"accessed via {path['relations'][0]}"},
            {"step": 2,
             "what": f"actor '{path['actor']['key']}' "
                     f"({path['actor']['kind']})"
                     + (" — tainted by UNTRUSTED_EXTERNAL_CONTENT"
                        if tainted else " — no untrusted taint observed"),
             },
            {"step": 3,
             "what": f"connection/sent_data to external '{path['destination']['key']}'"},
        ]
        contradictory = []
        if not observed_all:
            contradictory.append(
                "some edges in this path are inferred (observed=0), not "
                "directly witnessed; treat as weaker evidence")
        if not tainted:
            contradictory.append(
                "actor has no observed taint from untrusted content; the "
                "sensitive access and the connection may be unrelated")
        findings.append({
            "finding_id": uuid.uuid4().hex,
            "created_at": _now(),
            "detection_id": "TW-EXPOSURE-PATH",
            "detection_version": DETECTION_VERSION,
            "severity": severity,
            "confidence": path["confidence"],
            "title": title,
            "timeline": timeline,
            "supporting_events": path["evidence_event_ids"],
            "contradictory_evidence": contradictory,
            "rule": "exposure-path:sensitive->actor->external-dest"
                    + (":tainted-actor" if tainted else ""),
            "action_taken": "finding recorded; enforcement happens at the "
                            "policy layer when a matching action executes",
            "blind_spots": [
                "process-level file/connection attribution is sampled, not "
                "kernel-audited; short-lived activity can be missed",
                "encrypted traffic contents are not inspected",
                "if the exfiltration already completed before sensors saw "
                "the connection, this is detective, not preventive",
            ],
            "suggested_response": (
                "revoke the agent's network approval for this destination, "
                "rotate the exposed credential, and review the tool calls "
                "in the timeline" if tainted else
                "verify whether this actor legitimately uses this "
                "destination; if yes, add it to approved_destinations"),
        })
    return findings
