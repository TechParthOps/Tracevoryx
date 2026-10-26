# Competitive Landscape — Tracevoryx (formerly TrustWeave) (researched 2026-10-15)

Method: GitHub repository search + README inspection for the categories below.
Findings are dated; anything not directly inspected is labelled UNVERIFIED.
Per the project rule: absence in one search is not proof of absence.

## 1. AI-agent / MCP tool-call security

### 1.1 mcp-agent-security-gateway (poojakira) — closest single-layer competitor
| | |
|---|---|
| What it implements | Default-deny MCP/JSON-RPC gateway; prompt-injection heuristics (69 named signatures, self-described as "code-inventory count, not effectiveness"); PII/exfiltration signals on routed tool calls; hash-chained audit; shadow mode; fail-closed PDP; stdio proxy + HTTP control plane; 782 tests / 81.93% coverage (Oct 2026 CI). |
| Documented limitations | "Enforcement depends on the integration path"; "not an OS firewall, endpoint agent, or complete DLP"; heuristic detectors "evadable"; application-layer egress only. |
| License | **Proprietary (All Rights Reserved) since 2026-10-13** (historically MIT). → We cannot reuse its code. Design-level ideas (default-deny, hash-chained audit, shadow mode) are not copyrightable and are implemented independently. |
| Gap Tracevoryx (formerly TrustWeave) fills | Single-layer: it judges each `tools/call` **in isolation**. It has no OS event context — no file reads, no process tree, no clipboard, no connection attribution, and no cross-layer path ("untrusted content → agent → sensitive file → egress"). Tracevoryx (formerly TrustWeave)'s provenance graph consumes its own gateway decisions *plus* endpoint sensors and detects the **combination**. |

### 1.2 Others observed (inspection-level only)
- **TheLunarCompany/lunar** (TypeScript, ~504★) — agent-native MCP gateway for governance/rate limits. Governance focus, not endpoint provenance. UNVERIFIED detail.
- **chaitin/OctoBus** (~203★) — local gateway for approved enterprise APIs. UNVERIFIED detail.
- **ressl/mcp-firewall**, **provnai/McpVanguard**, **vaquarkhan/aegis-mcp-gateway** — policy enforcement/detection gateways; none advertise OS-sensor correlation. UNVERIFIED detail.
- **adithyan-ak/AgentHound** (~450★, Go) — *offensive* attack-path analysis for agent infra using graph techniques (BloodHound-style). Conceptual cousin; opposite direction (attacker recon vs. local defense). UNVERIFIED detail.
- **mcp-scan family** (invariantlabs-ai and many forks) — static scanners for tool poisoning/prompt injection in server configs; no runtime enforcement, no provenance.

## 2. Clipboard / privacy
- **kalix127/secret-stripper** (Rust, ~30★) — on-demand clipboard secret stripping.
- **BinyamMamo/clipshield** (Python) — local clipboard secret removal.
- **ARMeeru/clipveil** (macOS) — paste-time redaction hotkey.
- **beforewire/beforepaste** — "local-first paste protection for AI workflows".
- Common shape: standalone, single-layer; none tie clipboard content to agent sessions or downstream exfiltration evidence. (User-reported "ClipRedact": UNVERIFIED — no exact-match repository found in this search.)
- Tracevoryx (formerly TrustWeave) reuses the *concept* (deterministic detectors, post-hoc Windows clipboard) but links clipboard detections into the same graph as agent activity.

## 3. Ephemeral transfer
- User-reported "Shred" and "Vapor": **UNVERIFIED** — not inspected in this pass.
- Category is crowded; Tracevoryx (formerly TrustWeave) deliberately treats secure handoff as a **later, minimal module** and makes no erasure guarantees (see LIMITATIONS.md).

## 4. Endpoint provenance / taint tracking (academic & prior art)
- Host-level provenance systems exist in research (BackTracker, ProTracer, MORSE, Rain/Anteater lineage — cited from background knowledge, NOT re-fetched here). They are kernel-instrumented, heavyweight, and not AI-agent aware.
- GitHub search "agent taint tracking provenance exfiltration" → **0 repositories** (weak signal; phrase-specific).
- Tracevoryx (formerly TrustWeave)'s position: **application-level, AI-aware provenance** — edges come from the agent gateway, privacy engine, process/connection sampling, and imported traffic — with honest confidence labels, not a kernel audit subsystem.

## 5. What Tracevoryx (formerly TrustWeave) reuses legally
- Ideas and formats (JSON-RPC 2.0, MCP conventions, OpenAPI 3.x, classic PCAP format, HMAC/hash-chain audit patterns, SAS pairing concepts).
- Standard libraries only (cryptography, psutil, FastAPI, pydantic).
- **No code** from the projects above. mcp-agent-security-gateway is now proprietary; clipboard tools inspected for concepts only.

## 6. Proposed differentiation (the one bet)
**Cross-layer provenance with enforcement.** Existing tools answer "is this one call/content/clipboard bad?" Tracevoryx (formerly TrustWeave) answers "**how did untrusted input flow toward sensitive data and an exit, and should this next action be allowed?**" — one graph across agent calls, files, processes, clipboard, and network, with trust labels, taint propagation, evidence-backed findings, and a policy engine that can REQUIRE_APPROVAL when the graph shows a risky path.

## 7. Claims that cannot yet be verified
- That no existing product combines MCP gating with endpoint provenance (searches are finite; commercial products may exist unpublished).
- Any detection effectiveness numbers until Tracevoryx (formerly TrustWeave)'s own benchmarks run (see BENCHMARKS.md).
- "Airlock", "ClipRedact", "Shred", "Vapor" details as described by the requester (unverified in this pass).
