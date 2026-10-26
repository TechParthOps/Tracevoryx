# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | yes       |
| < 0.3   | no (rename + hardening release; upgrade) |

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Report privately to the repository owner via GitHub Security Advisories
("Report a vulnerability" on the Security tab). Include:

- affected version/commit,
- a minimal reproduction (request, tool call, or config),
- observed vs expected behavior,
- your assessment of impact and preconditions.

You will receive an acknowledgment within 7 days and a status update within
30 days. Please keep details private until a fix is released.

## Scope and honest boundaries

In scope: this repository's code — the REST API, the MCP/JSON-RPC gateway,
built-in executors, audit integrity, privacy guard, dashboard assets, CLI,
and packaging.

Explicitly in scope as design boundaries (not vulnerabilities when
documented): the gateway enforces only calls routed through it; delegated
tool reports are caller-reported; a local attacker who controls both the
database and `data/audit_key` defeats signed checkpoints; deterministic DLP
is evadable; clipboard protection is post-hoc. See
`docs/SECURITY_THREAT_MODEL.md` and `docs/KNOWN_LIMITATIONS.md`.

Out of scope: attacks against systems you do not own or operate, social
engineering, physical attacks, and denial of service against any host other
than your own local instance.

## Disclosure process

1. Private report received and acknowledged.
2. Triage against the threat model; severity assigned (P0–P3 per
   docs/REMEDIATION_ROADMAP.md).
3. Fix developed with a regression test; retest evidence recorded in
   docs/VULNERABILITY_REGISTER.md.
4. Coordinated release; credit unless you prefer anonymity.
