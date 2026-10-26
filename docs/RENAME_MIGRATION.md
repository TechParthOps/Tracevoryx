# Rename: TrustWeave → Tracevoryx (0.3.0)

## Availability verification (performed 2026-10-24)

| Name | PyPI | GitHub | Decision |
|---|---|---|---|
| **tracevoryx** | available (no project) | 0 repository results | **CHOSEN** |
| traceloom | TAKEN — `traceloom` 0.1.4, an unrelated C++/vLLM timeline analyzer | (n/a) | rejected |
| trustweave | TAKEN — `trustweave` 0.3.0, an unrelated config-review tool | exists | rejected (also impossible to publish) |

Informal trademark/domain checks were not conclusive at engagement time;
the owner should complete a formal trademark search and domain
registration before wide publication. No formal trademark conflict was
found in code/registry searches.

## What changed

- Python package: `tracevoryx` (all 35 modules). Distribution name:
  `tracevoryx` 0.3.0. Primary CLI: `tracevoryx`.
- Product name in README, docs, dashboard branding, server info strings,
  user-agent (`Tracevoryx/0.3`), MCP `serverInfo.name`
  (`tracevoryx-gateway`), OpenAPI extension key (`x-tracevoryx`).

## Compatibility (deliberately preserved — no careless replace)

- `import trustweave` and `import trustweave.<anything>` still work via
  generated shim modules that mirror `tracevoryx`.
- The `trustweave` CLI entry point still works (deprecated alias; removal
  not before 1.0).
- **Data compatibility is untouched:** the `data/` directory, SQLite
  schema, `tw_*` kv keys, `tw_` token prefix, `[TW:REDACT:*]` placeholders,
  and the handoff INFO constant domain-separation scheme carry over with
  NO migration. Existing databases, tokens, policies, and audit history
  remain valid.
- Agent process-name detection matches BOTH `tracevoryx` and `trustweave`.

## Migration test

Verified in this workspace: fresh `pip install -e .`, both import paths,
shim deep-imports (`from trustweave.core.store import Store` resolves to
`tracevoryx.core.store`), and the full 238-test suite against the renamed
package. A copy of pre-rename runtime state (the owner's `data/` DBs)
remains readable — verified by direct SQLite inspection during the secret
cleanup, no schema change.

## Deprecation policy

`trustweave` shims and CLI alias are documented as deprecated; removal not
earlier than 1.0. A DeprecationWarning is NOT emitted from the shims to
avoid breaking unattended integrations; the README and CHANGELOG carry the
notice instead.
