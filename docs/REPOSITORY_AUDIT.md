# Repository Audit — Tracevoryx 0.3.0

Audit date: 2026-10-25. Method: full inspection of the working tree, Git
history, package metadata, and installed entry points — before any edits
in this phase.

## Canonical determination (verified from code, not names)

| Question | Verified answer | Evidence |
|---|---|---|
| Authoritative package | `tracevoryx/` (35 modules) | all implementation logic lives here; entry points resolve into it |
| Compatibility layer | `trustweave/` (35 generated shim modules) | each shim is a deterministic mirror: `importlib.import_module("tracevoryx.<m>")` + `globals().update` |
| Primary CLI | `tracevoryx = tracevoryx.cli:main` | installed console script |
| Legacy CLI alias | `trustweave = tracevoryx.cli:main` | same `main`; deprecated, removal not before 1.0 |
| State separation | none — both import paths resolve to ONE implementation and one state | `Store.__module__ == 'tracevoryx.core.store'` even via shim |

Import compatibility results (dev env AND clean wheel install):
`import tracevoryx` ✅ · `import trustweave` ✅ · deep shim
`from trustweave.core.store import Store` ✅ · both CLIs ✅ ·
`tracevoryx demo` (isolated temp env; real data dir untouched) ✅.

## Folder-by-folder classification

| Path | Class | Action |
|---|---|---|
| `tracevoryx/` | canonical source | keep |
| `trustweave/` | generated compat shims | keep (documented, tested) |
| `tests/` | test suite (27 files, 241 tests) | keep |
| `docs/` | documentation (20 files) | keep; refreshed 0.3.0 |
| `reports/` | sanitized security reports | keep (no secrets) |
| `scripts/` | operational scripts | keep |
| `benchmarks/`, `fixtures/` | synthetic evidence | keep |
| `.github/workflows/ci.yml` | CI (least-privilege, security gates) | keep |
| root docs (README/SECURITY/CONTRIBUTING/CHANGELOG/LICENSE) | release docs | keep |
| `pyproject.toml`, `.env.example`, `.gitignore` | packaging/config | keep |
| `data/` | owner runtime state (tokens rotated 0.3.0; DBs preserved) | ignore, never publish |
| `data-bundled-backup/`, `.venv-bundled-backup/` | pre-audit local backups | ignore; owner may delete when done |
| `.venv/`, `logs/`, `dist/`, caches, egg-info | local/generated | ignore |

Stale/redundant artifacts: **none found in the tracked tree.** An earlier
`tmp_parse.py` and stale `trustweave.egg-info` were removed in 0.3.0. The
tracked tree contains exactly the 138 approved files.

## Tracked / untracked / ignored inventory

- Tracked: 138 files (`git ls-files`).
- Untracked: 0 (working tree clean; verified `git status --short`).
- Ignored: runtime material confined to `data/` (10 files),
  `data-bundled-backup/` (4), `.venv` (5158), `.venv-bundled-backup/`
  (3714), `dist/` (build output), logs and caches.

## Git history verification

- 3 commits, no remotes, branches: `master` (baseline) and
  `security/production-hardening` (work).
- Full-history secret scan over every commit tree: **no real secrets ever
  committed.** Only hit: the documented synthetic DLP fixture in
  `tests/test_privacy.py` (an obvious sequential-alphabet fake token,
  allowlisted) present in the first two commits — no rotation or history
  rewrite warranted.
- Runtime files (DBs/keys/tokens) were never tracked: `.gitignore` was in
  place before the first commit.

## Packaging verification (this phase)

- Wheel: 79 entries, **dashboard assets included** (fixed this phase —
  previously absent, see `reports/FINAL_RELEASE_AUDIT.md`), shim package
  included, 0 prohibited paths.
- sdist: 124 entries, 0 prohibited paths.
- `scripts/package_release.py`: allowlist + deny rules now internally
  consistent (`.git` dir denied; `.gitignore` allowed), produces ZIP +
  SHA-256 manifest + dependency inventory + `release-gate.json`, and
  **independently re-extracts the ZIP** to a temp dir verifying traversal
  safety, prohibited paths, secrets, and manifest parity. Gate: PASS.

## Proposed removals

None. No tracked file is stale, duplicated, or unsafe. The `trustweave/`
shims are retained deliberately (tested compatibility requirement).

## Unresolved architectural concerns

Documented, non-blocking (see docs/KNOWN_LIMITATIONS.md): single-process
rate-limit/lockout state; POSIX-only file-mode enforcement; exposure-path
query cost on very large graphs; no TLS termination in-app.
