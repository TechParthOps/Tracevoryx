# Baseline Release Audit — Tracevoryx 0.3.0 (GitHub publication gate)

Audit pass 1: 2026-10-25. Audit pass 2 (final GitHub baseline):
2026-10-26 — generated-file cleanup, test-environment hardening, one
additional application defect found and fixed (store close-race), full
re-verification, regenerated release artifacts. Both passes were
performed on the owner's workspace `E:\Tracevoryx`, branch `master`,
single baseline commit `138b566`, no remote configured. All evidence in
this document was produced by commands executed during these passes
(full log with exit codes: `docs/TEST_RESULTS.md`, which reflects pass 2).
No results were copied from earlier runs.

## Pass-2 summary (deltas since pass 1)

- **Generated-file contamination removed from the source tree** (all
  regenerable, none tracked): 19 `__pycache__/` trees, `.pytest_cache/`,
  `.ruff_cache/`, `tracevoryx.egg-info/`, `dist/` (regenerated fresh at
  the end of the pass). `.gitignore` extended for coverage/Tox output.
  Verified via `git status --short --ignored` (no `!!` entries).
- **Test environment verified:** pytest-timeout 2.4.0 installed with the
  dev extra; `timeout = 120` ini option recognized; timeout enforcement
  proven on Windows (60 s hang killed at 3 s); hang audit clean
  (daemonized threads, bounded joins, stdin-mocked prompts, SSE loop
  bounded by client disconnect). The external review's "unknown config
  option" warning was an environment artifact — running without the
  `dev` extra.
- **Explicit timeout budgets added** with rationale to the four
  environment-sensitive suites (winlog 240 s, live scenarios 180 s,
  lifecycle 180 s, perf 300 s); pyproject timeout config documented.
- **Application defect fixed (store close-race):** `append_event`
  checked the closed flag before acquiring the store lock; a racing
  `close()` could surface as a bare `sqlite3.ProgrammingError` in a
  background writer (observed live as a PytestUnhandledThreadException
  warning in `test_closed_while_write_pending`). Fixed by re-checking
  under the lock; regression strengthened to assert the contract
  ("never a bare ProgrammingError"). Suite warnings dropped from 2 to 1
  (remaining: upstream starlette deprecation).
- **`tracevoryx serve` smoke-tested:** boots on 127.0.0.1:8640,
  correctly refuses unauthenticated API access (401), stops cleanly.
  Incident note: a one-time bootstrap token from this smoke test was
  briefly echoed by an inspection command; its throwaway store and the
  temp file were destroyed immediately (credential inert); post-incident
  secret scans are clean. Details: `docs/TEST_RESULTS.md` incident note.
- **Full re-verification at final code state:** 244/244, ruff clean,
  bandit 0/0, pip-audit clean, live 31/31, hygiene 37/37, secret scans
  (tracked + history) 0 hits, release gate PASS, artifacts regenerated
  and independently verified, wheel clean-install OK.

Backup: branch `backup/pre-github-baseline` points at the pre-correction
commit; the working tree was never reset or force-discarded.

---

## 1. Canonical source and final folder structure

Canonical package: **`tracevoryx/`** (35 modules + dashboard assets).
**`trustweave/`** is retained as a compatibility layer: every one of its
35 modules is a verified pure-delegation shim
(`importlib.import_module("tracevoryx...")` + `globals().update(...)`);
no divergent second implementation exists. Two CLI entry points
(`tracevoryx`, deprecated alias `trustweave`) resolve to
`tracevoryx.cli:main`.

```
E:\Tracevoryx\                (140 tracked files; +1 new test = 141 to commit)
├── tracevoryx/               canonical package
├── trustweave/               compatibility shims (pure delegation, verified)
├── tests/                    23 test files / 244 tests
├── docs/                     21 documents (incl. this audit)
├── reports/                  security-findings.json + pentest/final reports
├── scripts/                  live_validate.py, package_release.py, ops (.ps1)
├── benchmarks/  fixtures/    synthetic-only fixtures
├── .github/workflows/ci.yml  lint, matrix tests, bandit, pip-audit, secret scan
├── README.md LICENSE SECURITY.md CONTRIBUTING.md CHANGELOG.md
└── pyproject.toml  .env.example  .gitignore
```

Not present in git or artifacts: `.git/`, `data/`, `.venv*/`, caches,
`dist/`, logs, tokens, keys. `.env.example` contains placeholders only
(log level, host/port, rate limits, body cap) — no credentials; kept.

## 2. Disposition of modified files

Baseline state: working tree was clean (all prior work already committed
into `138b566`); this pass produced 112 modified tracked files + 1 new
file, all classified:

**Intentional — functional corrections (pass 1 + pass 2, 15 files):**

| File | Change | Classification |
|---|---|---|
| `tracevoryx/core/store.py` | **close-race fix (pass 2):** `append_event` re-checks the closed flag under the store lock so a racing `close()` surfaces as `StoreClosedError`, never a bare `sqlite3.ProgrammingError` | required |
| `tracevoryx/cli.py` | CLI description said "(formerly tracevoryx)" → "(formerly TrustWeave)"; mojibake in help strings repaired | required |
| `tracevoryx/provenance/graph.py` | 2 bandit B608 findings verified as placeholder-only parameterized SQL; annotated `# nosec B608` with rationale (CI `-ll` gate otherwise fails) | required |
| `scripts/package_release.py` | symlink rejection in `stage()` (fail-closed hardening); dead `man_lines` assignment removed | required |
| `tests/test_lifecycle.py` | stale legacy logger name in capture setup fixed (§4); racing-writer regression strengthened to assert "never a bare ProgrammingError" (pass 2); module timeout budget 180 s | required |
| `tests/test_encoding_hygiene.py` | NEW: 3 regression tests (mojibake, BOM, PS1 ASCII) | required |
| `tests/test_win_eventlog.py`, `tests/test_live_scenarios.py`, `tests/test_perf.py` | NEW: explicit `pytest.mark.timeout` budgets with rationale (240/180/300 s) | required |
| `scripts/start.ps1`, `scripts/stop.ps1` | bare `—` in BOM-less comments → ASCII `-` (PS 5.1 reads BOM-less files as ANSI; would misrender at execution) | required |
| `benchmarks/run_bench.py` | 2 unused imports removed (ruff F401) | required |
| `pyproject.toml` | timeout config documented (requires pytest-timeout from the `dev` extra) | required |
| `.gitignore` | coverage/Tox/wheel-metadata output added | required |
| `README.md` | full-suite count corrected to 244 | required |
| `CHANGELOG.md` | "Repository baseline cleanup" section documenting the pre-publication work | required |
| `docs/TEST_RESULTS.md`, `docs/GITHUB_PUBLICATION_CHECKLIST.md` | rewritten/new with the pass-2 evidence and the manual publication sequence | required |
| `reports/FINAL_RELEASE_AUDIT.md`, `reports/security-findings.json` | stale workspace facts (`E:\TrustWeave`, 3 commits, 138 files, 241/238 counts) updated to verified reality | required |

**Intentional — encoding hygiene (bulk):** 107 files stripped of UTF-8
BOMs; 37 files repaired for mojibake (see §3). All other modified files
(~60 `.py`, 11 `.md`) are encoding-only changes with zero functional
delta, verified by ruff, `compileall`, and the full test suite.

**Accidental content removed:** none found — no generated or duplicated
files present; `__pycache__`/`dist`/`egg-info` are gitignored and excluded
from artifacts by staging deny rules.

**Unresolved:** none.

## 3. Encoding fixes (mojibake + BOM)

Detection: repo-wide scan of all tracked UTF-8 files using a verified
round-trip — a window is mojibake only if
`window.encode("cp1252").decode("utf-8")` succeeds and differs, so
legitimate non-ASCII (`— → … § ★ ✓ ≠ ─ × · ▶`) cannot be damaged.
Blind global replacement was not used.

- **288 mojibake occurrences in 37 files repaired.** Each corrupted
  sequence was the CP1252 misdecoding of the intended glyph's own UTF-8
  bytes. Intended glyphs restored: em dash, en dash, ellipsis, section
  sign, multiplication sign, middle dot, not-equal sign, rightwards
  arrow (→), star (★), check mark (✓), and the box-drawing set used by
  the `docs/ARCHITECTURE.md` diagrams. Example mapping: an em dash
  appearing as `\u00e2\u20ac\u201d` in source was restored to `—`.
  Affected: README.md, 10 docs/*.md, 10 tests/*.py, 15
  tracevoryx/**/*.py (incl. docstrings, comments, CLI help strings).
- **107 files:** UTF-8 BOM stripped (Windows-editor artifact; stray BOM
  can leak into string comparisons and rendered Markdown).
- **2 `.ps1` scripts:** non-ASCII in BOM-less comments converted to ASCII
  (PS 5.1 ANSI fallback).
- Post-fix: 0 mojibake, 0 U+FFFD, 0 undecodable files; README inspected
  in rendered form (headings, tables, code blocks intact).
- Recurrence guard: `tests/test_encoding_hygiene.py` (3 tests, passing).

## 4. Lifecycle test failure — root cause and evidence

Failing test at baseline:
`tests/test_lifecycle.py::TestWinlogProbeLifecycle::test_worker_store_error_observable`.

**Trace:** `WinEventLogCollector._beat()` (collector/win_eventlog.py:191)
catches the closed-store exception and calls
`log_error(_log(), "sensor_beat_failed", ...)` where `_log()` returns
`logging.getLogger("tracevoryx.collector.winlog")`. `setup_logging()`
(core/logging_util.py:44-46) configures the `"tracevoryx"` logger with
`propagate=False` (by design: JSON-lines to file + stdout = the intended
diagnostic channel). pytest's `caplog` listens at the root logger, so the
record never reaches it unless propagation is temporarily re-enabled.
The test did exactly that — but on `logging.getLogger("trustweave")`,
the pre-rename logger name, which is not in the `"tracevoryx.*"` chain.
The structured error visible on stdout confirmed production logging was
working; the test's capture assumption was stale after the 0.3.0 rename.

**Verdict:** defect in the test (stale logger name), not in production
logging, propagation policy, or the collector. No exception is
suppressed, the assertion is unchanged, and the lifecycle requirement is
intact. Fix: re-enable propagation on
`logging.getLogger("tracevoryx")` in the test with a comment explaining
the rename history. Production code unchanged for this defect.

**Regression evidence:** focused file passes (`6 passed`); full suite
passes (`244 passed`); shutdown-safety tests
(`test_stop_during_pending_probe`, `test_store_close_while_probe_inflight`,
`test_no_probe_thread_leak_between_tests`) all pass. Log content carries
only sensor names and `repr(exc)` — no secrets (redaction filter also
active in `logging_util`).

## 5. Actual test results and exit codes

Environment: Windows (win32), Python 3.11.9, clean venvs created for
this pass; project installed from project metadata
(`pip install -e ".[dev]"` → exit 0). Highlights (full table in
`docs/TEST_RESULTS.md`):

| Check | Result | Exit |
|---|---|---|
| Import checks (`tracevoryx`, `trustweave`) | both OK | 0 |
| CLI smoke (`--help`, `demo`) | attack chain detected; shadow decision + provenance correct | 0 |
| Focused lifecycle + encoding tests | 6 + 3 passed | 0 |
| **Full suite** (`pytest tests/ -q`, incl. perf) | **244 passed**, 0 failed, 0 skipped | 0 |
| Perf separately | 3 passed | 0 |
| Fast CI subset (perf deselected) | 241 passed | 0 |
| Release + production hygiene | 34 passed | 0 |
| Ruff (all dirs) | all checks passed | 0 |
| `compileall` | clean | 0 |
| Bandit (`-ll`, excl. dashboard) | 0 high / 0 medium after triage | 0 |
| pip-audit (verification env) | no known vulnerabilities | 0 |
| Live acceptance (`live_validate.py`) | **31/31 PASS** | 0 |
| History secret scan (1 commit, 140 blobs) | no secrets; only allowlisted synthetic DLP fixture | 0 |
| ZIP independent inspection | 141 members, 0 prohibited | 0 |

Flake note: one mid-pass full-suite run failed
`test_perf.py::TestThroughput::test_sustained_ingest_volume` while
parallel tooling loaded the machine (402 s wall vs ~194 s normal); it
passed in isolation and in the final quiet run. Documented honestly in
`docs/TEST_RESULTS.md`.

## 6. Security and secret-scan results

- **Tracked-file secret scan** (CI-identical: `SECRET_PATTERNS` +
  `ALLOWLISTED_SECRET_VALUES` over `git ls-files`): **0 hits**. The only
  pattern-matching values are the documented synthetic DLP fixture
  (`ghp_Qk7...` deterministic fake, allowlisted) and test/example keys.
- **History scan:** every blob of the single commit scanned — **no
  secrets ever committed**. No rotation required for git content; the
  0.2.0 archive incident tokens were already revoked/rotated per
  `docs/SECRET_CLEANUP.md` (owner actions there remain outstanding).
- **Bandit:** the two medium B608 findings in `provenance/graph.py`
  were verified line-by-line: the f-string interpolates only a generated
  `"?,..."` placeholder list; all values are bound parameters. Annotated
  `# nosec B608` with rationale; bandit now exits 0.
- **pip-audit:** clean. The 9 advisories found were in the verification
  venv's bundled `setuptools 65.5.0` (environment tooling, not a declared
  dependency; `pyproject.toml` requires setuptools>=68 at build time).
- **Runtime hygiene:** `data/`, logs, tokens, keys absent from the tree;
  demo/live-validate runtime state removed after each run.

## 7. Packaging and release-archive verification

`scripts/package_release.py` (hardened this pass with symlink
rejection): explicit `APPROVED_DIRS`/`APPROVED_FILES` allowlist; deny
rules for DBs/WAL/SHM, token/key files, logs, pyc, venvs, caches,
`.git`; secret-pattern scan with documented allowlist; fail-closed exit
codes.

Run: staged 141 files; 126 cache exclusions; secret scan clean;
`MANIFEST.sha256` written; **ZIP re-extracted into a fresh temp dir and
independently verified** (no traversal-unsafe names, 0 prohibited paths,
0 secret hits, SHA-256 parity 141/141) → `release-gate.json` gate=PASS,
exit 0.

Artifacts built at final code state: `tracevoryx-0.3.0.zip` (141 files),
wheel (79 entries, dashboard assets included), sdist (107 files, no
prohibited paths). Clean installs verified twice: staged tree into a
fresh venv (imports + CLI, exit 0) and wheel into another fresh venv
(imports, dashboard asset resolves, `tracevoryx demo`, exit 0).

## 8. Remaining limitations and unverified platform checks

Honest, documented — not silently dropped:

- **GitHub CI unverified until first run.** The workflow is configured
  (win/ubuntu × 3.11/3.12) but no remote/credentials exist here. Note:
  the workflow triggers on `main`; local branch is `master` — push to
  `main` or adjust the trigger before the first run.
- **Linux/macOS:** not executed on this Windows-only machine.
- **Sysmon provider behavior:** requires Sysmon installed on the owner
  machine; probe logic covered via honest `provider_missing` states.
- **ZAP/Nuclei dynamic scans:** not run (no authorization).
- **Design limitations** unchanged and documented:
  `docs/KNOWN_LIMITATIONS.md`, `docs/CONTROL_COVERAGE.md` (gateway-only
  enforcement, delegated results are *reported* not *observed*,
  DB+key-holder defeats audit chain, deterministic-only DLP, single-host
  SQLite, no native TLS).

## 9. Decision

**READY for GitHub source publication** (public or private, owner's
choice), on the strength of: clean history and working tree, clean
secret/history scans, 244/244 tests, lint/type/compile clean, live
31/31, verified release gate, clean installs, and honest documentation.
This is a statement about the **source repository**, not about
production deployment.

**Controlled release (sharing with known parties / limited distribution):
READY**, conditioned on the owner completing the outstanding
`docs/SECRET_CLEANUP.md` actions (bootstrap-token rotation) and the
first green CI run.

**Internet-facing production: NOT READY** (by design at 0.3.0). Missing:
TLS termination + deployment isolation, external key management,
multi-node scalability, hardened ops monitoring. Gate:
`docs/PRODUCTION_READINESS.md`.

## 10. Exact next steps for owner approval (not executed)

The complete manual sequence — review, staged-commit, browser repo
creation, remote wiring (with YOUR actual URL), branch rename to `main`,
push, and post-push verification — is in
**`docs/GITHUB_PUBLICATION_CHECKLIST.md`** (phases A–F, with
safe-now vs. needs-your-URL steps clearly separated).

Summary of the owner-only decisions:

1. Review this audit, `docs/TEST_RESULTS.md`, and the diff
   (`git diff` / `git diff --stat`).
2. Run Phase B of the checklist: stage + commit the baseline.
3. Create the repository **manually in the browser** (do not
   initialize it with README/license — the repo already has them).
4. Add your actual repository URL as `origin` (checklist Phase D),
   rename `master` → `main`, push.
5. Verify the rendered repository and the first CI run (Phase E).
6. Optional: attach `dist/tracevoryx-0.3.0.zip` + `MANIFEST.sha256`
   (gitignored, local-only) to a GitHub Release (Phase F).

Do not push until the owner has reviewed this audit and the diff.
The preparation tooling did not commit, push, create remotes, or
publish anything.
