# Test Results — Tracevoryx 0.3.0 (GitHub baseline pass, 2026-10-26)

All results below were executed **fresh during this final baseline
verification pass** on Windows, Python 3.11.9, in `E:\Tracevoryx`, inside
clean virtual environments created for this pass
(`pip install -e ".[dev]"` from project metadata). Exit codes recorded.
Nothing is copied from historical runs.

## Test-environment findings (this pass)

- **pytest-timeout is a declared dev dependency** (`pytest-timeout>=2.3`
  in `[project.optional-dependencies].dev`) and the
  `[tool.pytest.ini_options] timeout = 120` option is **recognized** when
  the `dev` extra is installed (verified: run passed with
  `-W error::pytest.PytestConfigWarning`). The "unknown config option"
  warning seen in an external review happened because that environment
  ran pytest **without** the dev extra installed — installing
  `.[dev]` is the documented setup and the fix.
- **Timeout enforcement verified on Windows**: a deliberately hanging
  test (60 s sleep) was killed after 3 s with `--timeout=3` (thread
  method auto-selected). A hung test fails loudly instead of stalling
  the suite.
- **Explicit per-suite timeout budgets added** (with rationale comments):
  `test_win_eventlog.py` 240 s (PowerShell subprocess probes),
  `test_live_scenarios.py` 180 s (real app + SQLite + TestClient),
  `test_lifecycle.py` 180 s (background probes/shutdown sleeps),
  `test_perf.py` 300 s (CI runners can be several times slower).
  Everything else keeps the global 120 s default.
- **Hang audit:** no unbounded waits in tested paths. All background
  threads are daemonized with bounded `join(timeout)`; interactive
  `input()` prompts are stdin-mocked in tests; the SSE `while True`
  generator is bounded by client disconnect. No test waits on an
  external service.
- **Defect found and fixed during this pass:** `Store.append_event`
  checked the closed flag *before* acquiring the store lock; a racing
  `close()` could interleave and surface as a bare
  `sqlite3.ProgrammingError` in a background writer (observed as a
  `PytestUnhandledThreadExceptionWarning` in
  `test_closed_while_write_pending`). Fixed by re-checking under the
  lock; the regression now asserts the racing writer never escapes with
  a bare ProgrammingError. Full suite now reports **1 warning** (the
  upstream starlette TestClient deprecation) — the thread-exception
  warning is gone.

## Command log (actual)

| # | Command | Result | Exit |
|---|---|---|---|
| 1 | Clean venv + `pip install -e ".[dev]"` | installed from project metadata (pytest 9.1.1, pytest-timeout 2.4.0) | 0 |
| 2 | `python -c "import tracevoryx, trustweave"` | both import OK (canonical + shims) | 0 |
| 3 | CLI smoke: `tracevoryx --help`, `tracevoryx demo` | help OK; end-to-end demo (attack chain detected, shadow decision, provenance graph) | 0 |
| 4 | CLI smoke: `tracevoryx serve` (background) | boots on 127.0.0.1:8640; `/api/v1/status` correctly refuses unauthenticated access (HTTP 401); stopped cleanly; throwaway store deleted | 0 |
| 5 | `python -m pytest tests/test_lifecycle.py -q` (focused, after race fix) | 7 passed | 0 |
| 6 | `python -m pytest tests/ -q` (FULL suite incl. perf, final code state) | **244 passed**, 0 failed, 0 skipped, 0 timed out (75.7 s; also 89.6 s and 121.0 s in repeat runs) | 0 |
| 7 | Slowest single test (durations profile) | 6.27 s (`test_sustained_ingest_volume`); next 4.61/3.10/2.06/2.03 s | 0 |
| 8 | `python -m pytest tests/test_release_hygiene.py tests/test_production_hygiene.py tests/test_encoding_hygiene.py -q` | 37 passed | 0 |
| 9 | `python -m ruff check tracevoryx trustweave tests scripts benchmarks` | **All checks passed** | 0 |
| 10 | `python -m compileall tracevoryx trustweave tests scripts -q` | no errors | 0 |
| 11 | `python -m bandit -r tracevoryx -ll --exclude tracevoryx/dashboard` | 0 high / 0 medium (2 triaged B608 false positives annotated `# nosec` with rationale: placeholder-list-only SQL, values bound) | 0 |
| 12 | `pip-audit --skip-editable` (verification env, setuptools upgraded first) | no known vulnerabilities | 0 |
| 13 | `python scripts/live_validate.py` | **31/31 PASS** | 0 |
| 14 | `python scripts/package_release.py` (regenerated at final code state) | staged 142 files; 126 cache exclusions by deny rules; secret scan clean; **ZIP re-extraction verification PASS**; `release-gate.json` gate=PASS | 0 |
| 15 | ZIP independent inspection (fresh decode of member names + SHA-256) | 142 members; 0 prohibited paths (`.git/`, `__pycache__`, `.pyc`, `.db`, `.log`, `.venv`, egg-info, `data/`); manifest parity 142/142 | 0 |
| 16 | `python -m build` | wheel (79 entries, dashboard assets included) + sdist (107 files, no pyc/git contamination) | 0 |
| 17 | Clean-install test: fresh venv → wheel → imports, dashboard asset, `tracevoryx demo` | all OK | 0 |
| 18 | Secret scan (tracked files, CI-identical patterns + allowlist) | 0 hits | 0 |
| 19 | Git history secret scan (1 commit, 140 blobs, every blob) | 0 hits; only the documented synthetic DLP fixture (allowlisted) | 0 |
| 20 | PowerShell parse check (`start/stop/install/validate_win_eventlog.ps1`) | 0 parse errors | 0 |
| 21 | Encoding scans (repo-wide) | 0 mojibake, 0 U+FFFD, 0 undecodable files, 0 BOM in py/md | 0 |

## Coverage of the 244 tests by layer

| Layer | Files | Notes |
|---|---|---|
| Unit (schemas, policy, approvals, store, detectors, handoff, pcap, checkpoints) | 12 files | includes adversarial handoff + checkpoint suites |
| Integration (REST, MCP over HTTP, roles, SSE, lifecycle) | 6 files | TestClient against real app |
| Adversarial/security regression | `test_security_adversarial.py` (33) + release/production hygiene (29 + 5) | every register finding maps to ≥1 test |
| Encoding hygiene | `test_encoding_hygiene.py` (3) | mojibake round-trip, BOM, PS1 ASCII guard |
| Performance | `test_perf.py` (3) | run separately and inside the full run |
| Live acceptance | `scripts/live_validate.py` | 31 checks over real HTTP paths |

## Full-suite totals (final)

- **244 passed · 0 failed · 0 skipped · 0 timed out** (three consecutive
  full runs: 89.6 s, 121.0 s, 75.7 s — all well inside a reasonable
  window).
- Warnings: 1 (upstream starlette TestClient deprecation; filtered by
  policy in `pyproject.toml` where applicable, otherwise informational).
- Fast CI subset (`--deselect tests/test_perf.py`): 241 tests.

## Observed flake (historical, prior pass)

One earlier full-suite run (during the previous pass, under heavy
parallel tooling load) failed the timing-sensitive
`test_sustained_ingest_volume` ingest bound (15 ms/event). It passed in
isolation and in every subsequent full run including all three runs in
this pass. CI runs perf as a separate step; treat persistent failures
under sustained load as environment contention, not a code defect.

## Incident note (honest disclosure)

During the `tracevoryx serve` smoke test (row 4), the process's one-time
bootstrap admin token was written to a temp redirect file; an inspection
command intended to filter it out failed to do so and echoed the line to
the console. Remediation was immediate and complete: the throwaway
`data/` store backing that token was deleted (credential inert), the
temp file containing the token was deleted, and the serve process was
stopped. The token never authenticated anything and exists nowhere on
disk now. No repository, history, or artifact content was affected —
verified by the secret scans (rows 18-19) which post-date the incident.

## Blocked / not run

- **GitHub CI execution:** workflow configured (windows-latest +
  ubuntu-latest × Python 3.11/3.12) but no remote/credentials exist
  here — **unverified until the first CI run**. Note the workflow
  triggers on `main`; the local branch is `master` (push to `main` or
  adjust the trigger — see `docs/GITHUB_PUBLICATION_CHECKLIST.md`).
- **Linux/macOS runtime tests:** not executed here (Windows-only
  machine).
- **ZAP/Nuclei dynamic scanning:** not run (no scanner authorization);
  covered instead by the adversarial suite + live validation.
- **Sysmon provider testing:** requires Sysmon installed on the owner
  machine; probe logic covered via honest `provider_missing` states.
