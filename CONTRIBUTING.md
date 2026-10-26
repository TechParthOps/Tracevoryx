# Contributing to Tracevoryx

Thank you for helping build a defensible, honest security tool.

## Ground rules

1. **Security claims must be testable.** If a feature claims a guarantee
   ("denied calls never execute"), there must be a regression test proving
   it. See `tests/test_security_adversarial.py` for the expected style.
2. **Fail closed.** New decision paths must fail closed where security is
   involved. Errors are audited, never silently converted to allow.
3. **Honesty over marketing.** Boundaries, blind spots, and limitations are
   documented next to the feature that has them (see
   `docs/KNOWN_LIMITATIONS.md`, `docs/CONTROL_COVERAGE.md`).
4. **No secrets, ever.** Never commit tokens, keys, databases, logs, or
   runtime state. `tests/test_release_hygiene.py` and CI scan for this.
   Synthetic fixture values must be obviously fake or documented
   (e.g. AWS's example key).

## Development workflow

```powershell
git clone <repo> && cd tracevoryx
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\python -m pytest tests/ -q          # full suite
.venv\Scripts\python -m ruff check tracevoryx tests scripts
.venv\Scripts\python -m bandit -r tracevoryx -ll --exclude tracevoryx/dashboard
.venv\Scripts\python scripts\live_validate.py     # 31-check live acceptance
.venv\Scripts\python scripts\package_release.py   # staging + secret scan
```

Linux/macOS: use `python3 -m venv .venv` and `.venv/bin/` paths instead.

## Test expectations

- Unit tests per module, integration tests over the FastAPI TestClient,
  adversarial tests for every security invariant, and the live validation
  script as the acceptance gate.
- New security-relevant behavior requires a test that FAILS without your
  fix. Include the reproducer in the PR description.
- Performance-sensitive paths: add numbers to `benchmarks/` rather than
  guessing.

## Code style

- `ruff check` must pass (line length 100; late imports allowed where they
  break import cycles).
- Type hints on public functions; docstrings state the security contract.
- SQLite is single-writer: all writes go through `Store` methods that hold
  the write lock; cross-thread single-use semantics must be atomic (see
  `Store.kv_consume_if_unused` for the CAS pattern).

## Submitting

1. Fork + branch (`security/<topic>` or `feat/<topic>`).
2. Tests pass locally, lint clean, no new bandit medium findings without a
   documented triage note.
3. PR description: what changed, which threat it addresses, test evidence.
4. Security-relevant PRs require review from a maintainer before merge.
