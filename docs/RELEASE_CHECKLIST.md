# Release Checklist — Tracevoryx 0.3.0

## Pre-flight (all must be green)

1. `python -m pytest tests/ -q` - **241 tests, 0 failures** (verified; includes the 3 perf tests).
2. `python -m ruff check tracevoryx trustweave tests scripts` — clean.
3. `python -m bandit -r tracevoryx -ll --exclude tracevoryx/dashboard` — no
   medium/high beyond documented triage (B608 ×2 TRIAGED-FP).
4. `pip-audit` (frozen env, exclude editables) — no known vulnerabilities.
5. `python scripts/live_validate.py` — 31/31.
6. `python -m pytest tests/test_release_hygiene.py -q` — 29/29.
7. `git status` clean; working tree committed on
   `security/production-hardening` (or merged to `main`).

## Packaging

8. `python scripts/package_release.py`:
   - staging allowlist applied; deny-rule exclusions printed;
   - secret scan clean (allowlisted synthetic fixtures only);
   - `dist/MANIFEST.sha256` written; `dist/dependency-inventory.json` written;
   - `dist/tracevoryx-0.3.0.zip` produced.
9. Inspect the zip listing: no `data/`, `.venv`, logs, `*.db*`, tokens,
   keys, caches, egg-info.

## Publication (owner actions — never automated)

10. Create the GitHub repository (name: `tracevoryx` — verified available;
    see docs/RENAME_MIGRATION.md for the decision record).
11. Push:
    ```
    git remote add origin <YOUR-ORIGIN-URL>
    git push -u origin security/production-hardening
    git checkout -b main && git push -u origin main
    ```
12. Tag after CI passes on `main`:
    ```
    git tag -a v0.3.0 -m "Tracevoryx 0.3.0 - security hardening release"
    git push origin v0.3.0
    ```
13. GitHub Release: paste CHANGELOG 0.3.0 section; attach
    `tracevoryx-0.3.0.zip` + `MANIFEST.sha256` +
    `dependency-inventory.json`.
14. PyPI (optional): `python -m build && twine upload dist/*` — the name
    is available; enable PyPI trusted publishing / 2FA first. Build in a
    clean env; re-run the hygiene scanner against the wheel.
15. Enable branch protection + secret scanning + dependabot on the repo.

## Post-release

16. Update docs/PRODUCTION_READINESS.md gate table with release URLs.
17. File follow-up issues for P2 roadmap items.
