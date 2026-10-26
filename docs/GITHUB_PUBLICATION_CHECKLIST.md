# GitHub Publication Checklist — Tracevoryx 0.3.0 (manual upload)

This is the owner's step-by-step sequence for publishing the local
baseline to GitHub **manually**. Nothing below has been executed by the
preparation tooling: no remote exists, nothing is staged, and the
baseline commit has not been created (deliberately — see step 3).

Current verified local state: branch `master` with one historical commit
(`138b566`), all baseline corrections uncommitted in the working tree,
backup branch `backup/pre-github-baseline` intact, working tree free of
generated artifacts (caches/`dist/`/egg-info are gitignored and were
removed from disk), full suite 244/244 green, release gate PASS
(`docs/TEST_RESULTS.md`, `docs/BASELINE_RELEASE_AUDIT.md`).

## Phase A — review (safe to run immediately)

```powershell
# 1. Confirm the tree is as described: source changes only, no artifacts
git status --short
git status --short --ignored          # ignored files must not appear in git status output
git diff --stat                       # ~113 paths, encoding + targeted fixes

# 2. Review the substantive (non-encoding) changes
git diff -- tracevoryx/core/store.py tracevoryx/cli.py tracevoryx/provenance/graph.py
git diff -- scripts/package_release.py tests/test_lifecycle.py tests/test_perf.py
git diff -- tests/test_win_eventlog.py tests/test_live_scenarios.py
git diff -- .gitignore pyproject.toml README.md CHANGELOG.md docs/TEST_RESULTS.md

# 3. Confirm no prohibited content anywhere (all should print nothing / "none")
git ls-files | Select-String -Pattern "\.db$|\.log$|\.key$|\.pem$|\.env$|token|__pycache__|egg-info"
git log --oneline --all               # 2 branches, 1 commit each
```

## Phase B — commit the baseline (safe; reversible, no push)

```powershell
# 4. Stage everything intended (114 paths: 112 modified + 2 new)
git add -A
git status --short                    # verify staged list matches Phase A review
git diff --cached --stat              # final staged-diff review

# 5. Commit (suggested message)
git commit -m "Baseline cleanup for publication: encoding repair, store close-race fix, test timeout budgets, packaging hardening" -m "Details: docs/BASELINE_RELEASE_AUDIT.md, CHANGELOG.md 0.3.0 baseline section."
```

## Phase C — create the repository (browser; needs your GitHub account)

6. In the browser: GitHub → **New repository**.
   - Owner/name: your choice (the project has no invented URL).
   - Visibility: **Private** is recommended for the first push; you can
     flip to public after reviewing the rendered repo.
   - Do **not** initialize with README/.gitignore/license (the repo
     already has all three) — an initialized remote would create
     divergent history.
7. Copy the repository URL when presented (e.g.
   `https://github.com/<owner>/<repo>.git`).

## Phase D — connect and push (needs YOUR URL from step 7)

```powershell
# 8. Add the remote — paste your actual URL (never commit credentials)
git remote add origin https://github.com/<owner>/<repo>.git
git remote -v                         # verify the URL is yours

# 9. Rename the local branch to main (safe: metadata-only; CI triggers on main)
git branch -M main

# 10. Push
git push -u origin main
```

## Phase E — verify on GitHub (browser)

11. Open the repository URL in the browser and confirm:
    - File tree matches the intended layout (tracevoryx/, trustweave/,
      tests/, docs/, scripts/, fixtures/, benchmarks/, reports/,
      .github/, top-level docs + pyproject).
    - **No** `data/`, `dist/`, `__pycache__/`, `.venv`, logs, keys, or
      token files anywhere in the tree.
    - README renders correctly (em dashes/arrows display as glyphs, not
      mojibake).
    - `CHANGELOG.md` shows the 0.3.0 + baseline-cleanup sections.
12. Check the **Actions** tab: the CI workflow should trigger on the
    `main` push. Expect the matrix (windows/ubuntu × Python 3.11/3.12)
    to take a few minutes. If a job fails, read the log — the local
    equivalents all passed (docs/TEST_RESULTS.md), so a remote failure
    is an environment difference to diagnose, not a reason to force
    anything.
13. Optionally delete the local backup branch when satisfied
    (`git branch -D backup/pre-github-baseline`) — or keep it; it costs
    nothing.

## Phase F — optional release assets (your decision; not required)

- `dist/tracevoryx-0.3.0.zip` + `dist/MANIFEST.sha256` exist locally
  (verified: gate PASS, manifest parity 142/142). They are gitignored —
  they will NOT be pushed by step 10. To attach them to a GitHub
  Release: create a tag (`git tag v0.3.0 && git push origin v0.3.0`),
  then use the GitHub "Draft a new release" UI and upload the ZIP +
  manifest as binary assets.
- Do not commit `dist/` into the repository.
- PyPI publication (if ever desired) should use trusted publishing —
  see `docs/RELEASE_CHECKLIST.md`.

## Hard rules (unchanged)

- Never commit `.env`, `data/`, token/key files; the deny rules in
  `scripts/package_release.py` and the CI secret scan enforce this on
  the artifact side; `.gitignore` + your Phase A review enforce the
  source side.
- If you ever find a real credential in history: do not force-push
  ad hoc — rotate the credential first, then decide on history cleanup
  with full awareness (currently the history is clean: 1 commit,
  140 blobs, 0 secret hits).
