# Secret Cleanup — 0.2.0 archive incident

## What was exposed

The 0.2.0 working archive shared for this engagement contained live
runtime state:

- `data/api_tokens.json` — two admin token HASHES (plus the ability to
  attempt offline guessing),
- `data/current_admin_token.txt` — a PLAINTEXT admin API token,
- `data/audit_key` — the HMAC audit trust anchor,
- `data/trustweave.db` (+ WAL/SHM) — runtime evidence,
- `data/logs/`, `data/tw_instance.json`, bundled `.venv`.

Any recipient of that archive must treat all of it as compromised.

## Actions taken (this workspace)

1. **Revoked all exposed tokens** — the token record store was purged
   (both admin records invalidated; nothing authenticated against them
   works anymore).
2. **Issued a fresh admin token** — written to
   `data/bootstrap_token.txt` (local-only, git-ignored, 0600 where the OS
   allows); the value is NOT reproduced in any report, log, or transcript.
   **Owner action:** use it once, then rotate via
   `POST /api/v1/auth/rotate`, then delete the file.
3. **Destroyed `data/current_admin_token.txt`** — the plaintext credential
   file is gone (its existence is documented here; the value is not).
4. **Rotated the audit key evidence-safely** — final checkpoint signed
   under the old key (`seq 3`), old key preserved as
   `data/audit_key.retired-20261024T151204Z` for verifying pre-rotation
   checkpoints, fresh key generated. Consequence: pre-rotation checkpoints
   verify under the retired epoch; rotation limits FUTURE forgery only.
5. **Verified no plaintext tokens in logs** — scanned `data/*.log` for
   token-shaped strings: none.
6. **Runtime evidence preserved** — `data/trustweave.db` and
   `data/tracevoryx.db` (the owner's Oct-24 `scan-pcap` runs) were NOT
   deleted; they remain local-only and are excluded from every packaged
   artifact.

## Structural prevention (why this cannot ship again)

- `.gitignore` excludes `data/`, `logs/`, `.venv*`, DB/WAL/SHM, token and
  key file names.
- `scripts/package_release.py` stages ONLY allowlisted paths and fails on
  any secret-pattern hit (documented synthetic fixtures allowlisted by
  exact value).
- `tests/test_release_hygiene.py` (runs in CI) re-verifies staging rules,
  scans the staged tree, and rejects token-shaped strings outside the
  allowlist.
- CI runs the same scanner over all git-tracked files.

## Owner checklist (outside this machine)

- If the archive was shared with anyone else, treat every token/key above
  as public: this rotation covers the workspace copy only.
- Rotate any credential that appears in old tool-call arguments or
  clipboard captures stored in the retained databases (they are readable
  to the local user by design).
- Delete `.venv-bundled-backup/` and `data-bundled-backup/` once no longer
  needed; they are already excluded from packaging and git.
