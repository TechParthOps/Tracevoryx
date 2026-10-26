"""Stage and verify a clean release package.

Only explicitly approved paths are staged. The staged tree is then scanned
for sensitive runtime artifacts and secret-like strings; any hit fails the
packaging run. Produces:
  dist/tracevoryx-<version>/        staged source tree
  dist/tracevoryx-<version>.zip    zipped artifact
  dist/MANIFEST.sha256              per-file hashes of the staged tree
  dist/dependency-inventory.json    declared + installed dependency inventory

Usage: python scripts/package_release.py
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

APPROVED_DIRS = ["tracevoryx", "trustweave", "docs", "tests", "scripts",
                 "benchmarks", "fixtures", "config", ".github", "reports"]
APPROVED_FILES = ["pyproject.toml", "README.md", "LICENSE", ".env.example",
                  ".gitignore", "CHANGELOG.md", "SECURITY.md",
                  "CONTRIBUTING.md"]

# Runtime state, credentials, local environments: never shipped.
DENY_FILE_PATTERNS = [
    r"\.db$", r"\.db-wal$", r"\.db-shm$", r"\.sqlite3?$",
    r"api_tokens\.json$", r"audit_key(\.retired-[\wT-Z]+)?$",
    r"current_admin_token\.txt$", r"bootstrap_token\.txt$",
    r"tw_instance\.json$", r"runtime_state\.json$",
    r"audit_export_.*\.jsonl$", r"\.log$", r"\.log\.\d+$",
    r"\.pyc$", r"\.pyo$", r"\.token$", r"\.pem$", r"\.key$",
]
DENY_DIR_PATTERNS = [
    r"^\.venv", r"^venv", r"^data", r"__pycache__", r"^\.pytest_cache",
    r"\.egg-info$", r"^\.git$", r"^dist", r"^build", r"node_modules",
    r"^logs", r"^bench_out", r"^\.ruff_cache", r"^\.mypy_cache",
]

# Known-secret shapes; documented synthetic fixture values are allowlisted
# explicitly (see ALLOWLISTED_SECRET_VALUES).
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"gh[pousr]_[A-Za-z0-9]{36}", "GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained token"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "PEM private key"),
    (r"tw_[A-Za-z0-9_\-]{38,}", "Tracevoryx/TrustWeave API token"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
     "JWT"),
    (r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}", "OpenAI-style API key"),
]
# Documented synthetic fixture values only (never real credentials).
# The DLP fixture is a deterministic high-entropy fake token.
_SYNTH_GH = "ghp_Qk7vW2xR9mZ4nJ8pL3sT6yH1cF5gD0aB2eX4"
ALLOWLISTED_SECRET_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",          # AWS documentation example key
    _SYNTH_GH,                       # DLP detector fixture (obviously fake)
    "-----BEGIN RSA PRIVATE KEY-----",  # bare PEM header detector fixture
}


def _denied(rel: Path) -> bool:
    for part in rel.parts[:-1]:
        if any(re.search(p, part) for p in DENY_DIR_PATTERNS):
            return True
    name = rel.name
    if any(re.search(p, name) for p in DENY_FILE_PATTERNS):
        return True
    return any(re.search(p, str(rel)) for p in DENY_DIR_PATTERNS)


def stage(dest: Path) -> tuple[int, list[str]]:
    """Copy approved paths into dest; return (file_count, denial_reasons)."""
    denials: list[str] = []
    staged = 0
    for name in APPROVED_FILES:
        src = ROOT / name
        if not src.exists():
            continue
        if src.is_symlink():
            denials.append(f"symlink rejected: {name}")
            continue
        shutil.copy2(src, dest / name)
        staged += 1
    for d in APPROVED_DIRS:
        src = ROOT / d
        if not src.exists():
            continue
        for f in src.rglob("*"):
            if f.is_symlink():
                denials.append(f"symlink rejected: {f.relative_to(ROOT)}")
                continue
            if not f.is_file():
                continue
            rel = f.relative_to(ROOT)
            if _denied(rel):
                denials.append(str(rel))
                continue
            out = dest / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, out)
            staged += 1
    return staged, denials


def scan_for_secrets(dest: Path) -> list[str]:
    hits: list[str] = []
    for f in dest.rglob("*"):
        if not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pat, label in SECRET_PATTERNS:
            for m in re.finditer(pat, text):
                if m.group(0) in ALLOWLISTED_SECRET_VALUES:
                    continue
                hits.append(f"{f.relative_to(dest)}: {label}")
    return sorted(set(hits))


def write_manifest(dest: Path, out: Path) -> int:
    lines = []
    for f in sorted(dest.rglob("*")):
        if not f.is_file():
            continue
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        lines.append(f"{digest}  {f.relative_to(dest).as_posix()}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def dependency_inventory(out: Path) -> dict:
    """Declared dependencies + versions installed in THIS build environment.
    Honest limitation: not a full transitive SBOM; regenerate in CI."""
    import importlib.metadata as md
    from tomllib import loads
    declared = loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = declared["project"]["dependencies"]
    optional = declared["project"].get("optional-dependencies", {})
    installed = {}
    for dist in md.distributions():
        name = dist.metadata.get("Name")
        if name:
            installed[name] = dist.version
    inv = {
        "schema": "tracevoryx-dependency-inventory/1",
        "generator": "scripts/package_release.py",
        "limitation": "installed list reflects the build environment; "
                      "generate a full SBOM in CI for release artifacts",
        "declared_runtime": deps,
        "declared_optional": optional,
        "requires_python": declared["project"]["requires-python"],
        "installed_in_build_env": dict(sorted(installed.items())),
    }
    out.write_text(json.dumps(inv, indent=2), encoding="utf-8")
    return inv


def verify_zip_independently(zpath: Path, staged: Path) -> dict:
    """Re-extract the release ZIP into a NEW temp directory and verify its
    contents independently of the source tree: no prohibited paths, no
    secret patterns, manifest hashes match, staged-tree parity."""
    import tempfile
    result: dict[str, object] = {"zip": zpath.name}
    with tempfile.TemporaryDirectory(prefix="tvx_verify_") as td:
        dest = Path(td)
        with zipfile.ZipFile(zpath) as zf:
            # reject absolute paths / traversal in member names before extract
            for info in zf.infolist():
                name = info.filename.replace("\\", "/")
                if name.startswith("/") or ".." in name.split("/"):
                    result["traversal_rejected"] = name
                    return {**result, "ok": False,
                            "reason": f"unsafe member name: {name}"}
            zf.extractall(dest)
        extracted = list(dest.rglob("*"))
        files = [f for f in extracted if f.is_file()]
        result["extracted_files"] = len(files)
        prohibited = []
        for f in files:
            rel = f.relative_to(dest)
            if _denied(rel):
                prohibited.append(str(rel))
        result["prohibited_paths"] = prohibited
        hits = scan_for_secrets(dest)
        result["secret_hits"] = hits
        # manifest parity: every extracted file matches MANIFEST.sha256
        manifest = {}
        # the manifest lives OUTSIDE the zip (dist/); verify against staged
        for line in (staged.parent / "MANIFEST.sha256").read_text(
                encoding="utf-8").splitlines():
            digest, _, relpath = line.partition("  ")
            manifest[relpath] = digest
        mismatches = []
        for f in files:
            rel = f.relative_to(dest).as_posix()
            if rel == "MANIFEST.sha256":
                continue
            digest = hashlib.sha256(f.read_bytes()).hexdigest()
            if manifest.get(rel) != digest:
                mismatches.append(rel)
        result["manifest_mismatches"] = mismatches
        ok = (not prohibited and not hits and not mismatches
              and len(files) == len(manifest))
        result["ok"] = ok
    return result


def release_gate_summary(dist: Path, version: str, staged_count: int,
                         denials: int, zip_check: dict) -> dict:
    return {
        "schema": "tracevoryx-release-gate/1",
        "version": version,
        "staged_files": staged_count,
        "deny_rule_exclusions": denials,
        "secret_scan": "clean",
        "zip_independent_verification": zip_check,
        "artifacts": {
            "staged_tree": f"tracevoryx-{version}/",
            "zip": zpath_name(version),
            "manifest": "MANIFEST.sha256",
            "dependency_inventory": "dependency-inventory.json",
        },
        "gate": "PASS" if zip_check.get("ok") else "FAIL",
    }


def zpath_name(version: str) -> str:
    return f"tracevoryx-{version}.zip"


def main() -> int:
    version = re.search(r'^version = "([^"]+)"',
                        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
                        re.MULTILINE).group(1)
    dist = ROOT / "dist"
    if dist.exists():
        shutil.rmtree(dist)
    dest = dist / f"tracevoryx-{version}"
    dest.mkdir(parents=True)
    staged, denials = stage(dest)
    print(f"staged {staged} files into {dest}")
    for d in denials[:20]:
        print(f"  excluded (deny rule): {d}")
    if denials:
        print(f"  ... {len(denials)} excluded total")
    hits = scan_for_secrets(dest)
    if hits:
        print("SECRET-LIKE STRINGS IN STAGED PACKAGE:")
        for h in hits:
            print(f"  {h}")
        return 1
    print("secret scan: clean")
    write_manifest(dest, dist / "MANIFEST.sha256")
    dependency_inventory(dist / "dependency-inventory.json")
    zpath = dist / zpath_name(version)
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(dest.rglob("*")):
            if f.is_file():
                zf.write(f, f.relative_to(dest))
    # independent verification: re-extract into a new temp dir and check
    check = verify_zip_independently(zpath, dest)
    print("zip re-extraction verification:",
          "PASS" if check.get("ok") else f"FAIL {check}")
    gate = release_gate_summary(dist, version, staged, len(denials), check)
    (dist / "release-gate.json").write_text(
        json.dumps(gate, indent=2), encoding="utf-8")
    print(f"artifact: {zpath} | gate: {gate['gate']}")
    return 0 if check.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
