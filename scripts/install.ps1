# TrustWeave installation for Windows 11 (PowerShell 5.1+)
# Reproducible install: venv + pinned install + first-run bootstrap.
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $root "..")

Write-Host "== TrustWeave install ==" -ForegroundColor Cyan

# 1. Python check
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Error "Python 3.11+ required"; exit 1 }
$ver = (& python --version) 2>&1
Write-Host "Found $ver"

# 2. Virtual environment (idempotent)
if (-not (Test-Path ".venv")) {
    python -m venv .venv
    Write-Host "Created .venv"
}
$pyPath = (Resolve-Path ".\.venv\Scripts\python.exe").Path

# 3. Dependencies (always via `python -m pip`)
Write-Host "Installing dependencies..." -ForegroundColor Cyan
& $pyPath -m pip install --upgrade pip 2>&1 | Out-Null
& $pyPath -m pip install -e ".[dev]"
if ($LASTEXITCODE -ne 0) { Write-Error "dependency install failed"; exit 1 }

# 4. Runtime directories (clean init without touching existing evidence)
New-Item -ItemType Directory -Force -Path data, logs | Out-Null

# 5. Sanity check: the package must import in the venv
& $pyPath -c "import trustweave; print('trustweave import OK')"

# 6. First-run token bootstrap (prints ONCE, hash-stored)
if (-not (Test-Path "data\api_tokens.json")) {
    Write-Host ""
    Write-Host "== Bootstrap admin token (shown ONCE, hash-stored) ==" -ForegroundColor Yellow
    & $pyPath -m trustweave.cli rotate-token
} else {
    Write-Host "Token records already exist - no new token issued." -ForegroundColor Green
}

Write-Host ""
Write-Host "Install complete. Start with: .\scripts\start.ps1" -ForegroundColor Green
