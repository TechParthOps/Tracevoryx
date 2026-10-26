# Start TrustWeave (shadow mode by default; -Enforce to enforce policies).
# Idempotent: if a healthy instance already listens on the port, report it
# and exit 0. If the port is held by an unrelated process, report the PID
# and exit 1 - never kill automatically.
param(
    [switch]$Enforce,
    [switch]$WithClipboard,
    [int]$HealthTimeoutSec = 20
)
$ErrorActionPreference = "Stop"
$twRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $twRoot

# --- configuration: read the port from config/settings.json if present ---
$port = 8640
$settingsPath = Join-Path $twRoot "config\settings.json"
if (Test-Path $settingsPath) {
    try {
        $cfg = Get-Content $settingsPath -Raw | ConvertFrom-Json
        if ($cfg.api.port) { $port = [int]$cfg.api.port }
        if ($cfg.api.host) { $host_ = $cfg.api.host } else { $host_ = "127.0.0.1" }
    } catch { $host_ = "127.0.0.1" }
} else { $host_ = "127.0.0.1" }
$base = "http://${host_}:${port}"

# --- 1. is something already listening? ---
$existing = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($existing) {
    $ownerPid = $existing.OwningProcess
    $procInfo = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
    $cmdline = (Get-CimInstance Win32_Process -Filter "ProcessId=$ownerPid" -ErrorAction SilentlyContinue).CommandLine
    $isTw = ($cmdline -match "trustweave") -or ($procInfo.ProcessName -eq "python" -and $cmdline -match "-m trustweave")

    # healthy TrustWeave instance -> report, don't duplicate
    try {
        $health = Invoke-WebRequest -Uri "$base/api/v1/health" -UseBasicParsing -TimeoutSec 3
        if ($health.StatusCode -eq 200 -and $isTw) {
            Write-Host "TrustWeave is already running and healthy at $base (pid $ownerPid). Nothing to do." -ForegroundColor Green
            exit 0
        }
    } catch { }

    if ($isTw) {
        Write-Warning "A TrustWeave process (pid $ownerPid) holds port $port but is NOT healthy yet. If it just started, wait; otherwise inspect it."
        exit 1
    }
    Write-Warning "Port $port is held by pid $ownerPid ('$($procInfo.ProcessName)') which is not TrustWeave. Refusing to start and refusing to kill it."
    Write-Warning "Free the port or change api.port in config/settings.json."
    exit 1
}

# --- 2. launch ---
$py = Join-Path $twRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$modeArgs = @("-m", "trustweave.cli")
if ($WithClipboard) { $modeArgs = @("-m", "trustweave.cli", "watch-clipboard") }
elseif ($Enforce) { $modeArgs = @("-m", "trustweave.cli", "enforce") }
else { $modeArgs = @("-m", "trustweave.cli", "serve") }

Write-Host "Starting TrustWeave on $base ..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $py -ArgumentList $modeArgs -WorkingDirectory $twRoot `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $twRoot "data\server.out.log") `
    -RedirectStandardError (Join-Path $twRoot "data\server.err.log")

# instance marker: pid + start time (both checked by stop.ps1; stale-safe)
[PSCustomObject]@{ pid = $proc.Id; started = $proc.StartTime.ToString("o"); port = $port } |
    ConvertTo-Json | Set-Content (Join-Path $twRoot "data\tw_instance.json")

# --- 3. verify health with timeout (never claim success prematurely) ---
$deadline = (Get-Date).AddSeconds($HealthTimeoutSec)
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) {
        Write-Error "TrustWeave exited during startup (code $($proc.ExitCode)). See data\server.err.log"
        exit 1
    }
    try {
        $health = Invoke-WebRequest -Uri "$base/api/v1/health" -UseBasicParsing -TimeoutSec 2
        if ($health.StatusCode -eq 200) {
            Write-Host "TrustWeave is running at $base (pid $($proc.Id))" -ForegroundColor Green
            Write-Host $health.Content
            exit 0
        }
    } catch { Start-Sleep -Milliseconds 500 }
}
Write-Error "TrustWeave did not become healthy within $HealthTimeoutSec s. See data\server.err.log"
exit 1
