# Stop TrustWeave - only the instance it can reliably identify.
# Identity = instance marker (pid + start time) OR port owner with a
# trustweave command line. Stale markers and unrelated processes are never
# killed. Graceful stop first, forced stop only if it does not exit.
param(
    [int]$TimeoutSec = 15
)
$ErrorActionPreference = "SilentlyContinue"
$twRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $twRoot

# --- configuration (same resolution as start.ps1) ---
$port = 8640
$settingsPath = Join-Path $twRoot "config\settings.json"
if (Test-Path $settingsPath) {
    try {
        $cfg = Get-Content $settingsPath -Raw | ConvertFrom-Json
        if ($cfg.api.port) { $port = [int]$cfg.api.port }
    } catch { }
}

function Get-TwPidFromMarker {
    $marker = Join-Path $twRoot "data\tw_instance.json"
    if (-not (Test-Path $marker)) { return $null }
    try {
        $m = Get-Content $marker -Raw | ConvertFrom-Json
        $p = Get-Process -Id $m.pid -ErrorAction SilentlyContinue
        if (-not $p) { return $null }                    # stale marker
        if ($p.StartTime.ToString("o") -ne $m.started) { return $null }  # PID reuse
        return $m.pid
    } catch { return $null }
}

function Test-TrustWeaveProcess($procId) {
    $cmdline = (Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue).CommandLine
    return ($null -ne $cmdline -and $cmdline -match "trustweave")
}

$targetPid = $null
$source = ""

# 1) instance marker (verified against start time - stale-PID safe)
$markerPid = Get-TwPidFromMarker
if ($markerPid) {
    $targetPid = $markerPid
    $source = "instance marker"
}

# 2) fall back to port owner if it is genuinely TrustWeave
if (-not $targetPid) {
    $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn -and (Test-TrustWeaveProcess $conn.OwningProcess)) {
        $targetPid = $conn.OwningProcess
        $source = "port $port owner (command line verified)"
    }
}

if (-not $targetPid) {
    Write-Host "TrustWeave is not running (no valid marker, no TrustWeave listener on port $port)."
    exit 0
}

Write-Host "Stopping TrustWeave pid $targetPid (identified via $source)..."
# graceful first: taskkill without /F sends a close request
taskkill /PID $targetPid 2>&1 | Out-Null
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline) {
    $still = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
    if (-not $still) { break }
    Start-Sleep -Milliseconds 400
}
if (Get-Process -Id $targetPid -ErrorAction SilentlyContinue) {
    Write-Host "Process did not exit gracefully; forcing..."
    Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}
if (Get-Process -Id $targetPid -ErrorAction SilentlyContinue) {
    Write-Warning "Timeout: process $targetPid is still running. NOT claiming success."
    exit 1
}
# confirm port release
$deadline = (Get-Date).AddSeconds(5)
while ((Get-Date) -lt $deadline) {
    $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if (-not $conn) { break }
    Start-Sleep -Milliseconds 300
}
if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    Write-Warning "Port $port is still in use after stop."
    exit 1
}
Remove-Item (Join-Path $twRoot "data\tw_instance.json") -ErrorAction SilentlyContinue
Write-Host "TrustWeave stopped; port $port released." -ForegroundColor Green
