# TrustWeave Windows telemetry diagnostics.
# REPORT-ONLY by default. With -EnableProcessCreationAuditing it proposes the
# exact change and requires -Apply to execute (administrator + explicit consent).
param(
    [switch]$EnableProcessCreationAuditing,
    [switch]$Apply
)
$ErrorActionPreference = "SilentlyContinue"

Write-Host "== TrustWeave Windows telemetry diagnostics ==" -ForegroundColor Cyan

# --- elevation state ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ""
Write-Host "Session elevation: " -NoNewline
if ($isAdmin) { Write-Host "ELEVATED (full checks available)" -ForegroundColor Green }
else {
    Write-Host "standard user (some checks unavailable - this is expected, not an error)" -ForegroundColor Yellow
    Write-Host "  To run every check, start an elevated PowerShell and re-run this script."
}

# --- audit policy (elevated only; auditpol /get requires admin) ---
Write-Host ""
Write-Host "Process-creation auditing (auditpol):"
if ($isAdmin) {
    $raw = auditpol /get /subcategory:"Process Creation" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  auditpol failed: $raw" -ForegroundColor Yellow
    } elseif ($raw -match "No Auditing") {
        Write-Host "  DISABLED - Security log will contain no 4688 events." -ForegroundColor Red
        Write-Host "  To enable (administrator, explicit operator decision):"
        Write-Host '    auditpol /set /subcategory:"Process Creation" /success:enable'
    } else {
        Write-Host "  ENABLED ($($raw | Where-Object { $_ -match 'Process Creation' }))" -ForegroundColor Green
    }
} else {
    Write-Host "  UNKNOWN - 'auditpol /get' requires elevation." -ForegroundColor Yellow
}

# --- Security log access ---
Write-Host ""
Write-Host "Security log access (4688 source):"
$readErr = $null
try {
    $null = Get-WinEvent -LogName "Security" -MaxEvents 1 -ErrorAction Stop
    Write-Host "  READABLE - collector can read Security events." -ForegroundColor Green
} catch {
    $readErr = $_.Exception.Message
    if ($readErr -match "unauthorized|access|denied") {
        Write-Host "  ACCESS DENIED - $readErr" -ForegroundColor Yellow
        Write-Host "  Fix: run elevated, or grant the account 'Event Log Readers' membership."
    } elseif ($readErr -match "No events|found") {
        Write-Host "  READABLE (log present; possibly empty)." -ForegroundColor Green
    } else {
        Write-Host "  ERROR - $readErr" -ForegroundColor Yellow
    }
}

# --- Sysmon (service enumeration needs no elevation) ---
Write-Host ""
Write-Host "Sysmon (process/network/file telemetry):"
$svc = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "  service present: $($svc.Name) - $($svc.Status)" -ForegroundColor Green
    try {
        $null = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
        Write-Host "  Sysmon operational log: READABLE" -ForegroundColor Green
    } catch {
        Write-Host "  Sysmon operational log: not readable - $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  NOT INSTALLED - this is a missing prerequisite, not a permission problem." -ForegroundColor Yellow
    Write-Host "  Install Sysmon (Sysinternals) with a config including process/network/file"
    Write-Host "  events; TrustWeave will then collect EIDs 1, 3, 11."
}

# --- optional remediation (explicit consent required) ---
if ($EnableProcessCreationAuditing) {
    Write-Host ""
    Write-Host "== Optional remediation ==" -ForegroundColor Cyan
    $change = 'auditpol /set /subcategory:"Process Creation" /success:enable'
    Write-Host "Proposed change: $change"
    if (-not $isAdmin) {
        Write-Host "REQUIRES an elevated session. Re-run this script elevated with -EnableProcessCreationAuditing -Apply."
        exit 1
    }
    if ($Apply) {
        Write-Host "Applying (you consented via -Apply)..."
        cmd /c $change
        Write-Host "Done. Verify with: auditpol /get /subcategory:`"Process Creation`""
    } else {
        Write-Host "DRY RUN - nothing changed. Re-run with -Apply to execute."
    }
}

Write-Host ""
Write-Host "Summary: TrustWeave keeps operating regardless of these results;"
Write-Host "degraded providers stay visibly degraded in /api/v1/status."
