#Requires -Version 5.1
<#
.SYNOPSIS
  Phase 1 helper: print versions of Windows prerequisites.
  A missing command is a missing install — never treat absence as success.
#>

$ErrorActionPreference = "Continue"

function Show-Check {
    param(
        [string]$Name,
        [scriptblock]$Command
    )
    Write-Host ""
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    try {
        & $Command
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            Write-Host "Command exited with code $LASTEXITCODE" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "NOT FOUND: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "IoT Security Framework — Windows prerequisite check"
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"

Show-Check "Git" { git --version }
Show-Check "Python" { python --version }
Show-Check "Python launcher list" { py -0 }
Show-Check "pip" { python -m pip --version }
Show-Check "Node.js" { node --version }
Show-Check "npm" { npm --version }
Show-Check "Docker" { docker --version }
Show-Check "Nmap" { nmap --version }
Show-Check "PostgreSQL client" { psql --version }
Show-Check "PlatformIO" { pio --version }

$wireshark = "C:\Program Files\Wireshark\Wireshark.exe"
Write-Host ""
Write-Host "=== Wireshark ===" -ForegroundColor Cyan
if (Test-Path $wireshark) {
    Write-Host "Found: $wireshark"
}
else {
    Write-Host "NOT FOUND at $wireshark" -ForegroundColor Red
}

Write-Host ""
Write-Host "Copy this output into SETUP_LOG.md after each install."
