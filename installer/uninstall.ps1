#Requires -Version 5.1
<#
.SYNOPSIS
    Uninstalls SQL Server Performance Dashboard.
#>
param([string]$InstallDir = "$env:LOCALAPPDATA\SqlDashboard")

$ErrorActionPreference = 'Continue'

Write-Host "Uninstalling SQL Server Performance Dashboard..." -ForegroundColor Cyan

# Stop running dashboard
$c = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
if ($c) { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue; Write-Host "  Stopped running dashboard" }

# Remove autostart task
schtasks /Delete /TN 'SqlDashboard-Autostart' /F 2>$null | Out-Null

# Remove shortcuts
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\SQL Dashboard" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\Desktop\SQL Dashboard.lnk" -Force -ErrorAction SilentlyContinue
Write-Host "  Removed shortcuts"

# Preserve config? Ask user
if (Test-Path (Join-Path $InstallDir 'servers.json')) {
    $ans = Read-Host "Keep server configuration (servers.json)? [Y/n]"
    if ($ans -notmatch '^n') {
        $backup = "$env:USERPROFILE\SqlDashboard-config-backup"
        New-Item -ItemType Directory -Force -Path $backup | Out-Null
        Copy-Item (Join-Path $InstallDir 'servers.json') $backup -Force -ErrorAction SilentlyContinue
        Copy-Item (Join-Path $InstallDir '.encryption-key') $backup -Force -ErrorAction SilentlyContinue
        Write-Host "  Config backed up to: $backup" -ForegroundColor Yellow
    }
}

# Remove hosts entry (needs admin)
$hostsFile = "$env:WINDIR\System32\drivers\etc\hosts"
if ((Get-Content $hostsFile -ErrorAction SilentlyContinue | Select-String 'sql-dashboard')) {
    Write-Host "  Removing 'sql-dashboard' hosts entry (may prompt for admin)..."
    try {
        $rmScript = @"
`$hostsFile = '$hostsFile'
`$lines = Get-Content `$hostsFile | Where-Object { `$_ -notmatch 'sql-dashboard' }
Set-Content -Path `$hostsFile -Value `$lines -Encoding ASCII
"@
        $tmp = Join-Path $env:TEMP "sqldash-rmhosts.ps1"
        Set-Content -Path $tmp -Value $rmScript -Encoding UTF8
        Start-Process powershell.exe -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File","`"$tmp`"" -Verb RunAs -Wait
        Remove-Item $tmp -ErrorAction SilentlyContinue
    } catch { Write-Host "  (Could not remove hosts entry — you can edit $hostsFile manually)" }
}

# Remove install folder
if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Removed: $InstallDir"
}

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
Write-Host "Note: Node.js, ODBC driver, and go-sqlcmd are NOT removed (they may be used by other apps)."
Write-Host "      Remove them via 'winget uninstall' if you no longer need them."
