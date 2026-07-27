#Requires -Version 5.1
<#
.SYNOPSIS
    SQL Server Performance Dashboard — installer

.DESCRIPTION
    Installs the multi-instance SQL Server Performance Dashboard to
    %LOCALAPPDATA%\SqlDashboard, checks/installs prerequisites, and creates
    Start Menu / Desktop shortcuts.

    Prerequisites installed via winget (if missing):
      * Node.js LTS (>=18)
      * Microsoft.Sqlcmd (go-sqlcmd) — needed for Entra ID MFA
      * Microsoft ODBC Driver for SQL Server (ships with ODBC SQLCMD)

    No admin required; installs per-user.

.PARAMETER InstallDir
    Target folder (default: %LOCALAPPDATA%\SqlDashboard)

.PARAMETER SkipPrereqs
    Skip prerequisite checks/installation.

.PARAMETER NoShortcuts
    Skip Start Menu / Desktop shortcut creation.

.PARAMETER NoAutostart
    Skip auto-registration of the "start at logon" scheduled task.

.PARAMETER NoHostsEntry
    Skip adding 'sql-dashboard' to the Windows hosts file (skips UAC prompt).
    Dashboard will still work via http://127.0.0.1:8765/
#>
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\SqlDashboard",
    [switch]$SkipPrereqs,
    [switch]$NoShortcuts,
    [switch]$NoAutostart,
    [switch]$NoHostsEntry
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$payload   = Join-Path $scriptDir 'payload'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "  [X] $msg"  -ForegroundColor Red }

function Test-Command($name) {
    $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

function Install-WithWinget($id, $friendlyName) {
    if (-not (Test-Command winget)) {
        Write-Err "winget not found. Please install App Installer from Microsoft Store, then rerun."
        return $false
    }
    Write-Step "Installing $friendlyName via winget ($id)..."
    $wingetArgs = @('install','--id',$id,'--silent','--accept-package-agreements','--accept-source-agreements','--source','winget','--scope','user')
    & winget @wingetArgs
    if ($LASTEXITCODE -ne 0) {
        # Retry without --scope user (some packages don't support it)
        & winget install --id $id --silent --accept-package-agreements --accept-source-agreements --source winget
    }
    return ($LASTEXITCODE -eq 0)
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "  SQL Server Performance Dashboard  —  Installer" -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host ""

# 1) Prerequisites
if (-not $SkipPrereqs) {
    Write-Step "Checking prerequisites..."

    # Node.js
    if (Test-Command node) {
        $nodeVer = (node --version) -replace 'v',''
        $major = [int]($nodeVer.Split('.')[0])
        if ($major -ge 18) { Write-OK "Node.js v$nodeVer" }
        else {
            Write-Warn "Node.js $nodeVer is too old (need >=18). Installing latest LTS..."
            $null = Install-WithWinget 'OpenJS.NodeJS.LTS' 'Node.js LTS'
        }
    } else {
        Write-Warn "Node.js not found. Installing..."
        $null = Install-WithWinget 'OpenJS.NodeJS.LTS' 'Node.js LTS'
    }

    # ODBC sqlcmd (Client SDK)
    $odbcSqlcmd = @(
        "$env:ProgramFiles\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE",
        "$env:ProgramFiles\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\SQLCMD.EXE",
        "$env:ProgramFiles\Microsoft SQL Server\Client SDK\ODBC\190\Tools\Binn\SQLCMD.EXE"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($odbcSqlcmd) {
        Write-OK "ODBC sqlcmd found: $odbcSqlcmd"
    } else {
        Write-Warn "ODBC sqlcmd not found. Installing Microsoft ODBC Driver 18 for SQL Server..."
        $null = Install-WithWinget 'Microsoft.msodbcsql.18' 'ODBC Driver 18'
    }

    # go-sqlcmd (for MFA / Entra ID Interactive)
    $goSqlcmd = "$env:ProgramFiles\SqlCmd\sqlcmd.exe"
    if (Test-Path $goSqlcmd) {
        Write-OK "go-sqlcmd found: $goSqlcmd"
    } else {
        Write-Warn "go-sqlcmd not found (needed for Entra ID MFA). Installing..."
        $null = Install-WithWinget 'Microsoft.Sqlcmd' 'go-sqlcmd'
    }
} else {
    Write-Warn "Skipping prerequisite checks (-SkipPrereqs)"
}

# 2) Copy payload
Write-Host ""
Write-Step "Installing dashboard to: $InstallDir"
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null }
Copy-Item "$payload\*" $InstallDir -Recurse -Force
# Preserve existing servers.json and .encryption-key on upgrade
Write-OK "Files copied"

# 3) npm install
Write-Host ""
Write-Step "Running npm install (this may take a minute)..."
# Refresh PATH so we can find node/npm right after installing them
$env:PATH = [Environment]::GetEnvironmentVariable('PATH','User') + ';' + [Environment]::GetEnvironmentVariable('PATH','Machine')
Push-Location $InstallDir
try {
    & npm install --omit=dev --no-audit --no-fund 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    if ($LASTEXITCODE -ne 0) { throw "npm install failed with exit code $LASTEXITCODE" }
    Write-OK "Dependencies installed"
} finally {
    Pop-Location
}

# 4) Start-Dashboard.ps1 launcher (kept alongside the app for direct execution)
$launcher = @'
# Launches the SQL Dashboard node server hidden and opens the browser
$installDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $installDir
$existing = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Dashboard already running"
} else {
    Start-Process node -ArgumentList "server5.mjs" -WorkingDirectory $installDir -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $installDir 'server.log') `
        -RedirectStandardError  (Join-Path $installDir 'server.err.log')
    Start-Sleep -Seconds 2
}
# Prefer the friendly hostname if it resolves (added by the installer to hosts)
$url = "http://127.0.0.1:8765/"
try { $null = [System.Net.Dns]::GetHostEntry("sql-dashboard"); $url = "http://sql-dashboard:8765/" } catch {}
Start-Process $url
'@
Set-Content -Path (Join-Path $InstallDir 'Start-Dashboard.ps1') -Value $launcher -Encoding UTF8
Write-OK "Launcher script created"

# Stop-Dashboard.ps1
$stopper = @'
$c = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
if ($c) { Stop-Process -Id $c.OwningProcess -Force; Write-Host "Dashboard stopped." }
else    { Write-Host "Dashboard was not running." }
'@
Set-Content -Path (Join-Path $InstallDir 'Stop-Dashboard.ps1') -Value $stopper -Encoding UTF8

# 5) Friendly hostname alias in %WINDIR%\System32\drivers\etc\hosts (needs admin)
if (-not $NoHostsEntry) {
    Write-Host ""
    Write-Step "Adding friendly hostname 'sql-dashboard' to hosts file (requires admin)..."
    $hostsFile = "$env:WINDIR\System32\drivers\etc\hosts"
    $existing = Get-Content $hostsFile -ErrorAction SilentlyContinue | Select-String 'sql-dashboard'
    if ($existing) {
        Write-OK "hosts already contains 'sql-dashboard' entry"
    } else {
        try {
            $addScript = @"
`$line = "``r``n127.0.0.1  sql-dashboard  # SQL Performance Dashboard"
Add-Content -Path '$hostsFile' -Value `$line
"@
            $tmpScript = Join-Path $env:TEMP "sqldash-hosts.ps1"
            Set-Content -Path $tmpScript -Value $addScript -Encoding UTF8
            Start-Process powershell.exe -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File","`"$tmpScript`"" -Verb RunAs -Wait
            Remove-Item $tmpScript -ErrorAction SilentlyContinue
            ipconfig /flushdns | Out-Null
            $verify = Get-Content $hostsFile | Select-String 'sql-dashboard'
            if ($verify) { Write-OK "Friendly URL: http://sql-dashboard:8765/" }
            else { Write-Warn "hosts entry not added (UAC declined?). Dashboard will use http://127.0.0.1:8765/" }
        } catch {
            Write-Warn "Could not add hosts entry: $($_.Exception.Message)"
            Write-Warn "Dashboard will use http://127.0.0.1:8765/"
        }
    }
}

# 6) Shortcuts
if (-not $NoShortcuts) {
    Write-Host ""
    Write-Step "Creating shortcuts..."
    $ws = New-Object -ComObject WScript.Shell
    $target  = 'powershell.exe'
    $lnkArgs = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallDir\Start-Dashboard.ps1`""
    $icoPath = Join-Path $InstallDir 'sql-dashboard-logo.ico'
    # Start Menu
    $startMenuDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\SQL Dashboard"
    New-Item -ItemType Directory -Force -Path $startMenuDir | Out-Null
    $lnkPath = Join-Path $startMenuDir 'SQL Performance Dashboard.lnk'
    $lnk = $ws.CreateShortcut($lnkPath)
    $lnk.TargetPath = $target
    $lnk.Arguments  = $lnkArgs
    $lnk.WorkingDirectory = $InstallDir
    if (Test-Path $icoPath) { $lnk.IconLocation = "$icoPath,0" }
    $lnk.Description = 'Open the SQL Performance Dashboard'
    $lnk.WindowStyle = 7
    $lnk.Save()
    Write-OK "Start Menu: $lnkPath"
    # Desktop (honors OneDrive-redirected Desktop)
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $desktopLnk = Join-Path $desktopPath 'SQL Performance Dashboard.lnk'
    $lnk2 = $ws.CreateShortcut($desktopLnk)
    $lnk2.TargetPath = $target
    $lnk2.Arguments  = $lnkArgs
    $lnk2.WorkingDirectory = $InstallDir
    if (Test-Path $icoPath) { $lnk2.IconLocation = "$icoPath,0" }
    $lnk2.Description = 'Open the SQL Performance Dashboard'
    $lnk2.WindowStyle = 7
    $lnk2.Save()
    Write-OK "Desktop: $desktopLnk"
}

# 7) Autostart at logon (Task Scheduler) — enabled by default
if (-not $NoAutostart) {
    Write-Host ""
    Write-Step "Registering autostart at logon (Task Scheduler)..."
    try {
        $taskName = 'SqlDashboard-Autostart'
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $startScript = Join-Path $InstallDir 'Start-Dashboard.ps1'
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                       -Argument ("-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$startScript`"")
        $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                       -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 0)
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
                       -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                       -Settings $settings -Principal $principal `
                       -Description 'Starts SQL Performance Dashboard at logon' | Out-Null
        Write-OK "Registered scheduled task: $taskName (starts at logon)"
    } catch {
        Write-Warn "Could not register scheduled task: $($_.Exception.Message)"
        Write-Warn "You can start the dashboard manually from the Start Menu shortcut."
    }
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "  INSTALL COMPLETE" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Launch the dashboard from:" -ForegroundColor White
Write-Host ("  Start Menu -> SQL Dashboard -> SQL Dashboard")
Write-Host ("  Desktop shortcut")
Write-Host ("  Or run: powershell " + (Join-Path $InstallDir 'Start-Dashboard.ps1'))
Write-Host ""
Write-Host "First-time setup:" -ForegroundColor White
Write-Host ("  1. Dashboard opens at http://sql-dashboard:8765/ (or http://127.0.0.1:8765/)")
Write-Host ("  2. It auto-seeds a Local server for your default SQL instance")
Write-Host ("  3. Click Add server to register more instances")
Write-Host ""
Write-Host ("Uninstall: powershell " + (Join-Path $scriptDir 'uninstall.ps1')) -ForegroundColor DarkGray
Write-Host ""
