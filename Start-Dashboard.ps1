# Launches the SQL Dashboard node server hidden and opens the browser
$installDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $installDir
$existing = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Dashboard already running"
} else {
    Start-Process node -ArgumentList "server.mjs" -WorkingDirectory $installDir -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $installDir 'server.log') `
        -RedirectStandardError  (Join-Path $installDir 'server.err.log')
    Start-Sleep -Seconds 2
}
# Prefer the friendly hostname if it resolves (added by the installer to hosts)
$url = "http://127.0.0.1:8765/"
try { $null = [System.Net.Dns]::GetHostEntry("sql-dashboard"); $url = "http://sql-dashboard:8765/" } catch {}
Start-Process $url

