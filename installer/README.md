# SQL Server Performance Dashboard — Installer

A live, multi-instance SQL Server performance dashboard powered by DMVs and Query Store, with support for on-prem SQL Server, Azure SQL Database, and Azure SQL Managed Instance.

## What's in this package

| File | Purpose |
|---|---|
| `install.bat` | Double-click to install (no admin needed) |
| `install.ps1` | The actual PowerShell installer |
| `uninstall.bat` / `uninstall.ps1` | Removal |
| `payload/` | Application source (Node.js server + HTML dashboard) |

## Quick install

**One-click:**
1. Double-click **`install.bat`**
2. Approve any winget prerequisite installs (Node.js, go-sqlcmd, ODBC driver)
3. When done, open **Start Menu → SQL Dashboard → SQL Dashboard** or the Desktop shortcut

**Advanced (PowerShell):**
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 [options]
```

### Options

| Flag | Description |
|---|---|
| `-InstallDir <path>` | Override target folder (default: `%LOCALAPPDATA%\SqlDashboard`) |
| `-SkipPrereqs` | Skip Node/sqlcmd checks (use if you know they're installed) |
| `-NoShortcuts` | Skip Start Menu / Desktop shortcut creation |
| `-NoAutostart` | Skip auto-registration of the "start at logon" scheduled task (autostart is enabled by default) |

## Prerequisites (installed automatically via winget if missing)

| Component | Purpose | winget ID |
|---|---|---|
| **Node.js LTS ≥ 18** | Runs the dashboard HTTP server | `OpenJS.NodeJS.LTS` |
| **ODBC Driver 18 for SQL Server** | Ships ODBC sqlcmd for standard auth | `Microsoft.msodbcsql.18` |
| **go-sqlcmd** | Needed for Entra ID Interactive (MFA) auth | `Microsoft.Sqlcmd` |

Windows 10 21H2+ / Windows 11 have `winget` pre-installed. If it's missing, install **App Installer** from the Microsoft Store first.

## First run

1. Dashboard opens at **http://127.0.0.1:8765/**
2. A default "Local" server entry points to your default SQL instance (Windows Auth)
3. Click **+ Add server** to register more:
   - **Windows Integrated** for on-prem SQL Server on the same domain
   - **SQL Server Authentication** for user/password logins
   - **Entra ID Integrated** for silent Azure auth using your Windows account
   - **Entra ID Password** for headless Azure automation
   - **Entra ID Interactive / MFA** for federated accounts (opens a browser once)

## Data at rest

- `servers.json` — server registry (no plaintext passwords)
- `.encryption-key` — AES-256 key **wrapped with Windows DPAPI (CurrentUser)**
- Both files live in the install folder and are bound to your Windows account
- Copying them to another machine / user won't decrypt

## Uninstall

Double-click **`uninstall.bat`**. You'll be asked whether to keep your server config (saved to `%USERPROFILE%\SqlDashboard-config-backup` if yes).

Node.js, ODBC driver, and go-sqlcmd are left in place — remove them via `winget uninstall` if you don't need them.

## Troubleshooting

**Dashboard doesn't open**
- Check `%LOCALAPPDATA%\SqlDashboard\server.log` and `server.err.log`
- Run manually: `powershell -File "%LOCALAPPDATA%\SqlDashboard\Start-Dashboard.ps1"`

**Connection test fails**
- Verify the SQL Server is reachable: `sqlcmd -S <server> -E -Q "SELECT 1"`
- For Azure SQL Database, check firewall rules for your client IP
- For Entra ID, make sure your account has been granted SQL access to the database

**Port 8765 already in use**
- Kill the previous instance: `powershell -File "%LOCALAPPDATA%\SqlDashboard\Stop-Dashboard.ps1"`

**No data on Azure SQL DB**
- Enable Query Store: `ALTER DATABASE <name> SET QUERY_STORE = ON;`
- Grant your login `VIEW DATABASE STATE` permission
