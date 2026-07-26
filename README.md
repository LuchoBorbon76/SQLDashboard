# SQL Performance Dashboard

Live multi-instance SQL Server performance dashboard powered by DMVs, Query Store, and a small Node.js HTTP server. Supports **on-prem SQL Server**, **Azure SQL Database**, and **Azure SQL Managed Instance**.

Created by **Luis Fernando Borbon** · MIT License

![Dashboard](https://img.shields.io/badge/status-live-brightgreen) ![Windows](https://img.shields.io/badge/platform-Windows-blue) ![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue)

## Features

- 🔴🟡🟢 **Traffic-light health indicator** — instant summary of overall server state
- 📊 **Rich metrics**: Page Life Expectancy, Buffer Cache Hit Ratio, Top Waits, Top Queries (Query Store), Missing Indexes, File I/O Latency, Buffer Pool distribution, TempDB usage, Active Sessions
- 🖱️ **Interactive query detail** — click any Top Query to see full text, execution plan XML, `sp_query_store_force_plan` DDL
- 🛠️ **CREATE INDEX generator** — click any Missing Index to get ready-to-run T-SQL
- 🌐 **Multi-instance sidebar** — switch between servers instantly; inactive servers don't poll
- 🎨 **11 themes** — Clawpilot, Ocean, Emerald, Cyberpunk, Solarized (both light/dark), Nord, High Contrast
- 🔒 **Encrypted credentials** — AES-256-GCM at rest, key wrapped with Windows DPAPI (user-scoped)
- 🔐 **All auth methods** — Windows Integrated, SQL Auth, Entra ID Integrated, Entra ID Password, Entra ID Interactive (MFA)
- ⏸️ **Pause + configurable refresh** — 30s to 30min, persisted per browser
- 🌍 **Friendly URL** — `http://sql-dashboard:8765/` via hosts alias
- 🚀 **Auto-start at logon** — no manual restart after reboot

## Screenshots

_(Add screenshots to `docs/` and reference here)_

## Quick install (Windows)

Download the latest release, or from source:

```powershell
# Clone
git clone https://github.com/LuchoBorbon76/sql-performance-dashboard.git
cd sql-performance-dashboard

# Install dependencies
npm install

# Run
node server.mjs
# Open http://127.0.0.1:8765/
```

## Full installer (recommended)

The `installer/` folder ships a Windows installer that:

- Auto-installs Node.js, ODBC Driver 18, go-sqlcmd via **winget** if missing
- Adds `sql-dashboard` to your hosts file (friendly URL)
- Registers a Task Scheduler job for auto-start at logon
- Creates Start Menu + Desktop shortcuts

```powershell
cd installer
.\install.bat
```

See [installer/README.md](installer/README.md) for options.

## Architecture

```
Browser (index.html)
        │
        ▼  HTTP polling every 30s (configurable)
Node.js HTTP server (server.mjs) :8765
        │
        ▼  Spawns per-request
sqlcmd.exe (ODBC 17/18) or go-sqlcmd (for MFA)
        │
        ▼  Windows Auth / SQL Auth / Entra ID
Target SQL Server / Azure SQL DB / Azure SQL MI
```

- **Node HTTP** serves static HTML and a `/api/metrics?serverId=X` endpoint
- **Metrics collector** runs a single dynamic `FOR JSON PATH` batch against DMVs, returning ~15 KB per snapshot
- **Per-server cache** (4s) prevents hammering when multiple browser tabs are open
- **Client-side per-server cache** shows the last snapshot instantly when switching servers

## Requirements

- Windows 10/11 (Task Scheduler + PowerShell 5.1+)
- Node.js 18 or newer
- Microsoft ODBC Driver 17 or 18 (ships with `sqlcmd`)
- For Entra ID Interactive/MFA: [go-sqlcmd](https://github.com/microsoft/go-sqlcmd) 1.10+

The installer handles all prerequisites automatically via winget.

## Security

Passwords are never stored in plaintext:

1. Server AES key (32 bytes) is generated on first save and wrapped via `System.Security.Cryptography.ProtectedData.Protect(..., 'CurrentUser')` (Windows DPAPI)
2. Wrapped key sits in `.encryption-key`; can't be decrypted by another Windows user or off-machine
3. Each password is AES-256-GCM encrypted with a unique 12-byte IV; format: `enc:v1:<iv>:<tag>:<ciphertext>` (all base64)
4. API responses never include the encrypted or decrypted password — only `hasPassword: true/false`

## Roadmap

- [ ] Trend charts (last N samples per KPI)
- [ ] CSV / JSON snapshot export
- [ ] Alert webhook (Teams, Slack) when health goes Critical
- [ ] Historical persistence (SQLite)
- [ ] Windows Service wrapper (nssm) for shared installs

## Contributing

Issues and PRs welcome. This is a personal project maintained in spare time — no SLA.

## Disclaimer

Provided **as-is**, without warranty of any kind. Not affiliated with or endorsed by Microsoft. Read-only DMV queries; always verify optimizer suggestions before applying to production.

## License

MIT © 2026 Luis Fernando Borbon — see [LICENSE](LICENSE).
