import http from 'node:http';
import { readFile, writeFile, mkdir, access, chmod } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 8765;
const HTML = path.join(__dirname, 'index.html');
const SQLCMD = 'C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\SQLCMD.EXE';
const GO_SQLCMD = 'C:\\Program Files\\SqlCmd\\sqlcmd.exe';
const SERVERS_FILE = path.join(__dirname, 'servers.json');
const KEY_FILE = path.join(__dirname, '.encryption-key');
const TMP_DIR = path.join(__dirname, 'tmp');

// ==============================
// Password encryption at rest (AES-256-GCM),
// with the AES key itself wrapped by Windows DPAPI (CurrentUser scope).
// This binds the key material to the current Windows user account —
// copying servers.json + .encryption-key off this machine will NOT
// let another user decrypt anything.
// ==============================
function dpapiProtect(bytes) {
  return new Promise((resolve, reject) => {
    const ps = [
      '-NoProfile', '-NonInteractive', '-Command',
      "Add-Type -AssemblyName System.Security; " +
      "$in = [Console]::In.ReadToEnd().Trim(); " +
      "$plain = [Convert]::FromBase64String($in); " +
      "$enc = [System.Security.Cryptography.ProtectedData]::Protect($plain, $null, 'CurrentUser'); " +
      "[Convert]::ToBase64String($enc)"
    ];
    const child = execFile('powershell.exe', ps, { timeout: 15000, windowsHide: true, encoding: 'utf8' },
      (err, stdout, stderr) => err ? reject(new Error(`DPAPI protect: ${stderr||err.message}`)) : resolve(stdout.trim()));
    child.stdin.write(bytes.toString('base64'));
    child.stdin.end();
  });
}

function dpapiUnprotect(b64) {
  return new Promise((resolve, reject) => {
    const ps = [
      '-NoProfile', '-NonInteractive', '-Command',
      "Add-Type -AssemblyName System.Security; " +
      "$in = [Console]::In.ReadToEnd().Trim(); " +
      "$enc = [Convert]::FromBase64String($in); " +
      "$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $null, 'CurrentUser'); " +
      "[Convert]::ToBase64String($plain)"
    ];
    const child = execFile('powershell.exe', ps, { timeout: 15000, windowsHide: true, encoding: 'utf8' },
      (err, stdout, stderr) => err ? reject(new Error(`DPAPI unprotect: ${stderr||err.message}`)) : resolve(Buffer.from(stdout.trim(), 'base64')));
    child.stdin.write(b64);
    child.stdin.end();
  });
}

// Key file stores DPAPI-wrapped random 32-byte AES key.
// Header 'dpapi:v1:' marks the format; legacy raw-32-byte key files auto-upgrade.
async function getKey() {
  if (existsSync(KEY_FILE)) {
    const raw = await readFile(KEY_FILE, 'utf8').catch(async () => (await readFile(KEY_FILE)).toString('binary'));
    if (raw.startsWith('dpapi:v1:')) {
      const b64 = raw.slice('dpapi:v1:'.length).trim();
      const bytes = await dpapiUnprotect(b64);
      if (bytes.length !== 32) throw new Error('unwrapped key length invalid');
      return bytes;
    }
    // Legacy: raw 32-byte key on disk. Upgrade to DPAPI wrapping.
    const legacy = await readFile(KEY_FILE);
    if (legacy.length === 32) {
      const wrapped = await dpapiProtect(legacy);
      await writeFile(KEY_FILE, 'dpapi:v1:' + wrapped, 'utf8');
      try { await chmod(KEY_FILE, 0o600); } catch {}
      console.log('Upgraded legacy AES key to DPAPI-wrapped form');
      return legacy;
    }
    throw new Error('Encryption key file is corrupt or unrecognized');
  }
  const k = crypto.randomBytes(32);
  const wrapped = await dpapiProtect(k);
  await writeFile(KEY_FILE, 'dpapi:v1:' + wrapped, 'utf8');
  try { await chmod(KEY_FILE, 0o600); } catch {}
  console.log('Generated new DPAPI-wrapped encryption key at', KEY_FILE);
  return k;
}
let cachedKey = null;
async function key() { if (!cachedKey) cachedKey = await getKey(); return cachedKey; }

async function encryptPassword(plain) {
  if (!plain) return '';
  const k = await key();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', k, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Format: enc:v1:<iv>:<tag>:<ciphertext>  (all base64)
  return `enc:v1:${iv.toString('base64')}:${tag.toString('base64')}:${enc.toString('base64')}`;
}

async function decryptPassword(str) {
  if (!str) return '';
  if (!str.startsWith('enc:v1:')) return String(str); // legacy plaintext
  const [, , ivB, tagB, ctB] = str.split(':');
  const k = await key();
  const decipher = crypto.createDecipheriv('aes-256-gcm', k, Buffer.from(ivB, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB, 'base64'));
  const dec = Buffer.concat([decipher.update(Buffer.from(ctB, 'base64')), decipher.final()]);
  return dec.toString('utf8');
}

await mkdir(TMP_DIR, { recursive: true });

// Sweep tmp/ files older than 1 hour once per hour (hygiene)
setInterval(async () => {
  try {
    const { readdir, stat, unlink } = await import('node:fs/promises');
    const files = await readdir(TMP_DIR);
    const cutoff = Date.now() - 3600000;
    for (const f of files) {
      const p = path.join(TMP_DIR, f);
      try {
        const s = await stat(p);
        if (s.mtimeMs < cutoff) await unlink(p);
      } catch {}
    }
  } catch {}
}, 3600000);

// ---------- Server registry ----------
// On disk servers.json holds `passwordEnc` (AES-256-GCM ciphertext string).
// In memory, `password` is decrypted; `passwordEnc` may still be present.
async function loadServers() {
  try {
    const raw = await readFile(SERVERS_FILE, 'utf8');
    const list = JSON.parse(raw);
    let migrated = false;
    for (const s of list) {
      if (s.password && !s.passwordEnc) {
        s.passwordEnc = await encryptPassword(s.password);
        migrated = true;
      }
      // Strip plaintext key from disk shape (even if empty string)
      if ('password' in s) { delete s.password; migrated = true; }
    }
    if (migrated) await writeFile(SERVERS_FILE, JSON.stringify(list, null, 2), 'utf8');
    return list;
  } catch {
    const seed = [{
      id: 'local-sqlsrv2025ent',
      name: 'Local SQLSRV2025ENT',
      server: 'TABLET-LUISBOR2\\SQLSRV2025ENT',
      auth: 'windows',
      user: '', passwordEnc: '',
      addedAt: new Date().toISOString(),
    }];
    await writeFile(SERVERS_FILE, JSON.stringify(seed, null, 2), 'utf8');
    return seed;
  }
}

async function saveServers(list) {
  // Persist only encrypted form
  const clean = list.map(s => {
    const { password, ...rest } = s;
    return rest;
  });
  await writeFile(SERVERS_FILE, JSON.stringify(clean, null, 2), 'utf8');
}

// Get a runnable copy with password decrypted
async function resolveServer(s) {
  const clone = { ...s };
  clone.password = await decryptPassword(s.passwordEnc);
  return clone;
}

// Return sqlcmd arg list for auth + connection options
// ==============================
// Access token cache for Entra ID Interactive (MFA)
// Acquires an access token ONCE via a PowerShell/Az.Accounts (or MSAL) helper,
// caches it in memory, and reuses across all sqlcmd invocations by passing it via
// SQLCMDACCESSTOKEN + --authentication-method=ActiveDirectoryAccessToken.
// This prevents the browser prompt from firing on every metrics collection.
// ==============================
const tokenCache = new Map();   // serverId -> { token, expiresAt }
const tokenLocks = new Map();   // serverId -> Promise (avoid concurrent acquisitions)

async function acquireEntraToken(cfg) {
  const now = Date.now();
  const cached = tokenCache.get(cfg.id);
  // Renew 5 min before expiry
  if (cached && cached.expiresAt - 300000 > now) return cached.token;
  if (tokenLocks.has(cfg.id)) return tokenLocks.get(cfg.id);

  const p = (async () => {
    // Use Az.Accounts if installed; otherwise fall back to MSAL.PS; otherwise
    // shell out to `az account get-access-token` (requires Azure CLI).
    const psScript = `
$ErrorActionPreference = 'Stop'
$user = '${(cfg.user || '').replace(/'/g, "''")}'
$resource = 'https://database.windows.net/'
try {
  # Prefer Azure CLI (already installed on most dev boxes; supports device code + interactive)
  $azOut = & az account get-access-token --resource $resource 2>$null | ConvertFrom-Json
  if ($azOut -and $azOut.accessToken) {
    Write-Output ("TOKEN::" + $azOut.accessToken)
    Write-Output ("EXPIRES::" + $azOut.expiresOn)
    exit 0
  }
} catch {}
try {
  # Fallback: Az.Accounts module
  Import-Module Az.Accounts -ErrorAction Stop -DisableNameChecking
  $ctx = Get-AzContext -ErrorAction SilentlyContinue
  if (-not $ctx) { Connect-AzAccount -ErrorAction Stop | Out-Null }
  $t = Get-AzAccessToken -ResourceUrl $resource -ErrorAction Stop
  Write-Output ("TOKEN::" + $t.Token)
  Write-Output ("EXPIRES::" + $t.ExpiresOn.UtcDateTime.ToString('o'))
  exit 0
} catch {
  Write-Error ("Token acquisition failed: " + $_.Exception.Message)
  exit 1
}
`;
    const scriptFile = path.join(TMP_DIR, `token-${cfg.id}.ps1`);
    await writeFile(scriptFile, psScript, 'utf8');
    return new Promise((resolve, reject) => {
      execFile('powershell.exe',
        ['-NoProfile','-ExecutionPolicy','Bypass','-File', scriptFile],
        { timeout: 180000, windowsHide: false, encoding: 'utf8' },  // Show window so MFA popup works
        (err, stdout, stderr) => {
          if (err) return reject(new Error(`Token acquire failed: ${(stderr||err.message).slice(0,300)}`));
          const tokMatch = stdout.match(/TOKEN::(.+)/);
          const expMatch = stdout.match(/EXPIRES::(.+)/);
          if (!tokMatch) return reject(new Error(`No token in output: ${stdout.slice(0,300)}`));
          const token = tokMatch[1].trim();
          const expIso = expMatch ? expMatch[1].trim() : null;
          const expiresAt = expIso ? new Date(expIso).getTime() : (Date.now() + 3300000); // 55 min fallback
          tokenCache.set(cfg.id, { token, expiresAt });
          console.log(`Acquired Entra token for ${cfg.id} (expires ${new Date(expiresAt).toISOString()})`);
          resolve(token);
        });
    });
  })();
  tokenLocks.set(cfg.id, p);
  try { return await p; } finally { tokenLocks.delete(cfg.id); }
}

function invalidateToken(cfg) { tokenCache.delete(cfg.id); }

function buildSqlcmdArgs(cfg, extraArgs = [], opts = {}) {
  const args = ['-S', cfg.server];
  switch (cfg.auth) {
    case 'windows': args.push('-E'); break;
    case 'sqlauth': args.push('-U', cfg.user, '-P', cfg.password); break;
    case 'azuread-integrated':
      args.push('--authentication-method=ActiveDirectoryIntegrated');
      if (cfg.user) args.push('-U', cfg.user);
      break;
    case 'azuread-password': args.push('-G', '-U', cfg.user, '-P', cfg.password); break;
    case 'azuread-interactive':
      if (opts.useAccessToken) {
        // Token supplied via SQLCMDACCESSTOKEN env var - no prompt, no user needed
        args.push('--authentication-method=ActiveDirectoryAccessToken');
      } else {
        args.push('--authentication-method=ActiveDirectoryInteractive');
        if (cfg.user) args.push('-U', cfg.user);
      }
      break;
    default: args.push('-E');
  }
  if (cfg.database) args.push('-d', cfg.database);
  if (cfg.encrypt !== false) args.push('-N');
  if (cfg.trustCert !== false) args.push('-C');
  return args.concat(extraArgs);
}

// Use go-sqlcmd for any Entra Integrated OR Interactive (both use --authentication-method flag)
function pickSqlcmd(cfg) {
  if (cfg.auth === 'azuread-integrated' || cfg.auth === 'azuread-interactive') return GO_SQLCMD;
  return SQLCMD;
}

// ---------- SQL batch ----------
const WAIT_EXCLUDES = [
  'CLR_SEMAPHORE','LAZYWRITER_SLEEP','RESOURCE_QUEUE','SLEEP_TASK','SLEEP_SYSTEMTASK',
  'SQLTRACE_BUFFER_FLUSH','WAITFOR','LOGMGR_QUEUE','CHECKPOINT_QUEUE','REQUEST_FOR_DEADLOCK_SEARCH',
  'XE_TIMER_EVENT','BROKER_TO_FLUSH','BROKER_TASK_STOP','CLR_MANUAL_EVENT','CLR_AUTO_EVENT',
  'DISPATCHER_QUEUE_SEMAPHORE','FT_IFTS_SCHEDULER_IDLE_WAIT','XE_DISPATCHER_WAIT','XE_DISPATCHER_JOIN',
  'BROKER_EVENTHANDLER','TRACEWRITE','FT_IFTSHC_MUTEX','SQLTRACE_INCREMENTAL_FLUSH_SLEEP',
  'BROKER_RECEIVE_WAITFOR','ONDEMAND_TASK_QUEUE','DBMIRROR_EVENTS_QUEUE','DBMIRRORING_CMD',
  'BROKER_TRANSMITTER','SQLTRACE_WAIT_ENTRIES','SLEEP_BPOOL_FLUSH','HADR_FILESTREAM_IOMGR_IOCOMPLETION',
  'DIRTY_PAGE_POLL','SP_SERVER_DIAGNOSTICS_SLEEP','QDS_PERSIST_TASK_MAIN_LOOP_SLEEP','QDS_ASYNC_QUEUE',
  'QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP','QDS_SHUTDOWN_QUEUE','PARALLEL_REDO_WORKER_WAIT_WORK',
  'PARALLEL_REDO_DRAIN_WORKER','PARALLEL_REDO_LOG_CACHE','PARALLEL_REDO_TRAN_LIST','PARALLEL_REDO_WORKER_SYNC',
  'PREEMPTIVE_XE_GETTARGETSTATE','HADR_LOGCAPTURE_WAIT','HADR_TIMER_TASK','HADR_WORK_QUEUE',
].map(w => `'${w}'`).join(',');

// ==============================
// Engine detection + Azure SQL DB variant
// ==============================
// Engine edition:
//   1 = Personal, 2 = Standard, 3 = Enterprise (on-prem)
//   4 = Express, 5 = Azure SQL Database, 6 = Azure Synapse, 8 = Azure SQL Managed Instance,
//   9 = Azure SQL Edge, 11 = Azure Synapse Serverless
function isAzureSqlDb(cfg) { return Number(cfg.engineEdition) === 5; }
function isAzureManagedInstance(cfg) { return Number(cfg.engineEdition) === 8; }
// Fallback: if engineEdition not cached yet, probe by hostname (best-effort)
function looksAzureHost(cfg) { return /\.database\.windows\.net$/i.test((cfg.server||'').trim()); }
function isAzureDbLike(cfg) {
  if (cfg.engineEdition) return isAzureSqlDb(cfg);
  return looksAzureHost(cfg); // Assume DB by default; MI users should re-probe
}

// Azure SQL Database has a different DMV surface. Sections not available on
// Azure return JSON null so the UI grays them out.
const MEGA_SQL_AZURE = `
SET NOCOUNT ON;
SET ANSI_WARNINGS OFF;

DECLARE @topq NVARCHAR(MAX) = N'[]';
BEGIN TRY
  DECLARE @tmp NVARCHAR(MAX);
  SELECT @tmp = (
    SELECT TOP 15 DB_NAME() AS db_name, q.query_id, SUM(rs.count_executions) AS execs,
      CAST(SUM(rs.avg_cpu_time*rs.count_executions)/1000.0 AS DECIMAL(18,1)) AS total_cpu_ms,
      CAST(AVG(rs.avg_cpu_time)/1000.0 AS DECIMAL(18,1)) AS avg_cpu_ms,
      CAST(AVG(rs.avg_duration)/1000.0 AS DECIMAL(18,1)) AS avg_dur_ms,
      CAST(AVG(rs.avg_logical_io_reads) AS BIGINT) AS avg_reads,
      MAX(rs.last_execution_time) AS last_exec,
      LEFT(REPLACE(REPLACE(REPLACE(qt.query_sql_text,CHAR(13),' '),CHAR(10),' '),CHAR(9),' '),300) AS query_text
    FROM sys.query_store_query q
    JOIN sys.query_store_query_text qt ON q.query_text_id=qt.query_text_id
    JOIN sys.query_store_plan p ON p.query_id=q.query_id
    JOIN sys.query_store_runtime_stats rs ON rs.plan_id=p.plan_id
    GROUP BY q.query_id, qt.query_sql_text
    ORDER BY total_cpu_ms DESC
    FOR JSON PATH);
  IF @tmp IS NOT NULL SET @topq = @tmp;
END TRY BEGIN CATCH SET @topq = N'[]'; END CATCH;

SELECT
  JSON_QUERY((SELECT
     @@SERVERNAME AS server_name,
     CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(64)) AS product_version,
     CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)) AS edition,
     CAST(ISNULL(SERVERPROPERTY('ProductLevel'),'') AS NVARCHAR(32)) AS product_level,
     CAST(SERVERPROPERTY('EngineEdition') AS INT) AS engine_edition,
     NULL AS sqlserver_start_time,
     NULL AS uptime_min,
     (SELECT TOP 1 avg_cpu_percent FROM sys.dm_db_resource_stats ORDER BY end_time DESC) AS avg_cpu_percent,
     (SELECT TOP 1 avg_memory_usage_percent FROM sys.dm_db_resource_stats ORDER BY end_time DESC) AS avg_memory_percent,
     (SELECT TOP 1 avg_data_io_percent FROM sys.dm_db_resource_stats ORDER BY end_time DESC) AS avg_data_io_percent,
     (SELECT TOP 1 avg_log_write_percent FROM sys.dm_db_resource_stats ORDER BY end_time DESC) AS avg_log_write_percent,
     (SELECT COUNT(*) FROM sys.dm_exec_connections) AS connections,
     (SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process=1) AS user_sessions,
     (SELECT COUNT(*) FROM sys.dm_exec_requests WHERE session_id > 50) AS active_requests,
     (SELECT COUNT(*) FROM sys.dm_exec_requests WHERE blocking_session_id <> 0) AS blocked_requests
   FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)) AS instance,
  JSON_QUERY((SELECT DB_NAME() AS name, 'ONLINE' AS state, 'FULL' AS recovery,
     CAST(DATABASEPROPERTYEX(DB_NAME(),'Version') AS INT) AS compat,
     CAST(SUM(CASE WHEN type=0 THEN size END)*8.0/1024 AS DECIMAL(18,1)) AS data_mb,
     CAST(SUM(CASE WHEN type=1 THEN size END)*8.0/1024 AS DECIMAL(18,1)) AS log_mb,
     NULL AS last_full_backup, NULL AS last_log_backup,
     (SELECT CAST(actual_state AS INT) FROM sys.database_query_store_options) AS qs_on
   FROM sys.database_files
   FOR JSON PATH)) AS databases,
  JSON_QUERY((SELECT TOP 12 wait_type,
     CAST(wait_time_ms/1000.0 AS DECIMAL(18,3)) AS wait_time_s,
     waiting_tasks_count AS tasks,
     CAST(wait_time_ms*1.0/NULLIF(waiting_tasks_count,0) AS DECIMAL(18,2)) AS avg_wait_ms,
     CAST(signal_wait_time_ms/1000.0 AS DECIMAL(18,3)) AS signal_wait_s
   FROM sys.dm_db_wait_stats
   WHERE waiting_tasks_count > 0
     AND wait_type NOT IN ('CLR_SEMAPHORE','LAZYWRITER_SLEEP','SLEEP_TASK','SLEEP_SYSTEMTASK',
       'WAITFOR','LOGMGR_QUEUE','CHECKPOINT_QUEUE','REQUEST_FOR_DEADLOCK_SEARCH',
       'XE_TIMER_EVENT','BROKER_TO_FLUSH','BROKER_TASK_STOP','SLEEP_BPOOL_FLUSH',
       'DIRTY_PAGE_POLL','SP_SERVER_DIAGNOSTICS_SLEEP','QDS_PERSIST_TASK_MAIN_LOOP_SLEEP',
       'QDS_ASYNC_QUEUE','QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP',
       'QDS_SHUTDOWN_QUEUE','BROKER_RECEIVE_WAITFOR','SQLTRACE_INCREMENTAL_FLUSH_SLEEP',
       'FT_IFTS_SCHEDULER_IDLE_WAIT','XE_DISPATCHER_WAIT','XE_DISPATCHER_JOIN')
   ORDER BY wait_time_ms DESC
   FOR JSON PATH)) AS waits,
  JSON_QUERY((SELECT TOP 15 DB_NAME() AS db_name, mf.name AS logical_name, mf.type_desc AS file_type,
     CAST(f.size_on_disk_bytes/1024.0/1024 AS DECIMAL(18,1)) AS size_mb,
     f.num_of_reads AS reads, f.num_of_writes AS writes,
     f.io_stall_read_ms AS read_stall_ms, f.io_stall_write_ms AS write_stall_ms,
     CAST(f.io_stall_read_ms*1.0/NULLIF(f.num_of_reads,0) AS DECIMAL(18,2)) AS avg_read_latency_ms,
     CAST(f.io_stall_write_ms*1.0/NULLIF(f.num_of_writes,0) AS DECIMAL(18,2)) AS avg_write_latency_ms
   FROM sys.dm_io_virtual_file_stats(DB_ID(),NULL) f
   JOIN sys.database_files mf ON f.file_id=mf.file_id
   ORDER BY (f.io_stall_read_ms + f.io_stall_write_ms) DESC
   FOR JSON PATH)) AS file_io,
  CAST(NULL AS NVARCHAR(MAX)) AS buffer_pool,
  JSON_QUERY(@topq) AS top_queries,
  JSON_QUERY((SELECT TOP 15 DB_NAME() AS db_name,
     OBJECT_SCHEMA_NAME(mid.object_id) AS schema_name,
     OBJECT_NAME(mid.object_id) AS table_name,
     migs.user_seeks + migs.user_scans AS user_impact_count,
     CAST(migs.avg_total_user_cost*(migs.avg_user_impact/100.0)*(migs.user_seeks+migs.user_scans) AS BIGINT) AS improvement_score,
     ISNULL(mid.equality_columns,'') AS eq_cols,
     ISNULL(mid.inequality_columns,'') AS ineq_cols,
     ISNULL(mid.included_columns,'') AS included_cols
   FROM sys.dm_db_missing_index_groups mig
   JOIN sys.dm_db_missing_index_group_stats migs ON mig.index_group_handle = migs.group_handle
   JOIN sys.dm_db_missing_index_details mid ON mig.index_handle = mid.index_handle
   WHERE mid.database_id = DB_ID()
   ORDER BY improvement_score DESC
   FOR JSON PATH)) AS missing_indexes,
  JSON_QUERY((SELECT TOP 20 s.session_id, s.login_name, s.host_name, s.program_name,
     r.status, r.command, r.wait_type, r.wait_time AS wait_ms, r.blocking_session_id AS blocked_by,
     DB_NAME(r.database_id) AS db_name,
     LEFT(REPLACE(REPLACE(REPLACE(st.text,CHAR(13),' '),CHAR(10),' '),CHAR(9),' '),200) AS query_text
   FROM sys.dm_exec_sessions s
   JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
   OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) st
   WHERE s.is_user_process = 1 AND s.session_id <> @@SPID
   ORDER BY r.total_elapsed_time DESC
   FOR JSON PATH)) AS active,
  CAST(NULL AS NVARCHAR(MAX)) AS tempdb
FOR JSON PATH, WITHOUT_ARRAY_WRAPPER;
`;

// On-prem MEGA batch below (existing)
const MEGA_SQL = `
SET NOCOUNT ON;
SELECT
  JSON_QUERY((SELECT
     @@SERVERNAME AS server_name,
     CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(64)) AS product_version,
     CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)) AS edition,
     CAST(ISNULL(SERVERPROPERTY('ProductLevel'),'') AS NVARCHAR(32)) AS product_level,
     (SELECT sqlserver_start_time FROM sys.dm_os_sys_info) AS sqlserver_start_time,
     DATEDIFF(MINUTE,(SELECT sqlserver_start_time FROM sys.dm_os_sys_info),GETDATE()) AS uptime_min,
     (SELECT cpu_count FROM sys.dm_os_sys_info) AS cpu_count,
     (SELECT physical_memory_kb/1024 FROM sys.dm_os_sys_info) AS physical_memory_mb,
     (SELECT committed_target_kb/1024 FROM sys.dm_os_sys_info) AS target_memory_mb,
     (SELECT physical_memory_in_use_kb/1024 FROM sys.dm_os_process_memory) AS memory_in_use_mb,
     (SELECT COUNT(*) FROM sys.dm_exec_connections) AS connections,
     (SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process=1) AS user_sessions,
     (SELECT COUNT(*) FROM sys.dm_exec_requests WHERE session_id > 50) AS active_requests,
     (SELECT COUNT(*) FROM sys.dm_exec_requests WHERE blocking_session_id <> 0) AS blocked_requests,
     ISNULL((SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name='Page life expectancy' AND object_name LIKE '%Buffer Manager%'),0) AS page_life_expectancy,
     ISNULL((SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name='Batch Requests/sec'),0) AS batch_requests_per_sec_cum,
     ISNULL((SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name='SQL Compilations/sec'),0) AS compilations_cum,
     ISNULL((SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name='Buffer cache hit ratio'),0) AS buffer_cache_hit_ratio,
     ISNULL((SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name='Buffer cache hit ratio base'),0) AS buffer_cache_hit_ratio_base
   FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)) AS instance,
  JSON_QUERY((SELECT d.name, d.state_desc AS state, d.recovery_model_desc AS recovery, d.compatibility_level AS compat,
     CAST(SUM(CASE WHEN f.type=0 THEN f.size END)*8.0/1024 AS DECIMAL(18,1)) AS data_mb,
     CAST(SUM(CASE WHEN f.type=1 THEN f.size END)*8.0/1024 AS DECIMAL(18,1)) AS log_mb,
     (SELECT MAX(backup_finish_date) FROM msdb.dbo.backupset b WHERE b.database_name=d.name AND b.type='D') AS last_full_backup,
     (SELECT MAX(backup_finish_date) FROM msdb.dbo.backupset b WHERE b.database_name=d.name AND b.type='L') AS last_log_backup,
     CAST(d.is_query_store_on AS INT) AS qs_on
   FROM sys.databases d JOIN sys.master_files f ON d.database_id=f.database_id
   GROUP BY d.name, d.state_desc, d.recovery_model_desc, d.compatibility_level, d.is_query_store_on
   ORDER BY d.name
   FOR JSON PATH)) AS databases,
  JSON_QUERY((SELECT TOP 12 wait_type,
     CAST(wait_time_ms/1000.0 AS DECIMAL(18,3)) AS wait_time_s,
     waiting_tasks_count AS tasks,
     CAST(wait_time_ms*1.0/NULLIF(waiting_tasks_count,0) AS DECIMAL(18,2)) AS avg_wait_ms,
     CAST(signal_wait_time_ms/1000.0 AS DECIMAL(18,3)) AS signal_wait_s
   FROM sys.dm_os_wait_stats
   WHERE wait_type NOT IN (${WAIT_EXCLUDES}) AND waiting_tasks_count > 0
   ORDER BY wait_time_ms DESC
   FOR JSON PATH)) AS waits,
  JSON_QUERY((SELECT TOP 15 DB_NAME(f.database_id) AS db_name, mf.name AS logical_name, mf.type_desc AS file_type,
     CAST(f.size_on_disk_bytes/1024.0/1024 AS DECIMAL(18,1)) AS size_mb,
     f.num_of_reads AS reads, f.num_of_writes AS writes,
     f.io_stall_read_ms AS read_stall_ms, f.io_stall_write_ms AS write_stall_ms,
     CAST(f.io_stall_read_ms*1.0/NULLIF(f.num_of_reads,0) AS DECIMAL(18,2)) AS avg_read_latency_ms,
     CAST(f.io_stall_write_ms*1.0/NULLIF(f.num_of_writes,0) AS DECIMAL(18,2)) AS avg_write_latency_ms
   FROM sys.dm_io_virtual_file_stats(NULL,NULL) f
   JOIN sys.master_files mf ON f.database_id=mf.database_id AND f.file_id=mf.file_id
   ORDER BY (f.io_stall_read_ms + f.io_stall_write_ms) DESC
   FOR JSON PATH)) AS file_io,
  JSON_QUERY((SELECT DB_NAME(database_id) AS db_name, COUNT_BIG(*)*8/1024 AS buffer_mb
   FROM sys.dm_os_buffer_descriptors WHERE database_id <> 32767
   GROUP BY database_id ORDER BY COUNT_BIG(*) DESC
   FOR JSON PATH)) AS buffer_pool,
  JSON_QUERY((SELECT TOP 15 DB_NAME(mid.database_id) AS db_name,
     OBJECT_SCHEMA_NAME(mid.object_id, mid.database_id) AS schema_name,
     OBJECT_NAME(mid.object_id, mid.database_id) AS table_name,
     migs.user_seeks + migs.user_scans AS user_impact_count,
     CAST(migs.avg_total_user_cost*(migs.avg_user_impact/100.0)*(migs.user_seeks+migs.user_scans) AS BIGINT) AS improvement_score,
     ISNULL(mid.equality_columns,'') AS eq_cols,
     ISNULL(mid.inequality_columns,'') AS ineq_cols,
     ISNULL(mid.included_columns,'') AS included_cols
   FROM sys.dm_db_missing_index_groups mig
   JOIN sys.dm_db_missing_index_group_stats migs ON mig.index_group_handle = migs.group_handle
   JOIN sys.dm_db_missing_index_details mid ON mig.index_handle = mid.index_handle
   WHERE mid.database_id > 4
   ORDER BY improvement_score DESC
   FOR JSON PATH)) AS missing_indexes,
  JSON_QUERY((SELECT TOP 20 s.session_id, s.login_name, s.host_name, s.program_name,
     r.status, r.command, r.wait_type, r.wait_time AS wait_ms, r.blocking_session_id AS blocked_by,
     DB_NAME(r.database_id) AS db_name,
     LEFT(REPLACE(REPLACE(st.text,CHAR(13),' '),CHAR(10),' '),200) AS query_text
   FROM sys.dm_exec_sessions s
   JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
   OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) st
   WHERE s.is_user_process = 1 AND s.session_id <> @@SPID
   ORDER BY r.total_elapsed_time DESC
   FOR JSON PATH)) AS active,
  JSON_QUERY((SELECT
     SUM(user_object_reserved_page_count)*8/1024 AS user_obj_mb,
     SUM(internal_object_reserved_page_count)*8/1024 AS internal_obj_mb,
     SUM(version_store_reserved_page_count)*8/1024 AS version_store_mb,
     SUM(unallocated_extent_page_count)*8/1024 AS free_mb
   FROM tempdb.sys.dm_db_file_space_usage
   FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)) AS tempdb
FOR JSON PATH, WITHOUT_ARRAY_WRAPPER;
`;

// Separate Query Store batch - can be slow, fetched with own timeout, doesn't block main metrics
const TOP_QUERIES_SQL = `
SET NOCOUNT ON;
DECLARE @topqSql NVARCHAR(MAX)=N'';
SELECT @topqSql = @topqSql + '
UNION ALL
SELECT TOP 8 '''+d.name+''' AS db_name, q.query_id, SUM(rs.count_executions) AS execs,
   CAST(SUM(rs.avg_cpu_time*rs.count_executions)/1000.0 AS DECIMAL(18,1)) AS total_cpu_ms,
   CAST(AVG(rs.avg_cpu_time)/1000.0 AS DECIMAL(18,1)) AS avg_cpu_ms,
   CAST(AVG(rs.avg_duration)/1000.0 AS DECIMAL(18,1)) AS avg_dur_ms,
   CAST(AVG(rs.avg_logical_io_reads) AS BIGINT) AS avg_reads,
   MAX(rs.last_execution_time) AS last_exec,
   LEFT(REPLACE(REPLACE(qt.query_sql_text,CHAR(13),'' ''),CHAR(10),'' ''),300) AS query_text
FROM ['+d.name+'].sys.query_store_query q
JOIN ['+d.name+'].sys.query_store_query_text qt ON q.query_text_id=qt.query_text_id
JOIN ['+d.name+'].sys.query_store_plan p ON p.query_id=q.query_id
JOIN ['+d.name+'].sys.query_store_runtime_stats rs ON rs.plan_id=p.plan_id
GROUP BY q.query_id, qt.query_sql_text
ORDER BY total_cpu_ms DESC'
FROM sys.databases d
WHERE d.database_id > 4 AND d.state_desc='ONLINE' AND d.is_query_store_on=1;

DECLARE @topq NVARCHAR(MAX) = N'[]';
IF LEN(@topqSql) > 0
BEGIN
  DECLARE @wrapped NVARCHAR(MAX) = N'SELECT @out = (SELECT TOP 15 * FROM (' + STUFF(@topqSql,1,11,N'') + N') x ORDER BY total_cpu_ms DESC FOR JSON PATH)';
  DECLARE @tmp NVARCHAR(MAX);
  EXEC sp_executesql @wrapped, N'@out NVARCHAR(MAX) OUTPUT', @out=@tmp OUTPUT;
  IF @tmp IS NOT NULL SET @topq = @tmp;
END
SELECT JSON_QUERY(@topq) AS top_queries FOR JSON PATH, WITHOUT_ARRAY_WRAPPER;
`;

// ---------- Collector ----------
async function ensureSqlFile() {
  const p = path.join(__dirname, '_metrics.sql');
  await writeFile(p, MEGA_SQL, 'utf8');
  const pa = path.join(__dirname, '_metrics_azure.sql');
  await writeFile(pa, MEGA_SQL_AZURE, 'utf8');
  const tp = path.join(__dirname, '_topqueries.sql');
  await writeFile(tp, TOP_QUERIES_SQL, 'utf8');
  return { megaPath: p, megaAzurePath: pa, topqPath: tp };
}
let sqlPaths = null;

// Run a sqlcmd script, return parsed JSON (or throw).
// For Entra Interactive auth, acquires an access token once (cached) so the
// browser prompt only appears the first time — not on every collection.
async function runSqlcmdJson(cfg, scriptPath, tag, timeoutSec) {
  const outFile = path.join(TMP_DIR, `${tag}-${cfg.id}.out`);

  let accessToken = null;
  if (cfg.auth === 'azuread-interactive') {
    accessToken = await acquireEntraToken(cfg);
  }

  const args = buildSqlcmdArgs(cfg, [
    '-l', '10', '-t', String(timeoutSec),
    '-y', '0', '-Y', '0',
    '-w', '65535',
    '-i', scriptPath, '-o', outFile,
  ], { useAccessToken: !!accessToken });

  const env = { ...process.env };
  if (accessToken) env.SQLCMDACCESSTOKEN = accessToken;

  try {
    await new Promise((resolve, reject) => {
      execFile(pickSqlcmd(cfg), args, { timeout: (timeoutSec + 5) * 1000, windowsHide: true, encoding: 'utf8', env },
        (err, stdout, stderr) => {
          if (err) return reject(new Error(`sqlcmd ${tag} failed: ${err.message}\nSTDERR: ${(stderr||'').slice(0,400)}`));
          resolve();
        });
    });
  } catch (e) {
    // If token was rejected, invalidate cache so next call re-prompts
    if (accessToken && /token|authenticat|expire/i.test(e.message)) invalidateToken(cfg);
    throw e;
  }

  const raw = await readFile(outFile, 'utf8');
  const firstBrace = Math.min(...[raw.indexOf('{'), raw.indexOf('[')].filter(i => i >= 0));
  if (firstBrace < 0) throw new Error(`sqlcmd ${tag} returned no JSON: ${raw.slice(0,200)}`);
  let trimmed = raw.slice(firstBrace).trim();
  const strippedOnce = trimmed.replace(/\r?\n/g, '');
  try {
    return JSON.parse(trimmed);
  } catch (e) {
    try { return JSON.parse(strippedOnce); }
    catch (e2) { throw new Error(`Parse ${tag} failed: ${e.message}\nFirst 300: ${trimmed.slice(0,300)}`); }
  }
}

async function collectFor(cfg) {
  if (!sqlPaths) sqlPaths = await ensureSqlFile();
  const started = Date.now();

  // If engineEdition unknown, probe now so we route to the right batch.
  if (!cfg.engineEdition) {
    try {
      const edition = await probeEngineEdition(cfg);
      cfg.engineEdition = edition;
      // Persist so we don't re-probe every collection
      const list = await loadServers();
      const idx = list.findIndex(s => s.id === cfg.id);
      if (idx >= 0) { list[idx].engineEdition = edition; await saveServers(list); }
    } catch (e) { /* fall back to hostname sniffing */ }
  }

  const useAzureDbBatch = isAzureSqlDb(cfg) || (!cfg.engineEdition && isAzureDbLike(cfg));
  const engineLabel = isAzureSqlDb(cfg) ? 'azure-sqldb'
                    : isAzureManagedInstance(cfg) ? 'azure-mi'
                    : useAzureDbBatch ? 'azure-sqldb'
                    : 'onprem';

  let mainData, topqData;
  if (useAzureDbBatch) {
    mainData = await runSqlcmdJson(cfg, sqlPaths.megaAzurePath, 'metrics-azure', 45);
    topqData = { top_queries: mainData.top_queries || [] };
  } else {
    // On-prem AND Azure SQL Managed Instance share the same DMV surface
    [mainData, topqData] = await Promise.all([
      runSqlcmdJson(cfg, sqlPaths.megaPath, 'metrics', 45),
      runSqlcmdJson(cfg, sqlPaths.topqPath, 'topq', 45).catch(err => {
        console.error(`Top queries failed for ${cfg.id}: ${err.message}`);
        return { top_queries: [] };
      }),
    ]);
  }

  const data = { ...mainData };
  data.top_queries = topqData.top_queries || mainData.top_queries || [];
  data.generated_at = new Date().toISOString();
  data.collect_ms = Date.now() - started;
  data.server_id = cfg.id;
  data.server_name_config = cfg.name;
  data.engine = engineLabel;
  data.engine_edition = cfg.engineEdition;
  data.databases ??= [];
  data.waits ??= [];
  data.file_io ??= [];
  data.missing_indexes ??= [];
  data.active ??= [];
  data.instance ??= {};
  if (data.buffer_pool === undefined) data.buffer_pool = [];
  if (data.tempdb === undefined || (useAzureDbBatch && (!data.tempdb || Object.keys(data.tempdb).length === 0))) {
    data.tempdb = useAzureDbBatch ? null : {};
  }
  return data;
}

async function probeEngineEdition(cfg) {
  let accessToken = null;
  if (cfg.auth === 'azuread-interactive') accessToken = await acquireEntraToken(cfg);
  const args = buildSqlcmdArgs(cfg, ['-l','10','-t','15','-h','-1','-W','-Q','SELECT CAST(SERVERPROPERTY(\'EngineEdition\') AS INT) AS e'], { useAccessToken: !!accessToken });
  const env = { ...process.env }; if (accessToken) env.SQLCMDACCESSTOKEN = accessToken;
  return new Promise((resolve, reject) => {
    execFile(pickSqlcmd(cfg), args, { timeout: 20000, windowsHide: true, encoding: 'utf8', env },
      (err, stdout) => {
        if (err) return reject(err);
        const m = stdout.match(/(\d+)/);
        resolve(m ? Number(m[1]) : null);
      });
  });
}

async function testConnection(cfg) {
  let accessToken = null;
  if (cfg.auth === 'azuread-interactive') {
    // For test connection, allow the initial popup to happen if no token cached
    try { accessToken = await acquireEntraToken(cfg); }
    catch (e) { return { ok: false, error: 'Token acquisition failed: ' + e.message.slice(0,400) }; }
  }
  const args = buildSqlcmdArgs(cfg, [
    '-l', '60', '-t', '60',
    '-h', '-1',
    '-Q', 'SELECT 1',
  ], { useAccessToken: !!accessToken });
  const env = { ...process.env }; if (accessToken) env.SQLCMDACCESSTOKEN = accessToken;
  const needsUi = cfg.auth === 'azuread-interactive' && !accessToken;
  return new Promise((resolve) => {
    execFile(pickSqlcmd(cfg), args, { timeout: needsUi ? 180000 : 30000, windowsHide: !needsUi, encoding: 'utf8', env },
      (err, stdout, stderr) => {
        if (err) {
          const parts = [];
          if (stderr && stderr.trim()) parts.push('STDERR: ' + stderr.trim());
          if (stdout && stdout.trim()) parts.push('STDOUT: ' + stdout.trim());
          if (err.killed) parts.push(needsUi ? '(timed out — did you complete the MFA popup?)' : '(process timed out)');
          if (parts.length === 0) parts.push(err.message);
          resolve({ ok: false, error: parts.join(' | ').slice(0, 900) });
        } else resolve({ ok: true });
      });
  });
}

// ---------- Cache per server ----------
const cache = new Map(); // serverId -> { at, data }
const CACHE_MS = 4000;

// ---------- HTTP request body parser ----------
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', c => body += c);
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}

// Public view of a server (never leaks password or ciphertext)
function publicView(cfg) {
  const { password, passwordEnc, ...rest } = cfg;
  return { ...rest, hasPassword: !!(password || passwordEnc) };
}

// ---------- HTTP server ----------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;

    if (p === '/' || p === '/index.html') {
      const html = await readFile(HTML, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    if (p === '/api/servers' && req.method === 'GET') {
      const list = await loadServers();
      return json(res, 200, list.map(publicView));
    }

    if (p === '/api/servers' && req.method === 'POST') {
      const body = await readBody(req);
      if (!body.name || !body.server || !body.auth) return json(res, 400, { error: 'name, server, auth required' });
      const plainPw = body.password || '';
      const cfg = {
        id: body.id || (body.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-' + crypto.randomBytes(2).toString('hex')),
        name: body.name.slice(0, 60),
        server: body.server.slice(0, 200),
        auth: body.auth,
        user: body.user || '',
        password: plainPw, // in-memory only for the test call
        database: body.database || '',
        encrypt: body.encrypt !== false,
        trustCert: body.trustCert !== false,
        addedAt: new Date().toISOString(),
      };
      const t = await testConnection(cfg);
      if (!t.ok) return json(res, 400, { error: 'Connection test failed: ' + t.error });
      try { cfg.engineEdition = await probeEngineEdition(cfg); } catch { /* non-fatal */ }
      const list = await loadServers();
      if (list.find(s => s.id === cfg.id)) return json(res, 400, { error: 'ID exists' });
      // Encrypt password before persisting; strip plaintext.
      cfg.passwordEnc = await encryptPassword(plainPw);
      delete cfg.password;
      list.push(cfg);
      await saveServers(list);
      return json(res, 200, publicView(cfg));
    }

    if (p.startsWith('/api/servers/') && req.method === 'DELETE') {
      const id = p.substring('/api/servers/'.length);
      const list = await loadServers();
      const idx = list.findIndex(s => s.id === id);
      if (idx < 0) return json(res, 404, { error: 'not found' });
      list.splice(idx, 1);
      await saveServers(list);
      cache.delete(id);
      return json(res, 200, { ok: true });
    }

    if (p === '/api/metrics' && req.method === 'GET') {
      const id = url.searchParams.get('serverId');
      const list = await loadServers();
      const cfgStored = id ? list.find(s => s.id === id) : list[0];
      if (!cfgStored) return json(res, 404, { error: 'No server configured' });
      const now = Date.now();
      const c = cache.get(cfgStored.id);
      if (c && (now - c.at) < CACHE_MS) return json(res, 200, c.data);
      const cfg = await resolveServer(cfgStored);
      const data = await collectFor(cfg);
      // If engineEdition was newly probed inside collectFor, persist it
      if (cfg.engineEdition && cfgStored.engineEdition !== cfg.engineEdition) {
        cfgStored.engineEdition = cfg.engineEdition;
        await saveServers(list);
      }
      cache.set(cfgStored.id, { at: Date.now(), data });
      return json(res, 200, data);
    }

    if (p === '/api/query-detail' && req.method === 'GET') {
      const id = url.searchParams.get('serverId');
      const db = url.searchParams.get('db');
      const qid = url.searchParams.get('queryId');
      if (!id || !db || !qid) return json(res, 400, { error: 'serverId, db, queryId required' });
      const list = await loadServers();
      const stored = list.find(s => s.id === id);
      if (!stored) return json(res, 404, { error: 'server not found' });
      const cfg = await resolveServer(stored);
      if (!/^[A-Za-z0-9_\- ]+$/.test(db)) return json(res, 400, { error: 'invalid db name' });
      if (!/^\d+$/.test(qid)) return json(res, 400, { error: 'invalid queryId' });
      const sql = `
SET NOCOUNT ON;
SELECT
  JSON_QUERY((SELECT
     q.query_id, qt.query_sql_text,
     CAST(p.query_plan AS NVARCHAR(MAX)) AS query_plan,
     p.plan_id, p.query_plan_hash, p.is_forced_plan, p.compatibility_level,
     rs.avg_cpu_time, rs.avg_duration, rs.avg_logical_io_reads, rs.avg_physical_io_reads,
     rs.count_executions, rs.last_execution_time, rs.first_execution_time,
     rs.avg_rowcount, rs.avg_dop, rs.avg_query_max_used_memory
   FROM [${db}].sys.query_store_query q
   JOIN [${db}].sys.query_store_query_text qt ON q.query_text_id=qt.query_text_id
   JOIN [${db}].sys.query_store_plan p ON p.query_id=q.query_id
   OUTER APPLY (SELECT TOP 1 * FROM [${db}].sys.query_store_runtime_stats WHERE plan_id=p.plan_id ORDER BY last_execution_time DESC) rs
   WHERE q.query_id = ${qid}
   ORDER BY rs.last_execution_time DESC
   FOR JSON PATH)) AS plans
FOR JSON PATH, WITHOUT_ARRAY_WRAPPER;
`;
      const detailFile = path.join(TMP_DIR, `detail-${cfg.id}-${qid}.out`);
      const detailSql = path.join(TMP_DIR, `detail-${cfg.id}-${qid}.sql`);
      await writeFile(detailSql, sql, 'utf8');
      let detailToken = null;
      if (cfg.auth === 'azuread-interactive') detailToken = await acquireEntraToken(cfg);
      await new Promise((resolve, reject) => {
        const args = buildSqlcmdArgs(cfg, ['-l', '10', '-t', '30', '-y', '0', '-Y', '0', '-i', detailSql, '-o', detailFile], { useAccessToken: !!detailToken });
        const env = { ...process.env }; if (detailToken) env.SQLCMDACCESSTOKEN = detailToken;
        execFile(pickSqlcmd(cfg), args, { timeout: 40000, windowsHide: true, encoding: 'utf8', env },
          (err, stdout, stderr) => err ? reject(new Error(stderr||err.message)) : resolve());
      });
      const raw = await readFile(detailFile, 'utf8');
      const firstBrace = Math.min(...[raw.indexOf('{'), raw.indexOf('[')].filter(i => i >= 0));
      const trimmed = raw.slice(firstBrace >= 0 ? firstBrace : 0).trim();
      let data;
      try { data = JSON.parse(trimmed); }
      catch (e) { try { data = JSON.parse(trimmed.replace(/\r?\n/g,'')); } catch { return json(res, 500, { error: 'parse failed', raw: trimmed.slice(0,500) }); } }
      return json(res, 200, { queryId: Number(qid), db, plans: data.plans || [] });
    }

    if (p === '/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
      return;
    }

    res.writeHead(404); res.end('not found');
  } catch (e) {
    console.error('REQ ERROR:', e);
    json(res, 500, { error: String(e.message || e) });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`SQL dashboard listening on http://127.0.0.1:${PORT}`);
});
