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
// Azure CLI session bootstrap for Entra ID Interactive (MFA)
// Uses `az account get-access-token` as a fast "is there a session?" check.
// If no session, runs `az login` interactively (browser popup ONCE); after that,
// every sqlcmd call uses --authentication-method=ActiveDirectoryAzCli which
// silently reuses that cached session — no more prompts until refresh token
// expires (~90 days).
// ==============================
const azLoginLock = new Map();  // serverId -> Promise

async function ensureAzCliSession(cfg) {
  if (cfg.auth !== 'azuread-interactive') return;
  if (azLoginLock.has(cfg.id)) return azLoginLock.get(cfg.id);

  const p = (async () => {
    // Fast check: is `az` already logged in with a token for SQL?
    const check = await new Promise((resolve) => {
      execFile('az',
        ['account', 'get-access-token', '--resource', 'https://database.windows.net/', '--query', 'expiresOn', '-o', 'tsv'],
        { timeout: 10000, windowsHide: true, shell: true },
        (err, stdout) => resolve({ ok: !err && stdout.trim().length > 0, expires: stdout.trim() }));
    });
    if (check.ok) {
      console.log(`Azure CLI session valid for ${cfg.id}, expires ${check.expires}`);
      return;
    }
    // No session — run az login interactively (browser popup, one time)
    console.log(`No valid Azure CLI session — launching az login for ${cfg.id}`);
    const loginArgs = ['login'];
    if (cfg.user) { loginArgs.push('--username', cfg.user); }
    await new Promise((resolve, reject) => {
      execFile('az', loginArgs, { timeout: 180000, windowsHide: false, shell: true },
        (err, stdout, stderr) => err ? reject(new Error(`az login failed: ${(stderr||err.message).slice(0,300)}`)) : resolve());
    });
    console.log(`az login completed for ${cfg.id}`);
  })();
  azLoginLock.set(cfg.id, p);
  try { await p; } finally { azLoginLock.delete(cfg.id); }
}

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
      // go-sqlcmd v1.10 doesn't support ActiveDirectoryAccessToken but does
      // support ActiveDirectoryAzCli which reuses the Azure CLI cached session.
      // We run `az login` once (or reuse an existing session), and all future
      // sqlcmd calls silently reuse the same cached token — no browser popup.
      if (opts.useAccessToken) {
        args.push('--authentication-method=ActiveDirectoryAzCli');
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
SET ANSI_WARNINGS OFF;
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
     LEFT(REPLACE(REPLACE(st.text,CHAR(13),' '),CHAR(10),' '),200) AS query_text,
     CONVERT(NVARCHAR(200), r.plan_handle, 1) AS plan_handle_hex
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
   FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)) AS tempdb,
  JSON_QUERY((SELECT TOP 10 latch_class,
     CAST(wait_time_ms/1000.0 AS DECIMAL(18,3)) AS wait_time_s,
     waiting_requests_count AS tasks,
     CAST(wait_time_ms*1.0/NULLIF(waiting_requests_count,0) AS DECIMAL(18,2)) AS avg_wait_ms,
     CAST(100.0*wait_time_ms/NULLIF(SUM(wait_time_ms) OVER (),0) AS DECIMAL(5,2)) AS pct
   FROM sys.dm_os_latch_stats
   WHERE latch_class NOT IN (N'BUFFER') AND wait_time_ms > 0
   ORDER BY wait_time_ms DESC
   FOR JSON PATH)) AS latches,
  JSON_QUERY((
    SELECT session_id, blocking_session_id, wait_type, wait_ms, wait_resource, db_name,
           command, login_name, host_name, program_name, query_text, plan_handle_hex
    FROM (
      SELECT r.session_id, r.blocking_session_id, r.wait_type, r.wait_time AS wait_ms,
             r.wait_resource, DB_NAME(r.database_id) AS db_name, r.command,
             s.login_name, s.host_name, s.program_name,
             LEFT(REPLACE(REPLACE(st.text,CHAR(13),' '),CHAR(10),' '),200) AS query_text,
             CONVERT(NVARCHAR(200), r.plan_handle, 1) AS plan_handle_hex
      FROM sys.dm_exec_requests r
      JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
      OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) st
      WHERE s.is_user_process = 1
        AND (r.blocking_session_id <> 0
             OR r.session_id IN (SELECT DISTINCT blocking_session_id FROM sys.dm_exec_requests WHERE blocking_session_id <> 0))
    ) B
    ORDER BY blocking_session_id, wait_ms DESC
    FOR JSON PATH)) AS blocking,
  JSON_QUERY((SELECT TOP 20 owt.session_id, owt.wait_duration_ms AS wait_ms, owt.wait_type,
     owt.blocking_session_id AS blocked_by, owt.resource_description,
     es.program_name, es.login_name, es.host_name,
     DB_NAME(er.database_id) AS db_name,
     LEFT(REPLACE(REPLACE(st.text,CHAR(13),' '),CHAR(10),' '),200) AS query_text,
     CONVERT(NVARCHAR(200), er.plan_handle, 1) AS plan_handle_hex,
     es.cpu_time, es.memory_usage
   FROM sys.dm_os_waiting_tasks owt
   INNER JOIN sys.dm_exec_sessions es ON owt.session_id = es.session_id
   INNER JOIN sys.dm_exec_requests er ON es.session_id = er.session_id
   OUTER APPLY sys.dm_exec_sql_text(er.sql_handle) st
   WHERE es.is_user_process = 1 AND owt.wait_duration_ms > 0
   ORDER BY owt.wait_duration_ms DESC
   FOR JSON PATH)) AS waiters
FOR JSON PATH, WITHOUT_ARRAY_WRAPPER;
`;

// Separate Query Store batch - can be slow, fetched with own timeout, doesn't block main metrics
const TOP_QUERIES_SQL = `
SET NOCOUNT ON;
SET ANSI_WARNINGS OFF;
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

  if (cfg.auth === 'azuread-interactive') {
    await ensureAzCliSession(cfg);
  }
  const useAzCli = cfg.auth === 'azuread-interactive';

  const args = buildSqlcmdArgs(cfg, [
    '-l', '10', '-t', String(timeoutSec),
    '-y', '0', '-Y', '0',
    '-w', '65535',
    '-i', scriptPath, '-o', outFile,
  ], { useAccessToken: useAzCli });

  try {
    await new Promise((resolve, reject) => {
      execFile(pickSqlcmd(cfg), args, { timeout: (timeoutSec + 5) * 1000, windowsHide: true, encoding: 'utf8' },
        (err, stdout, stderr) => {
          if (err) return reject(new Error(`sqlcmd ${tag} failed: ${err.message}\nSTDERR: ${(stderr||'').slice(0,400)}`));
          resolve();
        });
    });
  } catch (e) {
    // If Az CLI session died, next call will re-run az login
    if (useAzCli && /authenticat|token|login/i.test(e.message)) azLoginLock.delete(cfg.id);
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
  data.latches ??= [];
  data.blocking ??= [];
  data.waiters ??= [];
  data.instance ??= {};
  if (data.buffer_pool === undefined) data.buffer_pool = [];
  if (data.tempdb === undefined || (useAzureDbBatch && (!data.tempdb || Object.keys(data.tempdb).length === 0))) {
    data.tempdb = useAzureDbBatch ? null : {};
  }

  // Custom counters (run after main metrics so we don't slow down the first paint)
  data.custom_counters = await runAllCounters(cfg);

  // Append to history ring buffer (async, doesn't block response)
  appendHistory(cfg.id, data).catch(() => {});

  return data;
}

async function probeEngineEdition(cfg) {
  if (cfg.auth === 'azuread-interactive') await ensureAzCliSession(cfg);
  const useAzCli = cfg.auth === 'azuread-interactive';
  const args = buildSqlcmdArgs(cfg, ['-l','10','-t','15','-h','-1','-W','-Q','SELECT CAST(SERVERPROPERTY(\'EngineEdition\') AS INT) AS e'], { useAccessToken: useAzCli });
  return new Promise((resolve, reject) => {
    execFile(pickSqlcmd(cfg), args, { timeout: 20000, windowsHide: true, encoding: 'utf8' },
      (err, stdout) => {
        if (err) return reject(err);
        const m = stdout.match(/(\d+)/);
        resolve(m ? Number(m[1]) : null);
      });
  });
}

async function testConnection(cfg) {
  if (cfg.auth === 'azuread-interactive') {
    try { await ensureAzCliSession(cfg); }
    catch (e) { return { ok: false, error: 'Azure CLI login failed: ' + e.message.slice(0,400) }; }
  }
  const useAzCli = cfg.auth === 'azuread-interactive';
  const args = buildSqlcmdArgs(cfg, [
    '-l', '60', '-t', '60',
    '-h', '-1',
    '-Q', 'SELECT 1',
  ], { useAccessToken: useAzCli });
  return new Promise((resolve) => {
    execFile(pickSqlcmd(cfg), args, { timeout: 30000, windowsHide: true, encoding: 'utf8' },
      (err, stdout, stderr) => {
        if (err) {
          const parts = [];
          if (stderr && stderr.trim()) parts.push('STDERR: ' + stderr.trim());
          if (stdout && stdout.trim()) parts.push('STDOUT: ' + stdout.trim());
          if (err.killed) parts.push('(process timed out)');
          if (parts.length === 0) parts.push(err.message);
          resolve({ ok: false, error: parts.join(' | ').slice(0, 900) });
        } else resolve({ ok: true });
      });
  });
}

// ---------- Cache per server ----------
const cache = new Map(); // serverId -> { at, data }
const CACHE_MS = 4000;

// ==============================
// History ring buffer (per server, JSON on disk under history/)
// Keeps last MAX_HISTORY samples (default 720 = 6 hours @ 30s)
// ==============================
const HISTORY_DIR = path.join(__dirname, 'history');
await mkdir(HISTORY_DIR, { recursive: true });
const MAX_HISTORY = 720;
const historyBuffers = new Map(); // serverId -> array

async function loadHistory(id) {
  if (historyBuffers.has(id)) return historyBuffers.get(id);
  try {
    const raw = await readFile(path.join(HISTORY_DIR, `${id}.json`), 'utf8');
    const arr = JSON.parse(raw);
    historyBuffers.set(id, Array.isArray(arr) ? arr.slice(-MAX_HISTORY) : []);
  } catch { historyBuffers.set(id, []); }
  return historyBuffers.get(id);
}
async function saveHistory(id) {
  const arr = historyBuffers.get(id) || [];
  await writeFile(path.join(HISTORY_DIR, `${id}.json`), JSON.stringify(arr));
}
function extractHistorySample(data) {
  const i = data.instance || {};
  const bhr = i.buffer_cache_hit_ratio_base > 0 ? (i.buffer_cache_hit_ratio*100/i.buffer_cache_hit_ratio_base) : 100;
  const waits = data.waits || [];
  const totalWait = waits.reduce((s,w)=>s + (Number(w.wait_time_s)||0), 0);
  const totalSignal = waits.reduce((s,w)=>s + (Number(w.signal_wait_s)||0), 0);
  const sample = {
    t: Date.now(),
    ple: i.page_life_expectancy ?? null,
    bhr: Number(bhr.toFixed(2)),
    memMb: i.memory_in_use_mb ?? null,
    sessions: i.user_sessions ?? null,
    active: i.active_requests ?? null,
    blocked: i.blocked_requests ?? null,
    waitS: Math.round(totalWait),
    signalPct: totalWait > 0 ? Number((totalSignal/totalWait*100).toFixed(2)) : 0,
    // Azure-specific
    cpuPct: i.avg_cpu_percent ?? null,
    memPct: i.avg_memory_percent ?? null,
    ioPct: i.avg_data_io_percent ?? null,
    logPct: i.avg_log_write_percent ?? null,
    // Custom counter values (id -> number)
    custom: {},
  };
  for (const cc of (data.custom_counters || [])) {
    if (typeof cc.value === 'number') sample.custom[cc.id] = cc.value;
  }
  return sample;
}
async function appendHistory(id, data) {
  const arr = await loadHistory(id);
  arr.push(extractHistorySample(data));
  if (arr.length > MAX_HISTORY) arr.splice(0, arr.length - MAX_HISTORY);
  historyBuffers.set(id, arr);
  // Fire-and-forget disk write; failures shouldn't block metrics
  saveHistory(id).catch(() => {});
}

// ==============================
// Custom counters
// User-defined T-SQL that returns a single scalar value per collection.
// Guarded by a keyword denylist (read-only only).
// ==============================
const CUSTOM_COUNTER_DENYLIST = /\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|TRUNCATE|MERGE|GRANT|REVOKE|BACKUP|RESTORE|RECONFIGURE|SHUTDOWN|WAITFOR|OPENROWSET|OPENDATASOURCE|xp_)\b/i;
function validateCounterSql(sql) {
  if (!sql || sql.length > 8000) throw new Error('SQL is empty or too long (>8000 chars)');
  if (CUSTOM_COUNTER_DENYLIST.test(sql)) throw new Error('SQL contains blocked keyword (write/DDL/exec statements are not allowed)');
  // Must contain SELECT
  if (!/\bSELECT\b/i.test(sql)) throw new Error('SQL must contain a SELECT statement');
  return true;
}

async function runCustomCounter(cfg, counter) {
  validateCounterSql(counter.sql);
  const outFile = path.join(TMP_DIR, `cc-${cfg.id}-${counter.id}.out`);
  const sqlFile = path.join(TMP_DIR, `cc-${cfg.id}-${counter.id}.sql`);
  // Wrap user SQL to guarantee a scalar (first column of first row).
  // We add a leading SET NOCOUNT ON and SET ANSI_WARNINGS OFF.
  const wrapped = `SET NOCOUNT ON;
SET ANSI_WARNINGS OFF;
${counter.sql}`;
  await writeFile(sqlFile, wrapped, 'utf8');
  if (cfg.auth === 'azuread-interactive') await ensureAzCliSession(cfg);
  const useAzCli = cfg.auth === 'azuread-interactive';
  const args = buildSqlcmdArgs(cfg, ['-l','5','-t','8','-h','-1','-w','8000','-i',sqlFile,'-o',outFile], { useAccessToken: useAzCli });
  await new Promise((resolve, reject) => {
    execFile(pickSqlcmd(cfg), args, { timeout: 12000, windowsHide: true, encoding: 'utf8' },
      (err, stdout, stderr) => err ? reject(new Error((stderr||err.message).slice(0,300))) : resolve());
  });
  const raw = (await readFile(outFile, 'utf8')).trim();
  if (!raw) return { value: null };
  // Take first non-empty line, first "column" (whitespace/tab separated)
  const firstLine = raw.split(/\r?\n/).find(l => l.trim().length > 0) || '';
  const firstCol = firstLine.split(/\s{2,}|\t/)[0].trim();
  const num = Number(firstCol);
  return { value: Number.isFinite(num) ? num : firstCol };
}

async function runAllCounters(cfg) {
  const counters = cfg.customCounters || [];
  if (counters.length === 0) return [];
  const results = await Promise.all(counters.map(c =>
    runCustomCounter(cfg, c).catch(e => ({ error: e.message.slice(0, 200) }))
  ));
  return counters.map((c, i) => ({
    id: c.id, name: c.name, unit: c.unit || '',
    warnGt: c.warnGt, critGt: c.critGt, warnLt: c.warnLt, critLt: c.critLt,
    description: c.description || '',
    ...results[i],
  }));
}

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

// ==============================
// Ollama proxy for "Ask AI" feature
// ==============================
const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
async function ollamaListModels() {
  const r = await fetch(OLLAMA_URL + '/api/tags');
  if (!r.ok) throw new Error('Ollama tags HTTP ' + r.status);
  const j = await r.json();
  // Exclude embedding-only models
  return (j.models || []).map(m => m.name).filter(n => !n.includes('embed'));
}
async function ollamaChat({ model, system, user, timeoutMs = 180000 }) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(OLLAMA_URL + '/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model, stream: false,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
        options: { temperature: 0.2, num_ctx: 8192 },
      }),
      signal: ctrl.signal,
    });
    if (!r.ok) {
      const txt = await r.text();
      throw new Error('Ollama HTTP ' + r.status + ': ' + txt.slice(0, 300));
    }
    const j = await r.json();
    return j.message?.content || '';
  } finally { clearTimeout(t); }
}
function buildAiContext(data, history) {
  // Compact context: instance summary + top waits + top queries + custom counter values
  const i = data.instance || {};
  const waits = (data.waits || []).slice(0, 8).map(w => ({
    type: w.wait_type,
    wait_s: Math.round(Number(w.wait_time_s) || 0),
    signal_s: Math.round(Number(w.signal_wait_s) || 0),
    count: Number(w.waiting_tasks_count) || 0,
  }));
  const topq = (data.top_queries || []).slice(0, 8).map(q => ({
    db: q.db_name, qid: q.query_id, execs: q.execution_count,
    avg_cpu_ms: q.avg_cpu_ms, avg_dur_ms: q.avg_duration_ms, avg_reads: q.avg_logical_reads,
    text: (q.query_text || '').slice(0, 400),
  }));
  const missing = (data.missing_indexes || []).slice(0, 5);
  const files = (data.file_io || []).slice(0, 8);
  const custom = (data.custom_counters || []).map(c => ({ name: c.name, value: c.value, unit: c.unit || '' }));
  const recent = (history || []).slice(-30);
  return {
    engine: data.engine,
    engine_edition: data.engine_edition,
    instance: {
      uptime_min: i.uptime_min, cpu_count: i.cpu_count,
      user_sessions: i.user_sessions, active_requests: i.active_requests, blocked_requests: i.blocked_requests,
      page_life_expectancy: i.page_life_expectancy,
      target_memory_mb: i.target_memory_mb, memory_in_use_mb: i.memory_in_use_mb,
      avg_cpu_percent: i.avg_cpu_percent, avg_memory_percent: i.avg_memory_percent,
      avg_data_io_percent: i.avg_data_io_percent, avg_log_write_percent: i.avg_log_write_percent,
      product_version: i.product_version, edition: i.edition,
    },
    top_waits: waits,
    top_queries: topq,
    missing_indexes: missing,
    file_io: files,
    custom_counters: custom,
    recent_history_last_30: recent,
  };
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

    if (p === '/api/list-databases' && req.method === 'POST') {
      // Probe an ad-hoc server (unsaved) to list databases visible to the login.
      // Used by the Add/Edit modal to fill the Database dropdown.
      const body = await readBody(req);
      if (!body.server || !body.auth) return json(res, 400, { error: 'server and auth required' });
      const cfg = {
        id: 'probe-' + crypto.randomBytes(2).toString('hex'),
        server: body.server, auth: body.auth,
        user: body.user || '', password: body.password || '',
        database: '',   // Master default is fine here; Azure SQL will refuse if no access
        encrypt: body.encrypt !== false,
        trustCert: body.trustCert !== false,
      };
      // For Azure SQL Database, we usually can't list from master; try anyway,
      // and if it fails, return an empty list (user must type the DB name).
      const outFile = path.join(TMP_DIR, `dblist-${cfg.id}.out`);
      const sqlFile = path.join(TMP_DIR, `dblist-${cfg.id}.sql`);
      await writeFile(sqlFile, `SET NOCOUNT ON;
SET ANSI_WARNINGS OFF;
SELECT (SELECT name FROM sys.databases WHERE database_id > 4 AND state_desc='ONLINE' ORDER BY name FOR JSON PATH) AS dbs;`, 'utf8');
      try {
        if (cfg.auth === 'azuread-interactive') await ensureAzCliSession(cfg);
        const useAzCli = cfg.auth === 'azuread-interactive';
        const args = buildSqlcmdArgs(cfg, ['-l','10','-t','15','-y','0','-Y','0','-w','65535','-i',sqlFile,'-o',outFile], { useAccessToken: useAzCli });
        await new Promise((resolve, reject) => {
          execFile(pickSqlcmd(cfg), args, { timeout: 20000, windowsHide: true, encoding: 'utf8' },
            (err, stdout, stderr) => err ? reject(new Error((stderr||err.message).slice(0,300))) : resolve());
        });
        const raw = await readFile(outFile, 'utf8');
        const firstBrace = Math.min(...[raw.indexOf('{'), raw.indexOf('[')].filter(i => i >= 0));
        if (firstBrace < 0) return json(res, 200, { databases: [] });
        const trimmed = raw.slice(firstBrace).trim().replace(/\r?\n/g, '');
        const parsed = JSON.parse(trimmed);
        const dbs = Array.isArray(parsed) ? parsed.map(x => x.name) : (parsed.dbs ? JSON.parse(parsed.dbs).map(x=>x.name) : []);
        return json(res, 200, { databases: dbs });
      } catch (e) {
        return json(res, 200, { databases: [], warning: e.message.slice(0,300) });
      }
    }

    if (p === '/api/servers' && req.method === 'POST') {
      const body = await readBody(req);
      if (!body.name || !body.server || !body.auth) return json(res, 400, { error: 'name, server, auth required' });
      const plainPw = body.password || '';
      const cfg = {
        id: body.id || (body.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-' + crypto.randomBytes(2).toString('hex')),
        name: body.name.slice(0, 60),
        group: (body.group || '').slice(0, 40) || null,
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

    if (p.startsWith('/api/servers/') && !p.includes('/counters') && req.method === 'DELETE') {
      const id = p.substring('/api/servers/'.length);
      const list = await loadServers();
      const idx = list.findIndex(s => s.id === id);
      if (idx < 0) return json(res, 404, { error: 'not found' });
      list.splice(idx, 1);
      await saveServers(list);
      cache.delete(id);
      return json(res, 200, { ok: true });
    }

    if (p.startsWith('/api/servers/') && !p.includes('/counters') && req.method === 'PATCH') {
      const id = p.substring('/api/servers/'.length);
      const body = await readBody(req);
      const list = await loadServers();
      const idx = list.findIndex(s => s.id === id);
      if (idx < 0) return json(res, 404, { error: 'not found' });
      const current = list[idx];
      // Build the candidate cfg (in-memory shape with decrypted password for the test)
      const candidate = {
        ...current,
        name: (body.name ?? current.name).slice(0, 60),
        group: (body.group === null || body.group === '') ? null : ((body.group ?? current.group) ? String(body.group ?? current.group).slice(0, 40) : null),
        server: (body.server ?? current.server).slice(0, 200),
        auth: body.auth ?? current.auth,
        user: body.user ?? current.user ?? '',
        database: body.database ?? current.database ?? '',
        encrypt: body.encrypt ?? current.encrypt !== false,
        trustCert: body.trustCert ?? current.trustCert !== false,
      };
      // Password: if body has a non-empty password field, replace; if empty string
      // AND passwordEnc is currently non-empty and body.clearPassword===true, wipe.
      let plainForTest = '';
      if (typeof body.password === 'string' && body.password.length > 0) {
        plainForTest = body.password;
      } else if (body.clearPassword) {
        candidate.passwordEnc = '';
      } else {
        // Keep existing encrypted password; decrypt for test
        plainForTest = await decryptPassword(current.passwordEnc || '');
      }
      // Test connection with the candidate values
      const testCfg = { ...candidate, password: plainForTest };
      const t = await testConnection(testCfg);
      if (!t.ok) return json(res, 400, { error: 'Connection test failed: ' + t.error });
      // Re-probe engine edition (server may have changed)
      try { candidate.engineEdition = await probeEngineEdition(testCfg); } catch { /* keep existing */ }
      // Store: encrypt new password if provided
      if (plainForTest && !body.clearPassword) {
        candidate.passwordEnc = await encryptPassword(plainForTest);
      }
      // Strip transient plaintext
      delete candidate.password;
      list[idx] = candidate;
      await saveServers(list);
      cache.delete(id);   // Force fresh collect with new creds
      return json(res, 200, publicView(candidate));
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
      if (cfg.auth === 'azuread-interactive') await ensureAzCliSession(cfg);
      const useAzCliDetail = cfg.auth === 'azuread-interactive';
      await new Promise((resolve, reject) => {
        const args = buildSqlcmdArgs(cfg, ['-l', '10', '-t', '30', '-y', '0', '-Y', '0', '-i', detailSql, '-o', detailFile], { useAccessToken: useAzCliDetail });
        execFile(pickSqlcmd(cfg), args, { timeout: 40000, windowsHide: true, encoding: 'utf8' },
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

    // ==============================
    // Custom counters CRUD (per server)
    // ==============================
    if (p.match(/^\/api\/servers\/[^/]+\/counters$/) && req.method === 'GET') {
      const id = p.split('/')[3];
      const list = await loadServers();
      const s = list.find(x => x.id === id);
      if (!s) return json(res, 404, { error: 'server not found' });
      return json(res, 200, s.customCounters || []);
    }
    if (p.match(/^\/api\/servers\/[^/]+\/counters$/) && req.method === 'POST') {
      const id = p.split('/')[3];
      const body = await readBody(req);
      const list = await loadServers();
      const s = list.find(x => x.id === id);
      if (!s) return json(res, 404, { error: 'server not found' });
      if (!body.name || !body.sql) return json(res, 400, { error: 'name and sql required' });
      try { validateCounterSql(body.sql); } catch (e) { return json(res, 400, { error: e.message }); }
      s.customCounters = s.customCounters || [];
      const cc = {
        id: body.id || ('cc-' + crypto.randomBytes(3).toString('hex')),
        name: body.name.slice(0, 60),
        sql: body.sql.trim(),
        unit: body.unit || '',
        description: (body.description || '').slice(0, 200),
        warnGt: body.warnGt === '' || body.warnGt == null ? null : Number(body.warnGt),
        critGt: body.critGt === '' || body.critGt == null ? null : Number(body.critGt),
        warnLt: body.warnLt === '' || body.warnLt == null ? null : Number(body.warnLt),
        critLt: body.critLt === '' || body.critLt == null ? null : Number(body.critLt),
      };
      const idx = s.customCounters.findIndex(x => x.id === cc.id);
      if (idx >= 0) s.customCounters[idx] = cc;
      else s.customCounters.push(cc);
      await saveServers(list);
      cache.delete(id);
      return json(res, 200, cc);
    }
    if (p.match(/^\/api\/servers\/[^/]+\/counters\/[^/]+$/) && req.method === 'DELETE') {
      const parts = p.split('/');
      const id = parts[3], ccid = parts[5];
      const list = await loadServers();
      const s = list.find(x => x.id === id);
      if (!s) return json(res, 404, { error: 'server not found' });
      s.customCounters = (s.customCounters || []).filter(x => x.id !== ccid);
      await saveServers(list);
      cache.delete(id);
      return json(res, 200, { ok: true });
    }
    if (p.match(/^\/api\/servers\/[^/]+\/counters\/test$/) && req.method === 'POST') {
      const id = p.split('/')[3];
      const body = await readBody(req);
      const list = await loadServers();
      const s = list.find(x => x.id === id);
      if (!s) return json(res, 404, { error: 'server not found' });
      try { validateCounterSql(body.sql); } catch (e) { return json(res, 400, { error: e.message }); }
      try {
        const cfg = await resolveServer(s);
        const result = await runCustomCounter(cfg, { id: 'test-' + Date.now(), sql: body.sql });
        return json(res, 200, result);
      } catch (e) {
    return json(res, 400, { error: e.message.slice(0, 400) });
  }
}

// ==============================
// History (trend samples)
// ==============================
    if (p === '/api/history' && req.method === 'GET') {
      const id = url.searchParams.get('serverId');
      const limit = Math.min(720, Math.max(1, parseInt(url.searchParams.get('limit')||'120', 10)));
      if (!id) return json(res, 400, { error: 'serverId required' });
      const arr = await loadHistory(id);
      return json(res, 200, arr.slice(-limit));
    }

    // ==============================
    // Shutdown: stop the running dashboard server
    // ==============================
    if (p === '/api/shutdown' && req.method === 'POST') {
      json(res, 200, { ok: true, message: 'Shutting down…' });
      console.log('Shutdown requested via /api/shutdown');
      // Give the response a moment to flush, then close the HTTP server + exit
      setTimeout(() => {
        try { server.close(() => process.exit(0)); } catch { process.exit(0); }
        // Hard fallback if close() hangs on live sockets
        setTimeout(() => process.exit(0), 1500);
      }, 250);
      return;
    }

    // ==============================
    // AI: list Ollama models + ask a question about a server
    // ==============================
    if (p === '/api/ai/models' && req.method === 'GET') {
      try {
        const models = await ollamaListModels();
        return json(res, 200, { models, ollamaUrl: OLLAMA_URL });
      } catch (e) {
        return json(res, 400, { error: 'Ollama not reachable at ' + OLLAMA_URL + ': ' + e.message.slice(0, 300) });
      }
    }
    if (p === '/api/ai/ask' && req.method === 'POST') {
      const body = await readBody(req);
      if (!body.serverId || !body.question) return json(res, 400, { error: 'serverId and question required' });
      const list = await loadServers();
      const s = list.find(x => x.id === body.serverId);
      if (!s) return json(res, 404, { error: 'server not found' });
      const model = body.model || 'llama3.1:8b';
      const question = String(body.question).slice(0, 4000);
      // Use cached data if fresh, else collect
      let data;
      const c = cache.get(s.id);
      if (c && Date.now() - c.at < 60000) data = c.data;
      else {
        try {
          const cfg = await resolveServer(s);
          data = await collectFor(cfg);
          cache.set(s.id, { at: Date.now(), data });
        } catch (e) { return json(res, 400, { error: 'Failed to collect metrics: ' + e.message.slice(0, 300) }); }
      }
      const history = await loadHistory(s.id);
      const ctx = buildAiContext(data, history);
      const system = `You are a senior SQL Server DBA assistant. You are given a JSON snapshot of a live SQL Server instance (waits, top queries, missing indexes, resource pressure, and a short history of samples).

Rules:
- Ground every claim in the JSON data. If the data does not support a claim, say so.
- Prefer specific, actionable recommendations (e.g. "add index on X.Y", "review the query with query_id=42 that averages 320ms CPU").
- Wait-percentage interpretation follows the Paul Randal / Microsoft Learn methodology (signal wait % > 25 = CPU pressure; PAGEIOLATCH dominant = IO bottleneck; WRITELOG dominant = log disk; RESOURCE_SEMAPHORE = memory grants; LCK_M_* = blocking).
- Keep answers concise. Use short markdown sections and bullet lists. Avoid long preambles.
- Never invent DMV rows, index names, or query text that are not in the JSON.`;
      const userMsg = `Server: ${s.name} (${s.server}), engine=${data.engine || '?'}\n\nUser question:\n${question}\n\nMetrics JSON (compact):\n\`\`\`json\n${JSON.stringify(ctx)}\n\`\`\``;
      try {
        const answer = await ollamaChat({ model, system, user: userMsg });
        return json(res, 200, { answer, model, contextBytes: JSON.stringify(ctx).length });
      } catch (e) {
        return json(res, 400, { error: 'AI call failed: ' + e.message.slice(0, 500) });
      }
    }

    // ==============================
    // Live plan by plan_handle (for waiter/blocker rows)
    // ==============================
    if (p === '/api/live-plan' && req.method === 'POST') {
      const body = await readBody(req);
      if (!body.serverId || !body.planHandleHex) return json(res, 400, { error: 'serverId + planHandleHex required' });
      if (!/^0x[0-9a-fA-F]{2,600}$/.test(body.planHandleHex)) return json(res, 400, { error: 'invalid plan_handle format' });
      const list = await loadServers();
      const s = list.find(x => x.id === body.serverId);
      if (!s) return json(res, 404, { error: 'server not found' });
      try {
        const cfg = await resolveServer(s);
        if (cfg.auth === 'azuread-interactive') await ensureAzCliSession(cfg);
        const useAzCli = cfg.auth === 'azuread-interactive';
        const outFile = path.join(TMP_DIR, `plan-${cfg.id}-${Date.now()}.out`);
        const sqlFile = path.join(TMP_DIR, `plan-${cfg.id}-${Date.now()}.sql`);
        const sql = `SET NOCOUNT ON; SET ANSI_WARNINGS OFF;
SELECT CAST(query_plan AS NVARCHAR(MAX)) AS xml_plan FROM sys.dm_exec_query_plan(${body.planHandleHex});`;
        await writeFile(sqlFile, sql, 'utf8');
        const args = buildSqlcmdArgs(cfg, ['-l','10','-t','20','-w','65535','-y','0','-Y','0','-i',sqlFile,'-o',outFile], { useAccessToken: useAzCli });
        await new Promise((resolve, reject) => {
          execFile(pickSqlcmd(cfg), args, { timeout: 30000, windowsHide: true, encoding: 'utf8' },
            (err, stdout, stderr) => err ? reject(new Error((stderr||err.message).slice(0,300))) : resolve());
        });
        const raw = (await readFile(outFile, 'utf8'));
        // Extract from first <ShowPlanXML through last </ShowPlanXML>
        const start = raw.indexOf('<ShowPlanXML');
        const end = raw.lastIndexOf('</ShowPlanXML>');
        if (start < 0 || end < 0) return json(res, 400, { error: 'no plan XML returned — request may have finished' });
        return json(res, 200, { xml: raw.slice(start, end + '</ShowPlanXML>'.length) });
      } catch (e) {
        return json(res, 400, { error: e.message.slice(0, 400) });
      }
    }

    // ==============================
    // Reorder servers (persist sidebar order)
    // ==============================
    if (p === '/api/servers/reorder' && req.method === 'POST') {
      const body = await readBody(req);
      const order = Array.isArray(body.order) ? body.order : [];
      const list = await loadServers();
      const byId = new Map(list.map(s => [s.id, s]));
      const reordered = [];
      for (const id of order) if (byId.has(id)) { reordered.push(byId.get(id)); byId.delete(id); }
      for (const s of byId.values()) reordered.push(s); // any servers not mentioned go at end
      await saveServers(reordered);
      return json(res, 200, { ok: true, count: reordered.length });
    }

    // ==============================
    // Kill session (requires ALTER ANY CONNECTION on the target server)
    // ==============================
    if (p === '/api/kill-session' && req.method === 'POST') {
      const body = await readBody(req);
      const sid = Number(body.sessionId);
      if (!body.serverId || !Number.isInteger(sid) || sid <= 50) {
        return json(res, 400, { error: 'valid serverId and sessionId >= 51 required' });
      }
      const list = await loadServers();
      const s = list.find(x => x.id === body.serverId);
      if (!s) return json(res, 404, { error: 'server not found' });
      try {
        const cfg = await resolveServer(s);
        if (cfg.auth === 'azuread-interactive') await ensureAzCliSession(cfg);
        const useAzCli = cfg.auth === 'azuread-interactive';
        const args = buildSqlcmdArgs(cfg, ['-l','10','-t','15','-Q',`KILL ${sid}`], { useAccessToken: useAzCli });
        await new Promise((resolve, reject) => {
          execFile(pickSqlcmd(cfg), args, { timeout: 20000, windowsHide: true, encoding: 'utf8' },
            (err, stdout, stderr) => err ? reject(new Error((stderr||err.message).slice(0,300))) : resolve());
        });
        cache.delete(body.serverId);
        return json(res, 200, { ok: true, killed: sid });
      } catch (e) {
        return json(res, 400, { error: e.message.slice(0, 400) });
      }
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
