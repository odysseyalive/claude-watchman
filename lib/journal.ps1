# lib/journal.ps1 — THE ONLY code that reads or writes journal/findings.db (PowerShell port).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. Routine create-or-update
# > of findings through this library is the tool's core function and is NOT a destructive database
# > modification. What IS destructive — wiping findings.db, mass-deleting findings, or a lossy
# > schema migration — falls fully under the Prime Directive: stop, warn, and ask before doing it.
# > journal_migrate below enforces that: it backs up first and refuses a lossy migration without
# > explicit operator confirmation. This rule has no exceptions and no mode that overrides it.
#
# Contract (CLAUDE.md "The journal contract"):
#   * Single writer in code: every interaction goes through these functions.
#   * Single writer at runtime: WAL + busy-timeout, and writes serialized behind a named Mutex
#     (the Windows analogue of the bash flock) so a loop pass and a manual run cannot corrupt state.
#   * Findings are created-or-updated, never blindly appended (stable fingerprint).
#
# Dot-source this file, then call journal_init once before any other function.

# --- Paths ------------------------------------------------------------------
function _journal_root {
    if ($env:WATCHMAN_ROOT) { return $env:WATCHMAN_ROOT }
    return (Split-Path -Parent $PSScriptRoot)
}
$script:JOURNAL_DIR    = if ($env:JOURNAL_DIR)    { $env:JOURNAL_DIR }    else { Join-Path (_journal_root) 'journal' }
$script:JOURNAL_DB     = if ($env:JOURNAL_DB)     { $env:JOURNAL_DB }     else { Join-Path $script:JOURNAL_DIR 'findings.db' }
$script:JOURNAL_SCHEMA = if ($env:JOURNAL_SCHEMA) { $env:JOURNAL_SCHEMA } else { Join-Path $script:JOURNAL_DIR 'schema.sql' }

# Schema version this library expects. Must match PRAGMA user_version in schema.sql.
$script:JOURNAL_SCHEMA_VERSION = 1

# Resolve the sqlite3 binary: explicit override, then PATH, then a bundled copy beside bin/.
function _journal_sqlite_bin {
    if ($env:WATCHMAN_SQLITE) { return $env:WATCHMAN_SQLITE }
    $cmd = Get-Command 'sqlite3' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $bundled = Join-Path (_journal_root) 'bin/sqlite3.exe'
    if (Test-Path -LiteralPath $bundled) { return $bundled }
    throw 'journal: sqlite3 not found (set WATCHMAN_SQLITE, add it to PATH, or bundle bin/sqlite3.exe).'
}

# --- Low-level sqlite wrappers ---------------------------------------------
# Every connection gets a busy timeout (the silent `.timeout` dot-command, so no pragma row
# pollutes output) so concurrent readers/writers wait instead of erroring. WAL is set once at
# init and persists in the DB file. The schema declares no foreign keys, so no per-connection
# foreign_keys pragma is needed. Reads use this directly; writes go through _journal_write.
function _journal_sqlite([string]$sql) {
    $bin = _journal_sqlite_bin
    $payload = ".timeout 10000`n$sql"
    $payload | & $bin $script:JOURNAL_DB
}

# Serialize writes behind a named system Mutex so two processes never write at once. Readers are
# unaffected (WAL allows concurrent reads). The Mutex is the cross-platform analogue of flock.
function _journal_write([string]$sql) {
    $mutex = $null
    $held = $false
    try {
        try {
            $mutex = New-Object System.Threading.Mutex($false, 'Global\watchman-journal')
            $held = $mutex.WaitOne([TimeSpan]::FromSeconds(15))
        } catch {
            # Named mutex unavailable in this environment — WAL + busy_timeout still serialize at
            # the sqlite layer; proceed without the advisory process lock.
            $mutex = $null; $held = $false
        }
        return (_journal_sqlite $sql)
    } finally {
        if ($mutex) { if ($held) { try { $mutex.ReleaseMutex() } catch {} } $mutex.Dispose() }
    }
}

# Double single-quotes so values are safe inside SQL string literals.
function _sql_escape([string]$s) { return ($s -replace "'", "''") }

# --- Initialization & migration --------------------------------------------
function journal_init {
    New-Item -ItemType Directory -Force -Path $script:JOURNAL_DIR | Out-Null
    if (-not (Test-Path -LiteralPath $script:JOURNAL_DB)) {
        if (-not (Test-Path -LiteralPath $script:JOURNAL_SCHEMA)) {
            Write-Error "journal: schema.sql not found at $($script:JOURNAL_SCHEMA)"
            return 1
        }
        # Fresh create is additive (no data to lose) — proceed without gating.
        $bin = _journal_sqlite_bin
        'PRAGMA journal_mode=WAL;' | & $bin $script:JOURNAL_DB | Out-Null
        Get-Content -Raw -LiteralPath $script:JOURNAL_SCHEMA | & $bin $script:JOURNAL_DB
        return
    }
    journal_migrate
}

# Compare on-disk user_version to the expected one and migrate (additive auto, lossy gated).
function journal_migrate {
    $on_disk = (_journal_sqlite 'PRAGMA user_version;')
    if (-not $on_disk) { $on_disk = 0 } else { $on_disk = [int]$on_disk }
    if ($on_disk -eq $script:JOURNAL_SCHEMA_VERSION) { return }
    if ($on_disk -gt $script:JOURNAL_SCHEMA_VERSION) {
        Write-Error "journal: DB is newer (v$on_disk) than this code (v$($script:JOURNAL_SCHEMA_VERSION)). Refusing to downgrade."
        return 1
    }
    Write-Warning "journal: migrating findings.db from v$on_disk to v$($script:JOURNAL_SCHEMA_VERSION) (additive)."
    journal_backup 'pre-migration'   # always back up before touching structure
    if ($env:WATCHMAN_LOSSY_MIGRATION -eq 'yes' -and $env:WATCHMAN_CONFIRM_MIGRATION -ne 'yes') {
        Write-Error @'
journal: STOP — a LOSSY schema migration was requested. This is a destructive
database operation under the Prime Directive: it can lose finding history.
A backup was taken, but the migration will NOT proceed without explicit operator
confirmation. Re-run with WATCHMAN_CONFIRM_MIGRATION=yes to authorize it.
'@
        return 1
    }
    _journal_write (Get-Content -Raw -LiteralPath $script:JOURNAL_SCHEMA)
}

# Timestamped backup of findings.db (additive, never destructive).
function journal_backup {
    param([string]$tag = 'manual')
    if (-not (Test-Path -LiteralPath $script:JOURNAL_DB)) { return }
    $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $backup = "$($script:JOURNAL_DB).backup-$ts-$tag"
    # Use sqlite's own backup so a concurrent writer can't tear the copy.
    ".backup '$backup'" | & (_journal_sqlite_bin) $script:JOURNAL_DB
    Write-Warning "journal: backed up to $backup"
}

# --- Retention prune (DESTRUCTIVE — Prime Directive, wm-apply only) ----------
# PowerShell port of journal_prune in journal.sh. Deleting old rows is destructive, so
# it is listed in lib/wm.mutators.ps1 (the read-only wm.ps1 dispatcher refuses it; only the
# apply dispatcher wm-apply.ps1, reachable solely from `watchman fix`, runs it) and it ALWAYS
# backs up findings.db first. Active findings (open/regressed/in-review) are NEVER pruned.
function journal_prune {
    $fdays = if ($env:WATCHMAN_RETAIN_FINDINGS_DAYS) { [int]$env:WATCHMAN_RETAIN_FINDINGS_DAYS } else { 180 }
    $mdays = if ($env:WATCHMAN_RETAIN_METRICS_DAYS)  { [int]$env:WATCHMAN_RETAIN_METRICS_DAYS }  else { 90 }
    $rdays = if ($env:WATCHMAN_RETAIN_RUNS_DAYS)     { [int]$env:WATCHMAN_RETAIN_RUNS_DAYS }     else { 90 }
    if (-not (Test-Path -LiteralPath $script:JOURNAL_DB)) { Write-Warning 'journal: no findings.db to prune.'; return }

    Write-Warning "journal: PRUNE is a DESTRUCTIVE database operation under the Prime Directive — it"
    Write-Warning "journal: deletes old terminal findings (fixed/ignored, last seen >${fdays}d ago),"
    Write-Warning "journal: metrics rows >${mdays}d, and runs rows >${rdays}d, then VACUUMs. Active"
    Write-Warning "journal: findings (open/regressed/in-review) are NEVER pruned. Backing up first."
    journal_backup 'pre-prune'
    _journal_write @"
DELETE FROM findings
  WHERE status IN ('fixed','ignored')
    AND last_seen_at < datetime('now','-$fdays days');
DELETE FROM metrics WHERE recorded_at < datetime('now','-$mdays days');
DELETE FROM runs    WHERE started_at  < datetime('now','-$rdays days');
VACUUM;
"@
    Write-Warning 'journal: prune complete (database vacuumed).'
}

# What journal_prune WOULD delete now, given the windows. Read-only (no DELETE).
function journal_prune_candidates {
    $fdays = if ($env:WATCHMAN_RETAIN_FINDINGS_DAYS) { [int]$env:WATCHMAN_RETAIN_FINDINGS_DAYS } else { 180 }
    $mdays = if ($env:WATCHMAN_RETAIN_METRICS_DAYS)  { [int]$env:WATCHMAN_RETAIN_METRICS_DAYS }  else { 90 }
    $rdays = if ($env:WATCHMAN_RETAIN_RUNS_DAYS)     { [int]$env:WATCHMAN_RETAIN_RUNS_DAYS }     else { 90 }
    if (-not (Test-Path -LiteralPath $script:JOURNAL_DB)) { "findings`t0"; "metrics`t0"; "runs`t0"; return }
    $f = _journal_sqlite "SELECT COUNT(*) FROM findings WHERE status IN ('fixed','ignored') AND last_seen_at < datetime('now','-$fdays days');"
    $m = _journal_sqlite "SELECT COUNT(*) FROM metrics WHERE recorded_at < datetime('now','-$mdays days');"
    $r = _journal_sqlite "SELECT COUNT(*) FROM runs WHERE started_at < datetime('now','-$rdays days');"
    "terminal findings >${fdays}d`t$f"
    "metrics rows >${mdays}d`t$m"
    "runs rows >${rdays}d`t$r"
}

# --- Fingerprint ------------------------------------------------------------
# Byte-identical to lib/journal.sh: sha256 over "family|profile|category|check_id|target" with
# NO trailing newline, lowercase hex. (printf '%s|...' | sha256sum on the bash side.)
function journal_fingerprint {
    param([string]$family, [string]$profile, [string]$category, [string]$check_id, [string]$target = '')
    $joined = "$family|$profile|$category|$check_id|$target"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($bytes) } finally { $sha.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

# --- Create-or-update -------------------------------------------------------
# The core Observe->Journal operation. Args mirror journal_upsert in journal.sh positionally:
#   family profile category severity risk_tier check_id target title detail remediation
function journal_upsert {
    param(
        [string]$family, [string]$profile, [string]$category, [string]$severity, [string]$risk_tier,
        [string]$check_id, [string]$target = '', [string]$title, [string]$detail = '', [string]$remediation = ''
    )
    # family/profile are machine constants. A skill may pass them explicitly, OR pass "" "" and let
    # the journal resolve them here (the dispatcher dot-sources distro.ps1/profile.ps1 first).
    if (-not $family)  { $family  = if (Get-Command watchman_family  -ErrorAction SilentlyContinue) { watchman_family }  else { 'unknown' } }
    if (-not $profile) { $profile = if (Get-Command watchman_profile -ErrorAction SilentlyContinue) { watchman_profile } else { 'unknown' } }
    $fp = journal_fingerprint $family $profile $category $check_id $target

    $ef = _sql_escape $family;      $ep = _sql_escape $profile
    $ec = _sql_escape $category;    $esv = _sql_escape $severity
    $ert = _sql_escape $risk_tier;  $ecid = _sql_escape $check_id
    $etg = _sql_escape $target;     $etl = _sql_escape $title
    $edt = _sql_escape $detail;     $erm = _sql_escape $remediation

    $sql = @"
INSERT INTO findings
    (fingerprint, family, profile, category, severity, risk_tier,
     check_id, target, title, detail, remediation, status,
     discovered_at, last_seen_at)
VALUES
    ('$fp','$ef','$ep','$ec','$esv','$ert','$ecid','$etg','$etl','$edt','$erm','open',
     datetime('now'), datetime('now'))
ON CONFLICT(fingerprint) DO UPDATE SET
    severity     = excluded.severity,
    risk_tier    = excluded.risk_tier,
    title        = excluded.title,
    detail       = excluded.detail,
    remediation  = excluded.remediation,
    last_seen_at = datetime('now'),
    status = CASE
                 WHEN findings.status = 'fixed'   THEN 'regressed'
                 WHEN findings.status = 'ignored' THEN 'ignored'
                 ELSE findings.status
             END;
"@
    _journal_write $sql | Out-Null
    return $fp
}

# --- Status & metrics -------------------------------------------------------
function journal_set_status {
    param([string]$fingerprint, [string]$new_status, [string]$note = '')
    $fp = _sql_escape $fingerprint
    $ns = _sql_escape $new_status
    $set_fix = if ($new_status -eq 'fixed') { ", fix_applied_at = datetime('now')" } else { '' }
    $set_note = if ($note) { ", notes = TRIM(notes || char(10) || '$(_sql_escape $note)')" } else { '' }
    _journal_write "UPDATE findings SET status='$ns'$set_fix$set_note WHERE fingerprint='$fp';" | Out-Null
}

function journal_record_metric {
    param([string]$name, [double]$value)
    $n = _sql_escape $name
    _journal_write "INSERT INTO metrics(name, value) VALUES('$n', $value);" | Out-Null
}

function journal_run_start {
    param([string]$kind = 'audit')
    $k = _sql_escape $kind
    $out = _journal_write "INSERT INTO runs(kind) VALUES('$k'); SELECT last_insert_rowid();"
    return ($out | Select-Object -Last 1)
}

function journal_run_finish {
    param([string]$id, [string]$summary = '')
    $s = _sql_escape $summary
    _journal_write "UPDATE runs SET finished_at=datetime('now'), summary='$s' WHERE id=$id;" | Out-Null
}

# --- Read helpers (no writes) ----------------------------------------------
function journal_count_open      { _journal_sqlite "SELECT COUNT(*) FROM findings WHERE status IN ('open','regressed');" }
function journal_count_regressed { _journal_sqlite "SELECT COUNT(*) FROM findings WHERE status='regressed';" }

function journal_list {
    param([string]$status = '')
    $where = if ($status) { "WHERE status='$(_sql_escape $status)'" } else { '' }
    _journal_sqlite @"
.mode column
.headers on
SELECT id, severity, risk_tier, status, category, title FROM findings $where ORDER BY
  CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
  last_seen_at DESC;
"@
}

function journal_get {
    param([string]$fingerprint)
    $fp = _sql_escape $fingerprint
    _journal_sqlite "SELECT id,fingerprint,severity,risk_tier,status,category,title,detail,remediation FROM findings WHERE fingerprint='$fp';"
}
