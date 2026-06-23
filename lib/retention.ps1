# lib/retention.ps1 — PowerShell port of lib/retention.sh: keep claude-watchman's own
# collected data (under journal/) from filling the host's disk.
#
# > **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# SEATBELT. retention_report / retention_total_mb / retention_file_candidates are READ-ONLY.
# retention_prune_files DELETES files and is therefore a MUTATOR — listed in
# lib/wm.mutators.ps1, so the read-only dispatcher (wm.ps1) refuses it; only the apply
# dispatcher (wm-apply.ps1), reachable solely from `watchman fix`, runs it. It NEVER touches
# findings.db (journal.ps1's job), the cost ledger, offsets, or the network baseline.

function _ret_journal_dir {
    if ($script:JOURNAL_DIR) { return $script:JOURNAL_DIR }
    if ($env:JOURNAL_DIR)    { return $env:JOURNAL_DIR }
    $root = if ($env:WATCHMAN_ROOT) { $env:WATCHMAN_ROOT } else { Split-Path -Parent $PSScriptRoot }
    return (Join-Path $root 'journal')
}

function _ret_bytes([string]$p) {
    if (Test-Path -LiteralPath $p -PathType Leaf) { return (Get-Item -LiteralPath $p).Length } else { return 0 }
}
function _ret_dir_bytes([string]$d) {
    if (-not (Test-Path -LiteralPath $d)) { return 0 }
    $sum = (Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Sum Length).Sum
    if ($sum) { return [long]$sum } else { return 0 }
}
function _ret_human([long]$b) {
    $u = @('B','KB','MB','GB','TB','PB'); $i = 0; $v = [double]$b
    while ($v -ge 1024 -and $i -lt 5) { $v /= 1024; $i++ }
    if ($i -eq 0) { return "$([long]$v)B" } else { return ('{0:N1}{1}' -f $v, $u[$i]) }
}
function _ret_backups {
    $d = _ret_journal_dir
    Get-ChildItem -LiteralPath $d -Filter 'findings.db.backup-*' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
}

# --- retention_report (READ-ONLY) -------------------------------------------
function retention_report {
    $d = _ret_journal_dir
    $total = [long]0
    $rows = @()
    function _row($bytes, $label) {
        $script:__rettotal += [long]$bytes
        "{0}`t{1}`t{2}" -f $bytes, (_ret_human ([long]$bytes)), $label
    }
    $script:__rettotal = [long]0
    $bk = @(_ret_backups); $bbytes = [long]0; foreach ($f in $bk) { $bbytes += $f.Length }
    $offsets = (_ret_bytes (Join-Path $d 'log-offsets.txt')) + (_ret_bytes (Join-Path $d 'monitor-offsets.txt')) + (_ret_bytes (Join-Path $d 'network-baseline.txt'))
    _row (_ret_bytes (Join-Path $d 'findings.db')) 'findings.db (active journal)'
    _row ((_ret_bytes (Join-Path $d 'findings.db-wal')) + (_ret_bytes (Join-Path $d 'findings.db-shm'))) 'findings.db WAL/SHM sidecars'
    _row (_ret_bytes (Join-Path $d 'run.log')) 'run.log (headless run log)'
    _row (_ret_bytes (Join-Path $d 'run-ledger.tsv')) 'run-ledger.tsv (cost ledger — reported, not auto-pruned)'
    _row $bbytes ("findings.db backups ($($bk.Count) file(s))")
    _row (_ret_dir_bytes (Join-Path $d 'monitor-state')) 'monitor-state/ (attended-watch snapshots)'
    _row $offsets 'offsets + network baseline (bounded)'
    "{0}`t{1}`t{2}" -f $script:__rettotal, (_ret_human $script:__rettotal), 'TOTAL (journal/ collected data)'
}

function retention_total_mb {
    $d = _ret_journal_dir
    $total = [long]0
    foreach ($f in @('findings.db','findings.db-wal','findings.db-shm','run.log','run-ledger.tsv','log-offsets.txt','monitor-offsets.txt','network-baseline.txt')) {
        $total += _ret_bytes (Join-Path $d $f)
    }
    $total += _ret_dir_bytes (Join-Path $d 'monitor-state')
    foreach ($f in @(_ret_backups)) { $total += $f.Length }
    [long]($total / 1MB)
}

# --- retention_file_candidates (READ-ONLY) ----------------------------------
function retention_file_candidates {
    $d = _ret_journal_dir
    $runlogMb = if ($env:WATCHMAN_RETAIN_RUNLOG_MB) { [int]$env:WATCHMAN_RETAIN_RUNLOG_MB } else { 10 }
    $keep     = if ($env:WATCHMAN_RETAIN_BACKUPS)   { [int]$env:WATCHMAN_RETAIN_BACKUPS }   else { 5 }
    $monDays  = if ($env:WATCHMAN_RETAIN_MONITOR_DAYS) { [int]$env:WATCHMAN_RETAIN_MONITOR_DAYS } else { 30 }

    $rlb = _ret_bytes (Join-Path $d 'run.log')
    if ($rlb -gt ($runlogMb * 1MB)) {
        "1`t$rlb`t$(_ret_human $rlb)`trun.log over ${runlogMb}MB -> rotate (keep recent tail)"
    }

    $bk = @(_ret_backups)
    if ($bk.Count -gt $keep) {
        $old = $bk[$keep..($bk.Count-1)]
        $bytes = [long]0; foreach ($f in $old) { $bytes += $f.Length }
        "$($old.Count)`t$bytes`t$(_ret_human $bytes)`told findings.db backups beyond newest $keep -> delete"
    }

    $ms = Join-Path $d 'monitor-state'
    if (Test-Path -LiteralPath $ms) {
        $cutoff = (Get-Date).AddDays(-$monDays)
        $stale = @(Get-ChildItem -LiteralPath $ms -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff })
        if ($stale.Count -gt 0) {
            $bytes = [long]0; foreach ($f in $stale) { $bytes += $f.Length }
            "$($stale.Count)`t$bytes`t$(_ret_human $bytes)`tmonitor-state snapshots older than ${monDays}d -> delete"
        }
    }
}

# --- retention_prune_files (MUTATOR — wm-apply only) ------------------------
function retention_prune_files {
    $d = _ret_journal_dir
    $runlogMb  = if ($env:WATCHMAN_RETAIN_RUNLOG_MB)    { [int]$env:WATCHMAN_RETAIN_RUNLOG_MB }    else { 10 }
    $keep      = if ($env:WATCHMAN_RETAIN_BACKUPS)      { [int]$env:WATCHMAN_RETAIN_BACKUPS }      else { 5 }
    $monDays   = if ($env:WATCHMAN_RETAIN_MONITOR_DAYS) { [int]$env:WATCHMAN_RETAIN_MONITOR_DAYS } else { 30 }
    $keepLines = if ($env:WATCHMAN_RETAIN_RUNLOG_LINES) { [int]$env:WATCHMAN_RETAIN_RUNLOG_LINES } else { 2000 }

    Write-Warning "retention: PRUNE deletes claude-watchman's own collected files (run.log tail-rotated,"
    Write-Warning "retention: old findings.db backups removed, stale monitor-state cleared). findings.db,"
    Write-Warning "retention: the cost ledger, offsets and the network baseline are NOT touched."

    $rl = Join-Path $d 'run.log'
    if ((_ret_bytes $rl) -gt ($runlogMb * 1MB)) {
        try {
            $tail = Get-Content -LiteralPath $rl -Tail $keepLines -ErrorAction Stop
            Set-Content -LiteralPath $rl -Value $tail -ErrorAction Stop
            Write-Warning "retention: rotated run.log to its last $keepLines lines."
        } catch { Write-Warning 'retention: could not rotate run.log (left untouched).' }
    }

    $bk = @(_ret_backups)
    if ($bk.Count -gt $keep) {
        $removed = 0
        foreach ($f in $bk[$keep..($bk.Count-1)]) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue; $removed++ }
        if ($removed -gt 0) { Write-Warning "retention: removed $removed old findings.db backup(s) (kept newest $keep)." }
    }

    $ms = Join-Path $d 'monitor-state'
    if (Test-Path -LiteralPath $ms) {
        $cutoff = (Get-Date).AddDays(-$monDays)
        $stale = @(Get-ChildItem -LiteralPath $ms -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff })
        foreach ($f in $stale) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
        if ($stale.Count -gt 0) { Write-Warning "retention: removed $($stale.Count) stale monitor-state snapshot(s) (older than ${monDays}d)." }
    }

    Write-Warning 'retention: file prune complete.'
}
