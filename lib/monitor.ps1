# lib/monitor.ps1 — deterministic, read-only delta helpers for `/watchman monitor` (Windows port).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# Both functions are READ-ONLY: they read files/stdin and write ONLY their own gitignored scratch
# state (journal/monitor-offsets.txt and journal/monitor-state/<key>) — the same advisory-state
# category as the loop's log offsets, NOT a Prime-Directive database write. Neither mutates the
# system, so neither belongs in wm.mutators.ps1's $script:WM_MUTATORS.
#
# Rotation analogue: bash keys offsets by inode. NTFS exposes a stable per-file identity; we derive
# a token from it (FileId when available, else CreationTime ticks) so a rotated/recreated file is
# detected exactly as an inode change is on Linux. All file I/O uses .NET (FileStream/FileInfo) and
# is guarded so the file parses and smoke-runs on a non-Windows host.

function _monitor_root {
    if ($env:WATCHMAN_ROOT) { return $env:WATCHMAN_ROOT }
    return (Split-Path -Parent $PSScriptRoot)
}

# Where the per-file read offsets live (gitignored local state; keyed separately from the loop's
# journal/log-offsets.txt so monitor and the audit never fight over the same cursor).
function monitor_offset_file { return (Join-Path (_monitor_root) 'journal/monitor-offsets.txt') }
# Where command-snapshot baselines live (one file per watch key).
function monitor_state_dir   { return (Join-Path (_monitor_root) 'journal/monitor-state') }

# A stable identity token for a file (the inode analogue, used to detect rotation/recreation).
# Prefer the NTFS file id (the true rotation signal, like an inode). When it is unavailable (older
# hosts, or a non-Windows test box), fall back to a CONSTANT sentinel rather than a volatile field
# like CreationTime — an unstable token would look "rotated" every pass and defeat incremental
# reads; with the sentinel, rotation is not distinguished but the size/truncation guard below still
# correctly resets on truncation, which is the safety-critical case. Returns '' when unreadable.
function _monitor_identity {
    param([string]$path)
    try {
        $fi = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        # PowerShell 7+ surfaces the NTFS file id on FileInfo in some builds; guard for absence.
        try { if ($fi.PSObject.Properties['FileId'] -and $fi.FileId) { return [string]$fi.FileId } } catch {}
        return 'noid'
    } catch { return '' }
}

# Read bytes [start, end) of a file with .NET and write them to stdout as text. Mirrors `tail -c`.
function _monitor_read_from {
    param([string]$path, [long]$start)
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        if ($start -gt 0 -and $start -le $fs.Length) { [void]$fs.Seek($start, [System.IO.SeekOrigin]::Begin) }
        $reader = New-Object System.IO.StreamReader($fs)
        $text = $reader.ReadToEnd()
        $reader.Dispose()
        if ($text) { foreach ($l in ($text -split "`r?`n")) { [Console]::Out.WriteLine($l) } }
    } catch {
    } finally {
        if ($fs) { $fs.Dispose() }
    }
}

# monitor_file_delta <path…> — emit only the NEW bytes of each given file since the last pass, then
# advance the stored offset. Mirrors webstats_cat_logs_incremental:
#   * Same file (identity unchanged) and grown → read [offset, end] only.
#   * Rotated (identity changed) or truncated (size < offset) → read from 0 and reset.
# Offsets persist as TSV: <path> <identity> <size>. Heavy reads run at the role's I/O priority when
# lib/io-courtesy.ps1 is sourced.
function monitor_file_delta {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$paths)
    $ofile = monitor_offset_file
    $offId = @{}; $offSize = @{}
    if (Test-Path -LiteralPath $ofile) {
        try {
            foreach ($row in (Get-Content -LiteralPath $ofile -ErrorAction Stop)) {
                if (-not $row) { continue }
                $c = $row -split "`t"
                if ($c.Count -ge 3 -and $c[0]) { $offId[$c[0]] = $c[1]; $offSize[$c[0]] = $c[2] }
            }
        } catch {}
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    foreach ($f in $paths) {
        if (-not $f) { continue }
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { continue }
        $seen[$f] = $true
        $ident = _monitor_identity $f
        $size = $null
        try { $size = (Get-Item -LiteralPath $f -Force -ErrorAction Stop).Length } catch { $size = $null }
        if (-not $ident -or $null -eq $size) { continue }
        $size = [long]$size

        $start = [long]0
        if ($offId.ContainsKey($f) -and $offId[$f] -eq $ident -and $offSize.ContainsKey($f)) {
            $prev = [long]$offSize[$f]
            if ($size -ge $prev) { $start = $prev }
        }
        if ($size -gt $start) {
            if (Get-Command io_run -ErrorAction SilentlyContinue) {
                io_run { _monitor_read_from $f $start }
            } else {
                _monitor_read_from $f $start
            }
        }
        $lines.Add("$f`t$ident`t$size")
    }

    # Preserve cursors for any previously-tracked file not watched this pass.
    foreach ($pk in $offId.Keys) {
        if ($seen.ContainsKey($pk)) { continue }
        $ps = if ($offSize.ContainsKey($pk)) { $offSize[$pk] } else { '0' }
        $lines.Add("$pk`t$($offId[$pk])`t$ps")
    }

    # Atomically replace the offset file (write temp, move).
    try {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ofile) | Out-Null
        $tmp = "$ofile.tmp.$PID"
        Set-Content -LiteralPath $tmp -Value $lines -ErrorAction Stop
        Move-Item -LiteralPath $tmp -Destination $ofile -Force -ErrorAction Stop
    } catch {
        if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

# monitor_diff <key> — read a fresh snapshot on STDIN, print only the lines that are NEW relative to
# the previous snapshot stored for <key>, then save the snapshot as the new baseline. For
# snapshot-style watches (open connections, a result set) where there is no byte offset. <key> is
# sanitized to a safe filename. First pass (no baseline) emits the whole snapshot.
function monitor_diff {
    param([string]$key)
    if (-not $key) { [Console]::Error.WriteLine('monitor_diff: a watch key is required'); return (Wm-Exit 2) }
    $key = ($key -replace '[^A-Za-z0-9._-]', '_')
    $dir = monitor_state_dir
    try { New-Item -ItemType Directory -Force -Path $dir | Out-Null } catch {}
    $state = Join-Path $dir $key

    # Read the fresh snapshot from stdin.
    $fresh = @($input | ForEach-Object { [string]$_ })

    $emit = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $state) {
        $old = @{}
        try { foreach ($l in (Get-Content -LiteralPath $state -ErrorAction Stop)) { $old[$l] = $true } } catch {}
        foreach ($l in $fresh) { if (-not $old.ContainsKey($l)) { $emit.Add($l) } }
    } else {
        foreach ($l in $fresh) { $emit.Add($l) }
    }

    # Save the fresh snapshot as the new baseline (atomic write/move).
    try {
        $tmp = "$state.tmp.$PID"
        Set-Content -LiteralPath $tmp -Value $fresh -ErrorAction Stop
        Move-Item -LiteralPath $tmp -Destination $state -Force -ErrorAction Stop
    } catch {
        if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }

    if ($emit.Count -gt 0) { return $emit }
}
