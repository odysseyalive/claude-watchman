# lib/io-courtesy.ps1 — be a good guest, but know your role and your own footprint
# (Windows-native PowerShell port of lib/io-courtesy.sh).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# This module keeps claude-watchman's heavy reads (integrity verification, full + rotated log
# scans, native hardening scans) from degrading the machine's real job — AND adapts to the case
# where claude-watchman is the most important thing on the box, AND measures what it costs.
#
#   1. io_run            — run a heavy command at a PriorityClass chosen by the declared ROLE
#                          (guest/peer/priority), under a timeout.
#   2. io_should_defer_heavy / io_pressure_high — true when the box is under enough real pressure
#                          to SKIP a heavy step this pass. Windows has NO PSI analogue, so this
#                          mirrors the Darwin no-PSI fallback shape: it samples performance
#                          counters (disk time, free memory, processor time) via Get-Counter.
#                          The defer thresholds scale by role.
#   3. io_measure        — run a command politely AND record what watchman spent on it (wall
#                          seconds; filesystem I/O bytes via process IO counters), so the monitor
#                          can analyze and bound its OWN footprint.
#
# ROLE (config WATCHMAN_PRIORITY): how hard claude-watchman yields.
#   guest    (default) — Idle process priority, defer at the configured thresholds.
#   peer               — BelowNormal priority, defer only under REAL pressure (2x).
#   priority           — claude-watchman is critical (dedicated monitor): Normal priority,
#                        defer only under EXTREME pressure (4x) so it keeps running.
#
# Config: WATCHMAN_PRIORITY, WATCHMAN_IONICE, WATCHMAN_IO_TIMEOUT, WATCHMAN_IO_GUARD,
# WATCHMAN_IO_GUARD_PSI (here: disk-busy %), WATCHMAN_IO_GUARD_LOAD (processor-time fallback),
# WATCHMAN_IO_GUARD_MEM_PCT, WATCHMAN_CHECK_TIME_BUDGET. Read-only and non-destructive: it only
# ever lowers its own priority or declines to run.

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# io_cpus — logical processor count; falls back to 1 when nothing reports it.
function io_cpus {
    $n = $null
    try { $n = [int][Environment]::ProcessorCount } catch { $n = $null }
    if (-not $n -or $n -lt 1) {
        try { $n = [int](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors } catch { $n = $null }
    }
    if (-not $n -or $n -lt 1) { $n = 1 }
    return [string]$n
}

function _io_role { if ($env:WATCHMAN_PRIORITY) { return $env:WATCHMAN_PRIORITY } else { return 'guest' } }

# Defer-threshold multiplier by role (higher role tolerates more before backing off).
function _io_role_mult {
    switch (_io_role) {
        'priority' { return 4 }
        'peer'     { return 2 }
        default    { return 1 }
    }
}

# Map the role to a .NET ProcessPriorityClass (the Windows analogue of ionice/nice tiers).
function _io_role_priorityclass {
    switch (_io_role) {
        'priority' { return 'Normal' }        # do not deprioritize a dedicated monitor
        'peer'     { return 'BelowNormal' }   # low-but-normal
        default    { return 'Idle' }          # idle (guest)
    }
}

# io_run <cmd> [args...] — run a heavy command at the role's process priority, under a timeout.
# On Windows the priority is applied to the started process; the timeout caps wall time. When the
# courtesy layer can't start a managed process it falls back to running the command directly.
function io_run {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$cmd)
    if (-not $cmd -or $cmd.Count -eq 0) { return }
    $exe = $cmd[0]
    $rest = if ($cmd.Count -gt 1) { $cmd[1..($cmd.Count - 1)] } else { @() }
    $timeout = 300
    if ($env:WATCHMAN_IO_TIMEOUT) { try { $timeout = [int]$env:WATCHMAN_IO_TIMEOUT } catch { $timeout = 300 } }

    # WATCHMAN_IONICE=no disables the priority shaping but keeps the timeout.
    $shape = ($env:WATCHMAN_IONICE -ne 'no')

    # Resolve to a real executable; if we can't (or can't manage a process), run inline.
    $resolved = $null
    try { $resolved = (Get-Command $exe -ErrorAction Stop).Source } catch { $resolved = $null }

    if (-not $resolved) {
        # Not an external program (e.g. a PS function/cmdlet): run inline, best-effort, no priority.
        try { return (& $exe @rest) } catch { [Console]::Error.WriteLine("io_run: $($_.Exception.Message)"); return }
    }

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $resolved
        foreach ($a in $rest) { [void]$psi.ArgumentList.Add([string]$a) }
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        if ($shape) {
            try { $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass](_io_role_priorityclass) } catch {}
        }
        $stdout = $p.StandardOutput.ReadToEndAsync()
        $stderr = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($timeout * 1000)) {
            try { $p.Kill($true) } catch { try { $p.Kill() } catch {} }
            [Console]::Error.WriteLine("io_run: '$exe' exceeded ${timeout}s timeout — killed.")
        }
        $o = $stdout.GetAwaiter().GetResult()
        $e = $stderr.GetAwaiter().GetResult()
        if ($e) { [Console]::Error.Write($e) }
        if ($o) { return ($o -split "`r?`n") } else { return }
    } catch {
        # Could not manage a process — degrade to a direct, unshaped invocation.
        try { return (& $resolved @rest) } catch { [Console]::Error.WriteLine("io_run: $($_.Exception.Message)"); return }
    }
}

# _io_counter <path> — sample a single performance counter, or $null when unavailable.
function _io_counter([string]$path) {
    if (-not (_have 'Get-Counter')) { return $null }
    try {
        $s = Get-Counter -Counter $path -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
        return [double]$s.CounterSamples[0].CookedValue
    } catch { return $null }
}

# io_pressure_high — TRUE when we should DEFER a heavy step. Windows has NO PSI, so (mirroring the
# Darwin no-PSI fallback) it samples performance counters: disk-busy %, then processor time / core,
# then free-memory %. Thresholds scale by role. FALSE when the guard is off or nothing is over.
function io_pressure_high {
    if ($env:WATCHMAN_IO_GUARD -eq 'no') { return $false }
    $mult = _io_role_mult

    # Primary signal: PhysicalDisk(_Total)\% Disk Time — the closest I/O-busy analogue to PSI/io.
    $diskBase = 20.0
    if ($env:WATCHMAN_IO_GUARD_PSI) { try { $diskBase = [double]$env:WATCHMAN_IO_GUARD_PSI } catch { $diskBase = 20.0 } }
    $diskThr = $diskBase * $mult
    $disk = _io_counter '\PhysicalDisk(_Total)\% Disk Time'
    if ($null -ne $disk) {
        if ($disk -gt $diskThr) { return $true }
    }

    # Fallback signal: processor time per core (the load-average analogue).
    $loadBase = 1.5
    if ($env:WATCHMAN_IO_GUARD_LOAD) { try { $loadBase = [double]$env:WATCHMAN_IO_GUARD_LOAD } catch { $loadBase = 1.5 } }
    # % Processor Time is 0..100; express per-core load on the 0..N scale by dividing by 100.
    $loadThr = $loadBase * $mult
    $cpu = _io_counter '\Processor Information(_Total)\% Processor Time'
    if ($null -eq $cpu) { $cpu = _io_counter '\Processor(_Total)\% Processor Time' }
    if ($null -ne $cpu) {
        $per = $cpu / 100.0
        if ($per -gt $loadThr) { return $true }
    }

    # Memory pressure: free physical memory below the configured percentage.
    $memPctFloor = 10
    if ($env:WATCHMAN_IO_GUARD_MEM_PCT) { try { $memPctFloor = [int]$env:WATCHMAN_IO_GUARD_MEM_PCT } catch { $memPctFloor = 10 } }
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $tot = [double]$os.TotalVisibleMemorySize
        $free = [double]$os.FreePhysicalMemory
        if ($tot -gt 0) {
            $pct = ($free * 100.0) / $tot
            if ($pct -lt $memPctFloor) { return $true }
        }
    } catch {}

    return $false
}

function io_should_defer_heavy { return (io_pressure_high) }

# io_pressure_reason — one-line human explanation (names the actual signal used).
function io_pressure_reason {
    $role = _io_role
    $mult = _io_role_mult

    $diskBase = 20.0
    if ($env:WATCHMAN_IO_GUARD_PSI) { try { $diskBase = [double]$env:WATCHMAN_IO_GUARD_PSI } catch { $diskBase = 20.0 } }
    $disk = _io_counter '\PhysicalDisk(_Total)\% Disk Time'
    if ($null -ne $disk) {
        $thr = $diskBase * $mult
        return ("role={0}; disk busy (PhysicalDisk %% Disk Time) {1:0.#}%% (limit {2:0.#}%%)" -f $role, $disk, $thr)
    }

    $loadBase = 1.5
    if ($env:WATCHMAN_IO_GUARD_LOAD) { try { $loadBase = [double]$env:WATCHMAN_IO_GUARD_LOAD } catch { $loadBase = 1.5 } }
    $cpu = _io_counter '\Processor Information(_Total)\% Processor Time'
    if ($null -eq $cpu) { $cpu = _io_counter '\Processor(_Total)\% Processor Time' }
    $cpus = io_cpus
    $per = if ($null -ne $cpu) { $cpu / 100.0 } else { 0 }
    $thr = $loadBase * $mult
    return ("role={0}; processor time {1:0.##}/core (limit {2:0.##}/core), no PSI on Windows" -f $role, $per, $thr)
}

# io_measure <cmd> [args...] — run politely (via io_run) AND record watchman's own cost.
# Sets WATCHMAN_LAST_SECS (wall seconds) and WATCHMAN_LAST_IO (filesystem read/write bytes, from
# the process IO counters when a managed process is used). Stdout of the command passes through.
function io_measure {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$cmd)
    $env:WATCHMAN_LAST_SECS = '0'
    $env:WATCHMAN_LAST_IO = ''
    if (-not $cmd -or $cmd.Count -eq 0) { return }

    $exe = $cmd[0]
    $rest = if ($cmd.Count -gt 1) { $cmd[1..($cmd.Count - 1)] } else { @() }
    $timeout = 300
    if ($env:WATCHMAN_IO_TIMEOUT) { try { $timeout = [int]$env:WATCHMAN_IO_TIMEOUT } catch { $timeout = 300 } }
    $shape = ($env:WATCHMAN_IONICE -ne 'no')

    $resolved = $null
    try { $resolved = (Get-Command $exe -ErrorAction Stop).Source } catch { $resolved = $null }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $resolved) {
        # Inline command — measure wall time only (no per-process IO counters available).
        try { $out = & $exe @rest } catch { [Console]::Error.WriteLine("io_measure: $($_.Exception.Message)"); $out = $null }
        $sw.Stop()
        $env:WATCHMAN_LAST_SECS = [string][int][math]::Round($sw.Elapsed.TotalSeconds)
        return $out
    }

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $resolved
        foreach ($a in $rest) { [void]$psi.ArgumentList.Add([string]$a) }
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        if ($shape) {
            try { $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass](_io_role_priorityclass) } catch {}
        }
        $stdout = $p.StandardOutput.ReadToEndAsync()
        $stderr = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($timeout * 1000)) {
            try { $p.Kill($true) } catch { try { $p.Kill() } catch {} }
            [Console]::Error.WriteLine("io_measure: '$exe' exceeded ${timeout}s timeout — killed.")
        }
        # Capture the process IO byte counters before the handle is gone. Win32_Process exposes
        # ReadTransferCount / WriteTransferCount — the GNU-time "File system inputs/outputs" analogue.
        $ioBytes = $null
        try {
            $wp = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction SilentlyContinue
            if ($wp) {
                $readBytes = [int64]$wp.ReadTransferCount
                $writeBytes = [int64]$wp.WriteTransferCount
                if ($readBytes -or $writeBytes) { $ioBytes = "$readBytes read / $writeBytes write (bytes)" }
            }
        } catch {}
        $o = $stdout.GetAwaiter().GetResult()
        $e = $stderr.GetAwaiter().GetResult()
        $sw.Stop()
        $env:WATCHMAN_LAST_SECS = [string][int][math]::Round($sw.Elapsed.TotalSeconds)
        if ($ioBytes) { $env:WATCHMAN_LAST_IO = $ioBytes }
        if ($e) { [Console]::Error.Write($e) }
        if ($o) { return ($o -split "`r?`n") } else { return }
    } catch {
        $sw.Stop()
        $env:WATCHMAN_LAST_SECS = [string][int][math]::Round($sw.Elapsed.TotalSeconds)
        [Console]::Error.WriteLine("io_measure: $($_.Exception.Message)")
        return
    }
}

# io_footprint_over_budget — TRUE if the last io_measure'd check exceeded the budget.
function io_footprint_over_budget {
    $secs = 0.0
    if ($env:WATCHMAN_LAST_SECS) { try { $secs = [double]$env:WATCHMAN_LAST_SECS } catch { $secs = 0.0 } }
    $budget = 120.0
    if ($env:WATCHMAN_CHECK_TIME_BUDGET) { try { $budget = [double]$env:WATCHMAN_CHECK_TIME_BUDGET } catch { $budget = 120.0 } }
    return ($secs -gt $budget)
}

# io_footprint_summary — human one-liner for the self_footprint finding.
function io_footprint_summary {
    $secs = if ($env:WATCHMAN_LAST_SECS) { $env:WATCHMAN_LAST_SECS } else { '0' }
    if ($env:WATCHMAN_LAST_IO) { return "${secs}s, $($env:WATCHMAN_LAST_IO)" } else { return "${secs}s" }
}
