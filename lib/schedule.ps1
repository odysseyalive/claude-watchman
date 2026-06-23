# lib/schedule.ps1 — the OPTIONAL headless cadence (PowerShell port): run one monitoring loop pass
# with no interactive session, and manage the recurring Windows Task Scheduler trigger that fires it.
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# WHY THIS EXISTS. claude-watchman's PRIMARY cadence is Claude Code's built-in /loop inside a tmux
# session — visible, with a live token meter, re-attachable. But a /loop expires after ~7 days, so a
# host that must be watched indefinitely needs a persistent trigger that outlives any one session.
# This file is that SECOND method:
#   * `watchman run`              — performs ONE headless loop pass (claude -p).
#   * `watchman schedule install` — installs the recurring trigger (a Windows Scheduled Task, the
#                                   Windows analogue of the Linux systemd timer / cron) that fires `run`.
#   * `watchman schedule remove`  — tears the trigger back down.
#   * `watchman schedule status`  — shows the trigger + the token/cost ledger.
#
# TOKEN VISIBILITY (the reason a headless scheduler was originally rejected) is preserved WITHOUT a
# live meter: every headless pass records its tokens + cost to journal/run-ledger.tsv from
# `claude -p --output-format json`, and send-report folds a summary of that ledger into the email.
# `watchman schedule status` shows it too.
#
# SAFETY. The headless pass inherits the SAME read-only dontAsk loop profile as the tmux loop
# (auto-discovered from the repo's .claude/), so it can apply NOTHING. Installing/removing the
# trigger is a system change, so it is operator-confirmed (stop-warn-ask) and is NEVER reachable
# from the loop itself (wm.mutators.ps1 lists schedule_run/install/remove as mutators).
#
# Every Windows cmdlet (Register-ScheduledTask, claude, …) is guarded so this file also parses and
# smoke-runs on a non-Windows host — which is how the port is statically tested.

function _sched_root {
    if ($env:WATCHMAN_ROOT) { return $env:WATCHMAN_ROOT }
    return (Split-Path -Parent $PSScriptRoot)
}
$script:SCHED_ROOT    = _sched_root
$script:SCHED_LEDGER  = if ($env:SCHED_LEDGER) { $env:SCHED_LEDGER } else { Join-Path $script:SCHED_ROOT 'journal/run-ledger.tsv' }
$script:SCHED_RUNLOG  = if ($env:SCHED_RUNLOG) { $env:SCHED_RUNLOG } else { Join-Path $script:SCHED_ROOT 'journal/run.log' }
$script:SCHED_TASK    = 'claude-watchman-loop'   # Scheduled Task name (the Windows analogue of the unit/cron marker)
$script:SCHED_DEFAULT_INTERVAL = '6h'

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# --- the headless single pass (what the trigger fires) ----------------------
# Runs ONE `/watchman loop` pass headless under the auto-discovered read-only dontAsk loop profile,
# then records the pass's tokens + cost to the ledger so token use stays visible without a live
# meter. Returns claude's exit code via Wm-Exit. MUTATOR (listed in wm.mutators.ps1).
function schedule_run {
    if (-not (Test-Path -LiteralPath $script:SCHED_ROOT)) {
        [Console]::Error.WriteLine("watchman run: cannot find WATCHMAN_ROOT at $($script:SCHED_ROOT)")
        return (Wm-Exit 1)
    }
    Set-Location -LiteralPath $script:SCHED_ROOT
    if (-not (_have 'claude')) {
        [Console]::Error.WriteLine("watchman run: the 'claude' CLI is not on PATH — install Claude Code, and make sure")
        [Console]::Error.WriteLine("              the SYSTEM/run account has logged in once ('claude' then /login) so headless runs authenticate.")
        return (Wm-Exit 1)
    }

    New-Item -ItemType Directory -Force -Path (Join-Path $script:SCHED_ROOT 'journal') | Out-Null
    $started = Get-Date -Format o
    Add-Content -LiteralPath $script:SCHED_RUNLOG -Value "[$started] watchman run: starting headless loop pass"

    # Headless single pass. Natural-language prompt on purpose: Claude Code DROPS a startup positional
    # prompt that begins with '/', so "Run /watchman loop" (no leading slash) is what actually invokes
    # the loop. No --permission-mode / --settings override: claude auto-discovers the repo's .claude/
    # (the read-only dontAsk loop profile) from the working directory, exactly like the tmux loop.
    $rc = 0
    $out = ''
    try {
        $out = & claude -p 'Run /watchman loop' --output-format json 2>> $script:SCHED_RUNLOG
        $rc = $LASTEXITCODE
        if ($out -is [System.Array]) { $out = ($out -join "`n") }
    } catch {
        $rc = 1
        Add-Content -LiteralPath $script:SCHED_RUNLOG -Value "[$started] watchman run: claude invocation threw — $($_.Exception.Message)"
    }

    $parsed = $null
    if ($out) { try { $parsed = $out | ConvertFrom-Json } catch { $parsed = $null } }

    if ($parsed) {
        $cost     = if ($null -ne $parsed.total_cost_usd) { $parsed.total_cost_usd } else { 0 }
        $intok    = if ($parsed.usage -and $null -ne $parsed.usage.input_tokens)             { $parsed.usage.input_tokens }             else { 0 }
        $outtok   = if ($parsed.usage -and $null -ne $parsed.usage.output_tokens)            { $parsed.usage.output_tokens }            else { 0 }
        $cachetok = if ($parsed.usage -and $null -ne $parsed.usage.cache_read_input_tokens)  { $parsed.usage.cache_read_input_tokens }  else { 0 }
        $dur      = if ($null -ne $parsed.duration_ms) { $parsed.duration_ms } else { 0 }
        $turns    = if ($null -ne $parsed.num_turns)   { $parsed.num_turns }   else { 0 }
        $iserr    = if ($null -ne $parsed.is_error)    { ([string]$parsed.is_error).ToLower() } else { 'false' }
        # Append-only TSV: started, cost_usd, in_tok, out_tok, cache_tok, duration_ms, turns, is_error.
        $row = ($started, $cost, $intok, $outtok, $cachetok, $dur, $turns, $iserr) -join "`t"
        Add-Content -LiteralPath $script:SCHED_LEDGER -Value $row
        [Console]::Error.WriteLine("watchman run: pass complete — cost `$$cost, tokens $intok/$outtok in/out, $turns turns (rc=$rc)")
        Add-Content -LiteralPath $script:SCHED_RUNLOG -Value "[$started] watchman run: cost `$$cost tokens $intok/$outtok turns $turns rc=$rc"
    } else {
        [Console]::Error.WriteLine("watchman run: pass complete (rc=$rc; cost not recorded — no JSON output).")
        Add-Content -LiteralPath $script:SCHED_RUNLOG -Value "[$started] watchman run: cost not recorded (rc=$rc)"
    }
    return (Wm-Exit $rc)
}

# --- read-only ledger summary (folded into the email by send-report) --------
# Pure read: never mutates. Reachable through the dispatcher (pwsh wm.ps1 schedule_ledger_summary)
# so the report path can show what the scheduler spent. Returns the summary as string lines.
function schedule_ledger_summary {
    if (-not (Test-Path -LiteralPath $script:SCHED_LEDGER) -or `
        ((Get-Item -LiteralPath $script:SCHED_LEDGER).Length -eq 0)) {
        return '(no scheduled/headless runs recorded yet — token cost is shown live in the tmux /loop)'
    }
    $n = 0; $cost = 0.0; $intok = 0; $outtok = 0; $err = 0; $last = ''
    foreach ($line in (Get-Content -LiteralPath $script:SCHED_LEDGER)) {
        if (-not $line.Trim()) { continue }
        $f = $line -split "`t"
        if ($f.Count -lt 8) { continue }
        $n++
        $c = 0.0;  [void][double]::TryParse($f[1], [ref]$c); $cost += $c
        $i = 0;    [void][int]::TryParse($f[2], [ref]$i);    $intok += $i
        $o = 0;    [void][int]::TryParse($f[3], [ref]$o);    $outtok += $o
        if ($f[7] -eq 'true' -or $f[7] -eq '1') { $err++ }
        $last = $f[0]
    }
    return @(
        ("Scheduled (headless) runs recorded: {0}" -f $n),
        ("  total cost: `${0:N4}   tokens in/out: {1}/{2}   runs with errors: {3}" -f $cost, $intok, $outtok, $err),
        ("  most recent run: {0}" -f $last)
    )
}

# --- schedule management ----------------------------------------------------
# Confirm prompt, default No. Honors WATCHMAN_CONFIRM=yes for non-interactive operator confirmation
# (the Prime Directive's stop-warn-ask still applies — the operator sets this deliberately).
function _sched_confirm([string]$prompt) {
    if ($env:WATCHMAN_CONFIRM -eq 'yes') { return $true }
    $ans = ''
    try { $ans = Read-Host "$prompt [y/N]" } catch { $ans = '' }
    return ($ans -match '^[Yy]([Ee][Ss])?$')
}

# Validate the interval is <N>m|<N>h|<N>d (the form the trigger accepts).
function _sched_validate_interval([string]$iv) {
    if ($iv -match '^[0-9]+[mhd]$') { return $true }
    [Console]::Error.WriteLine("watchman schedule: interval '$iv' is invalid — use <N>m, <N>h, or <N>d (e.g. 30m, 6h, 1d).")
    return $false
}

# Map an <N>m|<N>h|<N>d interval to a [TimeSpan] for New-ScheduledTaskTrigger -RepetitionInterval.
# Returns $null on a bad interval.
function _sched_interval_timespan([string]$iv) {
    if ($iv -notmatch '^([0-9]+)([mhd])$') { return $null }
    $n = [int]$Matches[1]; $unit = $Matches[2]
    switch ($unit) {
        'm' { return (New-TimeSpan -Minutes $n) }
        'h' { return (New-TimeSpan -Hours $n) }
        'd' { return (New-TimeSpan -Days $n) }
    }
    return $null
}

# True if a claude-watchman Scheduled Task is already registered.
function _sched_task_exists {
    if (-not (_have 'Get-ScheduledTask')) { return $false }
    try {
        $t = Get-ScheduledTask -TaskName $script:SCHED_TASK -ErrorAction SilentlyContinue
        return [bool]$t
    } catch { return $false }
}

# schedule_install [--every <interval>]  — MUTATOR (listed in wm.mutators.ps1).
# Registers a Windows Scheduled Task that fires `watchman run` on a repeating interval, running as
# SYSTEM with highest privileges. Operator-confirmed (stop-warn-ask).
function schedule_install {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$rest)
    $interval = $script:SCHED_DEFAULT_INTERVAL
    $i = 0
    while ($i -lt $rest.Count) {
        $a = $rest[$i]
        if ($a -eq '--every') { $interval = $rest[$i + 1]; $i += 2; continue }
        elseif ($a -like '--every=*') { $interval = $a.Substring(8); $i += 1; continue }
        # --cron / --systemd are Linux-only mechanisms; accept-and-ignore so a shared caller's flags
        # don't error on Windows (the only mechanism here is Task Scheduler).
        elseif ($a -eq '--cron' -or $a -eq '--systemd') { $i += 1; continue }
        else { [Console]::Error.WriteLine("watchman schedule install: unknown argument '$a'."); return (Wm-Exit 2) }
    }
    if (-not (_sched_validate_interval $interval)) { return (Wm-Exit 2) }

    if (-not (_have 'Register-ScheduledTask')) {
        [Console]::Error.WriteLine('watchman schedule: the ScheduledTasks module is unavailable — this host is not Windows or lacks Task Scheduler.')
        return (Wm-Exit 1)
    }

    $ts = _sched_interval_timespan $interval
    if (-not $ts) { [Console]::Error.WriteLine("watchman schedule: bad interval '$interval'."); return (Wm-Exit 2) }

    if (_sched_task_exists) {
        [Console]::Error.WriteLine("watchman schedule: a '$($script:SCHED_TASK)' task already exists. Run 'watchman schedule remove' first to re-install.")
        return (Wm-Exit 1)
    }

    $runnerPwsh = if (Get-Process -Id $PID -ErrorAction SilentlyContinue) {
        try { (Get-Process -Id $PID).Path } catch { 'pwsh' }
    } else { 'pwsh' }
    if (-not $runnerPwsh) { $runnerPwsh = 'pwsh' }
    $watchmanScript = Join-Path $script:SCHED_ROOT 'bin\watchman.ps1'

    [Console]::Error.WriteLine('')
    [Console]::Error.WriteLine('watchman schedule: this is a SYSTEM CHANGE. It will register a Windows Scheduled Task that')
    [Console]::Error.WriteLine("runs a headless monitoring pass every $interval, executing as SYSTEM with highest privileges:")
    [Console]::Error.WriteLine("    Task name: $($script:SCHED_TASK)")
    [Console]::Error.WriteLine("    Action:    $runnerPwsh -NoProfile -File `"$watchmanScript`" run")
    [Console]::Error.WriteLine('It does NOT stop or alter any other service, and it is fully reversible with')
    [Console]::Error.WriteLine("'watchman schedule remove'. The headless pass is read-only (it can apply no fixes).")
    if (-not (_sched_confirm 'Register the Scheduled Task now?')) {
        [Console]::Error.WriteLine('watchman schedule: aborted, nothing changed.')
        return (Wm-Exit 1)
    }

    try {
        $action  = New-ScheduledTaskAction -Execute $runnerPwsh -Argument "-NoProfile -File `"$watchmanScript`" run" -WorkingDirectory $script:SCHED_ROOT
        # Repeat every <interval>, starting 5 minutes from now, for an effectively unbounded duration.
        $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(5)) -RepetitionInterval $ts -RepetitionDuration ([TimeSpan]::MaxValue)
        # Run as SYSTEM (highest available) so it reads every log/config, like root on Linux.
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $script:SCHED_TASK -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings `
            -Description 'claude-watchman — recurring headless monitoring loop pass' -Force | Out-Null
    } catch {
        [Console]::Error.WriteLine("watchman schedule: failed to register the Scheduled Task — $($_.Exception.Message)")
        return (Wm-Exit 1)
    }
    [Console]::Error.WriteLine("watchman schedule: Scheduled Task '$($script:SCHED_TASK)' installed (every $interval).")
    return (Wm-Exit 0)
}

# schedule_status — read-only: report whether the task is installed + the ledger.
function schedule_status {
    [Console]::Error.WriteLine('claude-watchman schedule status')
    if (_sched_task_exists) {
        try {
            $t = Get-ScheduledTask -TaskName $script:SCHED_TASK -ErrorAction Stop
            [Console]::Error.WriteLine("  Scheduled Task: $($script:SCHED_TASK)  (state: $($t.State))")
            if (_have 'Get-ScheduledTaskInfo') {
                try {
                    $info = Get-ScheduledTaskInfo -TaskName $script:SCHED_TASK -ErrorAction Stop
                    [Console]::Error.WriteLine("    last run:  $($info.LastRunTime)  (result: $($info.LastTaskResult))")
                    [Console]::Error.WriteLine("    next run:  $($info.NextRunTime)")
                } catch {}
            }
        } catch {
            [Console]::Error.WriteLine("  Scheduled Task: $($script:SCHED_TASK)  (present; details unavailable)")
        }
    } else {
        [Console]::Error.WriteLine('  no headless schedule installed (the tmux /loop is the other cadence — see README).')
    }
    [Console]::Error.WriteLine('  --- token / cost ledger (headless runs) ---')
    foreach ($line in (schedule_ledger_summary)) { [Console]::Error.WriteLine($line) }
}

# schedule_remove — MUTATOR (listed in wm.mutators.ps1). Tear down the Scheduled Task. Unregistering
# a task is destructive (it ends the recurring headless loop), so it is confirmed (default No) per
# the Prime Directive. Removes ONLY claude-watchman's own task; never touches other tasks.
function schedule_remove {
    if (-not (_have 'Unregister-ScheduledTask')) {
        [Console]::Error.WriteLine('watchman schedule: the ScheduledTasks module is unavailable — nothing to remove.')
        return (Wm-Exit 1)
    }
    if (-not (_sched_task_exists)) {
        [Console]::Error.WriteLine('watchman schedule: no claude-watchman schedule found to remove.')
        return (Wm-Exit 0)
    }
    [Console]::Error.WriteLine('')
    [Console]::Error.WriteLine('watchman schedule remove: this will UNREGISTER and DELETE the Scheduled Task (a system')
    [Console]::Error.WriteLine('change — it ends the recurring headless loop):')
    [Console]::Error.WriteLine("    Unregister-ScheduledTask -TaskName $($script:SCHED_TASK)")
    [Console]::Error.WriteLine('No other task is affected.')
    if (-not (_sched_confirm 'Remove the Scheduled Task now?')) {
        [Console]::Error.WriteLine('watchman schedule: left the Scheduled Task in place.')
        return (Wm-Exit 1)
    }
    try {
        Unregister-ScheduledTask -TaskName $script:SCHED_TASK -Confirm:$false -ErrorAction Stop | Out-Null
    } catch {
        [Console]::Error.WriteLine("watchman schedule: failed to unregister the Scheduled Task — $($_.Exception.Message)")
        return (Wm-Exit 1)
    }
    [Console]::Error.WriteLine('watchman schedule: Scheduled Task removed.')
    return (Wm-Exit 0)
}
