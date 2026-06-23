#!/usr/bin/env pwsh
# bin/watchman.ps1 — the operator's SHELL entrypoint on Windows (PowerShell port of bin/watchman).
# Runs ONLY the zero-token verbs; the AI features run IN a Claude Code session so token use is
# visible. Verb contract matches bin/watchman exactly.
#
# > PRIME DIRECTIVE: this dispatcher never performs destructive actions itself — even the fix/dev
# > verbs only LAUNCH a Claude Code session bound to a generated profile. The loop runs
# > observe/report only (its dontAsk allowlist makes applying a fix impossible with no operator
# > present); remediation lives in the FIX profile, where "default" mode prompts per finding and
# > the deny base still blocks destruction. STOP-WARN-ASK governs anything destructive.

$ErrorActionPreference = 'Stop'
$binDir = $PSScriptRoot
$env:WATCHMAN_ROOT = if ($env:WATCHMAN_ROOT) { $env:WATCHMAN_ROOT } else { Split-Path -Parent $binDir }
$env:WATCHMAN_CLAUDE_DIR = if ($env:WATCHMAN_CLAUDE_DIR) { $env:WATCHMAN_CLAUDE_DIR } else { Join-Path $env:WATCHMAN_ROOT '.claude' }
$root = $env:WATCHMAN_ROOT
$libDir = Join-Path $root 'lib'

function _have([string]$n) { return [bool](Get-Command $n -ErrorAction SilentlyContinue) }

# Dot-source the runtime libs (the dispatcher's lib order) at SCRIPT scope so their functions
# persist for the verb dispatch below (dot-sourcing inside a function would lose them on return).
. (Join-Path $libDir 'wm.mutators.ps1')
. (Join-Path $libDir 'wm.common.ps1')
foreach ($lib in (_wm_lib_order)) {
    $p = Join-Path $libDir $lib
    if (Test-Path -LiteralPath $p) { . $p }
}

# CLI-only libs are loaded on demand (also at script scope — see _load_cli usage before the switch).
$script:CLI_LIB = @{ selfcheck = 'selfcheck.ps1'; preflight = 'preflight.ps1'; update = 'update.ps1'; uninstall = 'uninstall.ps1' }

function _usage {
    @'
watchman — claude-watchman shell CLI (Windows). Zero-token verbs:

  watchman selfcheck   Direct plumbing check (NO Claude) — run this FIRST on any new host.
  watchman preflight   Regenerate the Claude permission profiles + in-session commands (NO Claude).
  watchman update      Re-fetch the latest product from the manifest (NO git) + regenerate locals.
                       Maintainer subflags: --check (release guard), --sync (regenerate manifest.txt).
  watchman testmail    Send one test email to verify the .env SMTP credentials deliver.
  watchman uninstall   Remove claude-watchman in tiers, each behind a confirmation (default No).

Session launchers — each starts Claude Code in its OWN permission profile:
  watchman safe        Read-only session under the DEFAULT profile (observe only; applies nothing).
  watchman audit       DEFAULT read-only session, opened running /watchman audit.
  watchman report      DEFAULT read-only session, opened running /watchman report.
  watchman fix         Remediation session — FIX profile, default mode (per-finding prompts).
  watchman dev         Maintainer session — DEV profile, acceptEdits, repo-write.

Run inside a session (watchman safe, then type):
  /watchman loop        ONE pass: observe -> journal -> correlate delta -> conditional send-report.
  /watchman inventory   What is installed and how it serves.

Recurring monitoring — two cadences:
  1. VISIBLE: a tmux-style persistent session with /loop 6h /watchman loop (live token meter; ~7-day expiry).
  2. PERSISTENT/HEADLESS: a Task Scheduler trigger fires 'watchman run' on an interval; token cost
     is logged per run to journal/run-ledger.tsv and folded into the email report.
         watchman schedule install --every 6h
         watchman schedule status
         watchman schedule remove
  Headless runs are read-only, exactly like the loop: they can apply no fixes.
'@ | Write-Host
}

function _redirect_to_session([string]$v) {
    [Console]::Error.WriteLine(@"
watchman: '$v' is an AI feature — it runs inside a Claude Code session, not the shell, so you can
see what it does and what it spends. Launch a session and run the slash command:

    claude                # /login once if needed
    /watchman $v
"@)
    exit 2
}

# Launch a Claude Code session bound to a generated profile (fix/dev). PowerShell has no exec, so
# we invoke claude and propagate its exit code. The autorun prompt must be NATURAL LANGUAGE (no
# leading '/') — Claude Code silently drops a startup positional that begins with '/'.
function _launch_session([string]$file, [string]$mode, [string]$note, [string]$hint, [string]$autorun = '') {
    $settings = Join-Path $env:WATCHMAN_CLAUDE_DIR $file
    if (-not (_have 'claude')) { [Console]::Error.WriteLine("watchman: the 'claude' CLI is not on PATH — install Claude Code first."); exit 1 }
    if (-not (Test-Path -LiteralPath $settings)) { [Console]::Error.WriteLine("watchman: $file not found — run 'watchman preflight' to generate it."); exit 1 }
    Set-Location -LiteralPath $root
    if ($autorun) {
        [Console]::Error.WriteLine("watchman: $note`nOpening a Claude Code session and running:  $autorun")
        & claude --permission-mode $mode --settings $settings $autorun
    } else {
        [Console]::Error.WriteLine("watchman: $note`nLaunching a Claude Code session in this profile. Inside it, run:  $hint")
        & claude --permission-mode $mode --settings $settings
    }
    exit $LASTEXITCODE
}

function _launch_default_session([string]$note, [string]$autorun = '') {
    if (-not (_have 'claude')) { [Console]::Error.WriteLine("watchman: the 'claude' CLI is not on PATH — install Claude Code first."); exit 1 }
    Set-Location -LiteralPath $root
    if ($autorun) {
        [Console]::Error.WriteLine("watchman: $note`nOpening a Claude Code session and running:  $autorun")
        & claude $autorun
    } else {
        [Console]::Error.WriteLine("watchman: $note")
        & claude
    }
    exit $LASTEXITCODE
}

$verb = if ($args.Count -ge 1) { [string]$args[0] } else { '' }
$rest = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }

# Load the CLI-only lib for this verb at SCRIPT scope (the runtime libs are already loaded above).
if ($script:CLI_LIB.ContainsKey($verb)) {
    $clp = Join-Path $libDir $script:CLI_LIB[$verb]
    if (Test-Path -LiteralPath $clp) { . $clp } else { [Console]::Error.WriteLine("watchman: $($script:CLI_LIB[$verb]) not found"); exit 1 }
}

switch ($verb) {
    'selfcheck' { if (selfcheck_run) { exit 0 } else { exit 1 } }
    'preflight' {
        preflight_run
        Write-Host 'watchman: preflight complete (allowlist + in-session commands regenerated).'
    }
    'update' {
        switch ($rest[0]) {
            '--check' { update_check_run }
            '--sync'  { update_sync_run }
            default   { update_run }
        }
    }
    'testmail'  { smtp_send_test }
    'uninstall' { uninstall_run @rest }
    'run'       { schedule_run @rest }
    'schedule'  {
        switch ($rest[0]) {
            'install' { schedule_install @($rest | Select-Object -Skip 1) }
            'remove'  { schedule_remove @($rest | Select-Object -Skip 1) }
            'status'  { schedule_status @($rest | Select-Object -Skip 1) }
            default   {
                Write-Host 'watchman schedule — manage the headless cadence (Task Scheduler).'
                Write-Host '  watchman schedule install [--every <N>m|<N>h|<N>d]'
                Write-Host '  watchman schedule remove'
                Write-Host '  watchman schedule status'
            }
        }
    }
    'loop'      { _redirect_to_session 'loop' }
    'inventory' { _redirect_to_session 'inventory' }
    'safe'      { _launch_default_session 'read-only session under the default profile. To APPLY a fix, exit and run ''watchman fix''.' }
    'audit'     { _launch_default_session 'observe + analyze under the default read-only profile; journals findings, applies NO fixes.' 'Run /watchman audit' }
    'report'    { _launch_default_session 'report session under the default read-only profile (journal summary; read-only).' 'Run /watchman report' }
    'fix'       { _launch_session 'settings.fix.json' 'default' 'remediation session — per-finding prompts, safe fixes pre-approved, destructive ops denied.' '/watchman fix' 'Run /watchman fix' }
    'dev'       { _launch_session 'settings.dev.json' 'acceptEdits' "maintainer session — source edits in $root auto-apply; PowerShell still prompts." 'your editing / development work (no /watchman verb required)' }
    { $_ -in @('', '-h', '--help', 'help') } { _usage; exit 0 }
    default { [Console]::Error.WriteLine("watchman: unknown verb '$verb'"); Write-Host ''; _usage; exit 2 }
}
