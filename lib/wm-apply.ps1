#!/usr/bin/env pwsh
# lib/wm-apply.ps1 — the APPLY dispatcher (fixer only). PowerShell port of the `WM_APPLY=1` path.
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# This is the ONLY script permitted to run a system-mutating function. It is a DISTINCT command
# name from wm.ps1 precisely so the loop allowlist (which names only wm.ps1) cannot reach it —
# under dontAsk the loop auto-denies any `wm-apply.ps1` invocation. The FIX profile grants it
# per-mutator and SAFE-tier only (`PowerShell(pwsh -NoProfile -File lib/wm-apply.ps1 <op>:*)`);
# review-tier ops are left ungranted so default mode prompts per finding; manual is never granted.
#
# Skills invoke (fixer only):  pwsh -NoProfile -File lib/wm-apply.ps1 <function> [args...]

$ErrorActionPreference = 'Stop'
$libDir = $PSScriptRoot
if ($env:WATCHMAN_ROOT) { Set-Location -LiteralPath $env:WATCHMAN_ROOT }
else { $env:WATCHMAN_ROOT = (Split-Path -Parent $libDir); Set-Location -LiteralPath $env:WATCHMAN_ROOT }

. (Join-Path $libDir 'wm.mutators.ps1')
. (Join-Path $libDir 'wm.common.ps1')

# Dot-source the libs HERE, at script scope (see the note in wm.ps1).
foreach ($lib in (_wm_lib_order)) {
    $p = Join-Path $libDir $lib
    if (Test-Path -LiteralPath $p) { . $p }
}

$fn = if ($args.Count -ge 1) { [string]$args[0] } else { '' }
$rest = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }

# allowMutators = $true: mutators may run here. Read-only/journal functions also run (the fixer
# journals status transitions through the same dispatcher), so this is a superset of wm.ps1.
_wm_check_and_invoke $fn $rest $true
