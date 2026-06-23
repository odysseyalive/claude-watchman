#!/usr/bin/env pwsh
# lib/wm.ps1 — the READ-ONLY lib-function dispatcher (PowerShell port of `lib/wm`).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# WHY TWO SCRIPTS (the Windows seatbelt — see CLAUDE.md "Dispatcher + read-only seatbelt"):
#   On Linux the read-only seatbelt rides on a command PREFIX: the loop grants `Bash(bash lib/wm:*)`
#   and a mutation must be `WM_APPLY=1 bash lib/wm <fn>`, a DIFFERENT prefix the rule can't match.
#   PowerShell has no inline env-prefix, and Claude Code's PowerShell matcher is AST-based, so a
#   wildcard arg rule would also match a `-Apply` switch. The prefix-divergence therefore moves
#   into the COMMAND NAME: this read-only script (wm.ps1) is the only one the loop allowlist names
#   (`PowerShell(pwsh -NoProfile -File lib/wm.ps1:*)`), and the apply dispatcher (wm-apply.ps1) is
#   left un-named, so under dontAsk it auto-denies. Two independent seatbelts, same as Linux:
#     (1) the loop allowlist can't name the apply script;  (2) this script refuses every mutator.
#
# Adding a system-mutating function means adding it to lib/wm.mutators.ps1 in the SAME change.
#
# Skills invoke:  pwsh -NoProfile -File lib/wm.ps1 <function> [args...]
# (-NoProfile is load-bearing: it stops the user profile from shadowing cmdlets / altering
#  $PSModulePath and keeps the AST the permission matcher parses stable.)

$ErrorActionPreference = 'Stop'
$libDir = $PSScriptRoot
if ($env:WATCHMAN_ROOT) { Set-Location -LiteralPath $env:WATCHMAN_ROOT }
else { $env:WATCHMAN_ROOT = (Split-Path -Parent $libDir); Set-Location -LiteralPath $env:WATCHMAN_ROOT }

. (Join-Path $libDir 'wm.mutators.ps1')
. (Join-Path $libDir 'wm.common.ps1')

# Dot-source the libs HERE, at script scope, so their functions are visible to the dispatch
# (sourcing inside a helper function would scope them to that function and lose them).
foreach ($lib in (_wm_lib_order)) {
    $p = Join-Path $libDir $lib
    if (Test-Path -LiteralPath $p) { . $p }
}

$fn = if ($args.Count -ge 1) { [string]$args[0] } else { '' }
$rest = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }

# allowMutators = $false: this dispatcher refuses every name in $WM_MUTATORS, unconditionally.
_wm_check_and_invoke $fn $rest $false
