# lib/wm.mutators.ps1 — the SINGLE source of the system-mutating function list.
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# This list is dot-sourced by BOTH dispatchers (wm.ps1 read-only, wm-apply.ps1 apply) so the
# two can never drift. It is the PowerShell analogue of _WM_MUTATORS in lib/wm. Adding a
# system-mutating function to the PS libs means adding it HERE in the SAME change, or the
# read-only seatbelt silently leaks.
#
# registry_set is Windows-only: a config edit on Windows often targets the registry, which
# cannot be reached through an Edit()/Write() permission rule and so must be a gated mutator.
# Journal writes (journal_upsert / journal_set_status / …) are the sanctioned create-or-update
# of the Prime Directive and are deliberately NOT mutators here.

$script:WM_MUTATORS = @(
    'firewall_allow'
    'firewall_deny'
    'service_enable'
    'service_restart'
    'pkg_install'
    'registry_set'
    'schedule_run'
    'schedule_install'
    'schedule_remove'
)

function _wm_is_mutator([string]$fn) { return $script:WM_MUTATORS -contains $fn }
