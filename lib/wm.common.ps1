# lib/wm.common.ps1 — shared dispatch core for the two PowerShell dispatchers.
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# Dot-sourced INTERNALLY by wm.ps1 and wm-apply.ps1 (invisible to the permission layer). It holds
# the library load ORDER and the call/output/exit-code mapping that preserves the bash dispatcher's
# contract: skills read predicate results via the PROCESS EXIT CODE and read data via STDOUT.
#
# NOTE: the actual dot-sourcing of the libs happens at the SCRIPT scope of wm.ps1 / wm-apply.ps1,
# NOT inside a function here — dot-sourcing inside a function would scope the loaded functions to
# that function and lose them on return. This file only PROVIDES the ordered list and the helpers.

# WmExit lets a status function signal a specific process exit code (e.g. autoupdate_enabled:
# 0=on / 1=off / 2=n-a) without that integer being mistaken for printable data.
class WmExit { [int]$Code; WmExit([int]$c) { $this.Code = $c } }
function Wm-Exit([int]$code) { return [WmExit]::new($code) }

# The observe/analyze/report libs in dependency order (core first), mirroring lib/wm. CLI-only
# libs (preflight/update/uninstall/selfcheck) are intentionally NOT listed.
function _wm_lib_order {
    return @(
        'wm.mutators.ps1',
        'journal.ps1', 'distro.ps1', 'profile.ps1', 'io-courtesy.ps1',
        'capacity.ps1', 'webstats.ps1', 'security_currency.ps1', 'cpanel.ps1',
        'sectools.ps1', 'shellhist.ps1', 'monitor.ps1', 'smtp.ps1', 'schedule.ps1'
    )
}

# Call the resolved function and translate its result into the process exit code + stdout,
# preserving bash semantics:
#   * returns a WmExit  -> that exact exit code, nothing printed
#   * returns a [bool]  -> $true => exit 0, $false => exit 1 (predicate convention)
#   * returns data      -> printed to stdout, exit 0
#   * throws            -> message to stderr, exit 1
function _wm_invoke([string]$fn, [object[]]$arglist) {
    try {
        $out = & $fn @arglist
    } catch {
        [Console]::Error.WriteLine("wm: $fn failed: $($_.Exception.Message)")
        exit 1
    }
    if ($out -is [System.Array] -and $out.Count -eq 1) { $out = $out[0] }
    if ($out -is [WmExit]) { exit $out.Code }
    if ($out -is [bool])   { if ($out) { exit 0 } else { exit 1 } }
    if ($null -ne $out) { $out | ForEach-Object { [Console]::Out.WriteLine([string]$_) } }
    exit 0
}

# Seatbelt + dispatch. Assumes the libs are ALREADY dot-sourced at the caller's script scope.
# $allowMutators is the ONLY behavioral difference between the read-only and apply dispatchers.
function _wm_check_and_invoke([string]$fn, [object[]]$arglist, [bool]$allowMutators) {
    if (-not $fn) {
        [Console]::Error.WriteLine('wm: usage: pwsh -NoProfile -File lib/wm.ps1 <function> [args...]')
        exit 2
    }
    if (-not (Get-Command $fn -CommandType Function -ErrorAction SilentlyContinue)) {
        [Console]::Error.WriteLine("wm: '$fn' is not a claude-watchman library function.")
        exit 2
    }
    if ((_wm_is_mutator $fn) -and (-not $allowMutators)) {
        [Console]::Error.WriteLine("wm: refusing system-mutating function '$fn' — the read-only dispatcher applies nothing.")
        [Console]::Error.WriteLine('wm: remediation runs in the FIX profile (watchman fix), which gates each change per the risk tier.')
        exit 3
    }
    _wm_invoke $fn $arglist
}
