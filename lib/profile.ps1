# lib/profile.ps1 — the resolver for the WHAT (PowerShell port of lib/profile.sh).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# Resolves which checks run and what severity they carry, based on whether the machine is a
# `server` or a `workstation`. The skills are the same shape in both profiles; the profile points
# them in the right direction. Pure resolution — no mutation. The check table is a VERBATIM copy
# of the one in lib/profile.sh so both platforms register identical checks/severities.

function _profile_root {
    if ($env:WATCHMAN_ROOT) { return $env:WATCHMAN_ROOT }
    return (Split-Path -Parent $PSScriptRoot)
}

# --- Profile detection ------------------------------------------------------
function watchman_profile {
    if ($env:WATCHMAN_PROFILE) { return $env:WATCHMAN_PROFILE }
    $conf = if ($env:WATCHMAN_CONF) { $env:WATCHMAN_CONF } else { Join-Path (_profile_root) 'config/watchman.conf' }
    if (Test-Path -LiteralPath $conf) {
        # watchman.conf is a shell-style KEY=VALUE file; read the one key we need by regex
        # rather than executing it (it is not PowerShell).
        $line = Select-String -LiteralPath $conf -Pattern '^\s*WATCHMAN_PROFILE\s*=' -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($line) {
            $val = ($line.Line -replace '^\s*WATCHMAN_PROFILE\s*=', '').Trim().Trim('"').Trim("'")
            if ($val) { $env:WATCHMAN_PROFILE = $val; return $val }
        }
    }
    # Heuristic default: the safer, quieter default is workstation.
    $env:WATCHMAN_PROFILE = 'workstation'
    return 'workstation'
}

# --- Which checks run -------------------------------------------------------
# Format: "check_id:server_severity:workstation_severity". A severity of "-" means the check
# does NOT run in that profile. Keep this in lockstep with _PROFILE_CHECK_TABLE in profile.sh.
$script:PROFILE_CHECK_TABLE = @'
audit_lynis_index:medium:low
web_security_headers:high:-
web_cors_policy:high:-
firewall_exposed_ports:high:medium
ssh_hardening:high:medium
inbound_attack_patterns:high:-
request_rate_spike:high:-
outbound_new_connections:-:high
mac_not_enforcing:medium:low
autoupdate_not_enabled:high:medium
log_retention_volatile:medium:high
log_rotation_missing:low:medium
journal_size_unbounded:low:medium
disk_capacity:high:medium
inode_capacity:medium:low
memory_pressure:medium:medium
oom_recent_kill:high:high
integrity_modified_files:high:medium
shell_history_integrity:high:high
security_currency:medium:medium
diagnostic_deferred:info:info
self_footprint:info:info
service_inventory:info:info
sectool_inventory:info:info
sectool_health:medium:low
defense_gap_bruteforce:medium:low
defense_gap_rootkit:low:-
defense_gap_audit:low:-
defense_gap_integrity:low:low
defense_gap_antivirus:low:low
cpanel_cphulk_disabled:high:-
cpanel_eol_php:medium:-
cpanel_autoupdate_off:medium:-
cpanel_update_tier:low:-
cpanel_mail_queue_spike:high:-
cpanel_mail_frozen:medium:-
cpanel_csf_orphaned:medium:-
cpanel_imunify_malware:high:-
cpanel_rpm_altered:high:-
'@

function _profile_rows {
    $script:PROFILE_CHECK_TABLE -split "`n" |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and ($_ -split ':').Count -ge 3 } |
        ForEach-Object { $p = $_ -split ':'; [pscustomobject]@{ id = $p[0]; server = $p[1]; workstation = $p[2] } }
}

# Echo the applicable check_ids for the profile (one per line).
function profile_checks {
    param([string]$prof = (watchman_profile))
    $col = if ($prof -eq 'server') { 'server' } else { 'workstation' }
    _profile_rows | Where-Object { $_.$col -ne '-' } | ForEach-Object { $_.id }
}

# Echo the severity a given check carries in the active (or given) profile.
# Prints "skip" if the check does not run in that profile.
function profile_severity {
    param([string]$check_id, [string]$prof = (watchman_profile))
    $col = if ($prof -eq 'server') { 'server' } else { 'workstation' }
    $row = _profile_rows | Where-Object { $_.id -eq $check_id } | Select-Object -First 1
    if (-not $row) { return 'skip' }
    if ($row.$col -eq '-') { return 'skip' }
    return $row.$col
}

# True if a check runs in the active (or given) profile.
function profile_runs_check {
    param([string]$check_id, [string]$prof = (watchman_profile))
    return (profile_severity $check_id $prof) -ne 'skip'
}

# --- Directional hint for inspect-logs --------------------------------------
function profile_log_direction {
    if ((watchman_profile) -eq 'server') { return 'inbound' } else { return 'outbound' }
}

# --- Default fix-batching posture -------------------------------------------
function profile_allows_safe_batch {
    return (watchman_profile) -eq 'workstation'
}
