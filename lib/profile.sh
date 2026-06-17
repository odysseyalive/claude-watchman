#!/usr/bin/env bash
# lib/profile.sh — the resolver for the WHAT.
#
# Resolves which checks run and what severity they carry, based on whether the
# machine is a `server` or a `workstation`. The skills are the same shape in both
# profiles; the profile points them in the right direction (CLAUDE.md "Profile
# abstraction"):
#   * server      → public-facing attack surface (headers, CORS, exposed ports,
#                   inbound probes, SSH hardening).
#   * workstation → the opposite direction: what the machine talks TO. The
#                   highest-value workstation check is LOG RETENTION itself —
#                   journald often defaults to volatile, so logs vanish on reboot
#                   and the forensic trail the crash-diagnosis skill needs is gone.
#
# Profile comes from config/watchman.conf (WATCHMAN_PROFILE) written by install.sh,
# overridable via the env for testing. No mutation here — pure resolution.

# --- Profile detection ------------------------------------------------------
watchman_profile() {
    if [[ -n "${WATCHMAN_PROFILE:-}" ]]; then printf '%s\n' "$WATCHMAN_PROFILE"; return; fi
    local conf="${WATCHMAN_CONF:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/config/watchman.conf}"
    if [[ -r "$conf" ]]; then
        # shellcheck disable=SC1090
        local p; p="$(. "$conf" 2>/dev/null && printf '%s' "${WATCHMAN_PROFILE:-}")"
        [[ -n "$p" ]] && { WATCHMAN_PROFILE="$p"; printf '%s\n' "$p"; return; }
    fi
    # Heuristic default: a box running a web server or sshd open to the world is
    # likely a server; otherwise treat as workstation (the safer, quieter default).
    WATCHMAN_PROFILE="workstation"
    printf '%s\n' "$WATCHMAN_PROFILE"
}

# --- Which checks run -------------------------------------------------------
# The canonical check set, expressed once. profile_checks echoes the check_ids
# that apply to the active (or given) profile, so a skill iterates exactly the
# checks that matter here instead of hard-coding a per-profile list itself.
#
# Format of the table: "check_id:server_severity:workstation_severity"
# A severity of "-" means the check does NOT run in that profile.
_PROFILE_CHECK_TABLE='
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
service_inventory:info:info
'

# Echo the applicable check_ids for the profile.
profile_checks() {
    local prof="${1:-$(watchman_profile)}"
    local col; [[ "$prof" == server ]] && col=2 || col=3
    printf '%s\n' "$_PROFILE_CHECK_TABLE" | awk -F: -v c="$col" 'NF>=3 && $c!="-" {print $1}'
}

# Echo the severity a given check carries in the active (or given) profile.
# Prints "skip" if the check does not run in that profile — callers should not
# journal a finding for a skipped check.
profile_severity() {
    local check_id="$1" prof="${2:-$(watchman_profile)}"
    local col; [[ "$prof" == server ]] && col=2 || col=3
    printf '%s\n' "$_PROFILE_CHECK_TABLE" \
        | awk -F: -v id="$check_id" -v c="$col" '$1==id {print ($c=="-")?"skip":$c; found=1} END{if(!found) print "skip"}'
}

# True if a check runs in the active (or given) profile.
profile_runs_check() {
    local sev; sev="$(profile_severity "$1" "${2:-}")"
    [[ "$sev" != skip ]]
}

# --- Directional hint for inspect-logs --------------------------------------
# The same inspect-logs skill hunts INBOUND attack patterns on a server and
# watches OUTBOUND connections on a workstation. This tells it which way to look.
profile_log_direction() {  # echoes: inbound | outbound
    [[ "$(watchman_profile)" == server ]] && echo inbound || echo outbound
}

# --- Default fix-batching posture -------------------------------------------
# On a server, default to caution: never batch even 'safe' fixes without the
# operator opting in. On a workstation, 'safe' fixes may be batch-applied when the
# operator approves. (review/manual are NEVER batched in either — risk-tier rule.)
profile_allows_safe_batch() {
    [[ "$(watchman_profile)" == workstation ]]
}
