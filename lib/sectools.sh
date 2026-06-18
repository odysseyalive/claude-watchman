#!/usr/bin/env bash
# lib/sectools.sh — discover the box's OWN defensive tooling and bring it into scope.
#
# claude-watchman wraps battle-tested tools rather than reimplementing them
# (CLAUDE.md: "AI builds systems, not dependencies"). This engine generalises the
# ad-hoc `if command -v cscli / aide / freshclam` checks that used to be scattered
# in lib/security_currency.sh into ONE registry: the single declaration of which
# defensive tools claude-watchman knows how to observe. Discovery is then "which
# registry entries are present on THIS host", so the box's own toolset shapes what
# gets monitored — add a tool by adding a row, nothing else drifts.
#
# > PRIME DIRECTIVE. sectools is READ-ONLY. It detects installed tools, reads their
# > status/last-run state (never TRIGGERS a scan — no rkhunter --check, no clamscan,
# > no aide --check), and emits finding-candidates. It never installs, enables, or
# > changes anything. Absent-defense findings are MANUAL tier (installing software
# > is the operator's call); a degraded-tool finding is REVIEW tier and applied only
# > by the operator-run `watchman fix`, never the loop.
#
# Depends on lib/distro.sh + lib/profile.sh being sourced first (same convention as
# lib/security_currency.sh): it uses pkg_is_installed / service_status / watchman_family
# / watchman_profile / profile_severity / pkg_install_cmd.
#
# OWNERSHIP BOUNDARY (so we never double-journal). Where a dedicated engine already
# owns a tool's deeper finding, sectools emits ONLY the `info` inventory row and counts
# the tool toward its defense class — it defers the deep finding to the owner:
#   * crowdsec hub freshness        → check-security-currency (crowdsec_hub_stale)
#   * crowdsec inbound alerts       → inspect-logs
#   * clamav signature staleness    → check-security-currency (clamav_sig_stale)
#   * aide db-missing / file checks → check-security-currency (aide_db_missing) / integrity
#   * debsecan/arch-audit CVE scan  → check-security-currency (vuln_packages)
#   * unattended-upgrades enabled?  → check-security-currency (auto_security_updates_off)
# Findings never collide regardless (the fingerprint includes check_id), but deferring
# keeps the journal free of redundant rows.

# --- The registry -----------------------------------------------------------
# One row per tool claude-watchman can observe. Pipe-separated columns:
#   id | defense_class | category | unit
#     id            — canonical tool name (also the inventory finding's target)
#     defense_class — what protective capability it provides (drives absent-detection)
#     category      — finding category for the health row (inventory rows are config/info)
#     unit          — systemd unit to check active/enabled, or '-' if none
_ST_REGISTRY='
fail2ban|brute_force|security|fail2ban
sshguard|brute_force|security|sshguard
crowdsec|brute_force|security|crowdsec
rkhunter|rootkit|integrity|-
chkrootkit|rootkit|integrity|-
auditd|host_audit|security|auditd
clamav|antivirus|security|-
aide|file_integrity|integrity|-
debsecan|vuln_scanner|config|-
arch-audit|vuln_scanner|config|-
wazuh-ossec|host_ids|security|wazuh-agent
unattended-upgrades|auto_update|config|-
dnf-automatic|auto_update|config|dnf-automatic.timer
'

# Iterate the registry rows (blank lines stripped) on stdout.
_st_rows() { printf '%s\n' "$_ST_REGISTRY" | awk 'NF'; }

# Emit one finding-candidate the skill journals, identical TSV layout to
# security_currency.sh's _sc_emit:
#   category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation
_st_emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@"; }

# --- Detection --------------------------------------------------------------
# True (0) when the tool id is installed on this host. Detect by the tool's own
# command, then fall back to the package name(s) for this family.
_st_present() {
    local id="$1"
    case "$id" in
        fail2ban)    command -v fail2ban-client >/dev/null 2>&1 || pkg_is_installed fail2ban 2>/dev/null ;;
        sshguard)    command -v sshguard        >/dev/null 2>&1 || pkg_is_installed sshguard 2>/dev/null ;;
        crowdsec)    command -v cscli           >/dev/null 2>&1 || pkg_is_installed crowdsec 2>/dev/null ;;
        rkhunter)    command -v rkhunter         >/dev/null 2>&1 || pkg_is_installed rkhunter 2>/dev/null ;;
        chkrootkit)  command -v chkrootkit       >/dev/null 2>&1 || pkg_is_installed chkrootkit 2>/dev/null ;;
        auditd)      command -v auditctl         >/dev/null 2>&1 || pkg_is_installed auditd 2>/dev/null || pkg_is_installed audit 2>/dev/null ;;
        clamav)      command -v clamscan         >/dev/null 2>&1 || command -v freshclam >/dev/null 2>&1 || pkg_is_installed clamav 2>/dev/null ;;
        aide)        command -v aide             >/dev/null 2>&1 || pkg_is_installed aide 2>/dev/null ;;
        debsecan)    command -v debsecan         >/dev/null 2>&1 ;;
        arch-audit)  command -v arch-audit       >/dev/null 2>&1 ;;
        wazuh-ossec) [[ -x /var/ossec/bin/wazuh-control || -x /var/ossec/bin/ossec-control ]] || pkg_is_installed wazuh-agent 2>/dev/null ;;
        unattended-upgrades) pkg_is_installed unattended-upgrades 2>/dev/null ;;
        dnf-automatic)       pkg_is_installed dnf-automatic 2>/dev/null ;;
        *) return 1 ;;
    esac
}

_st_unit_active() { [[ "$(service_status "$1" 2>/dev/null)" == active ]]; }

# --- Observe (shallow + cheap, strictly read-only) --------------------------
# Echo a one-line health detail; return 0 = healthy/ok, 1 = degraded (installed
# but not actually protecting). NEVER triggers a scan — only reads live status and
# the tail of an existing last-run log. Deferred-ownership tools always return 0
# with an inventory-only detail (their deep finding belongs to another engine).
_st_observe() {
    local id="$1" unit="$2"
    case "$id" in
        fail2ban)
            _st_unit_active fail2ban || { echo "installed but the fail2ban service is inactive"; return 1; }
            local jails j banned=0 n
            jails="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' ' | xargs 2>/dev/null || true)"
            [[ -n "$jails" ]] || { echo "active but no jails are configured (nothing is being protected)"; return 1; }
            for j in $jails; do
                n="$(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Currently banned:[[:space:]]*//p' | head -1 || true)"
                [[ "$n" =~ ^[0-9]+$ ]] && banned=$((banned + n))
            done
            echo "active; jails: ${jails// /, }; ${banned} IP(s) currently banned"; return 0 ;;
        sshguard)
            _st_unit_active sshguard && { echo "active"; return 0; }
            echo "installed but the sshguard service is inactive"; return 1 ;;
        crowdsec)
            echo "present — inbound alerts via inspect-logs, hub freshness via check-security-currency"; return 0 ;;
        rkhunter)
            local log=/var/log/rkhunter.log warns
            if [[ -r "$log" ]]; then
                warns="$(grep -c 'Warning:' "$log" 2>/dev/null || echo 0)"
                echo "installed; last run reported ${warns} warning(s) [${log}]"; return 0
            fi
            echo "installed but it has never run (no ${log}) — schedule a periodic check"; return 1 ;;
        chkrootkit)
            local log=/var/log/chkrootkit/log.today
            [[ -r "$log" ]] && { echo "installed; recent run log present"; return 0; }
            echo "installed (run via cron or manually; it has no daemon)"; return 0 ;;
        auditd)
            _st_unit_active auditd || { echo "installed but the auditd service is inactive"; return 1; }
            local rules; rules="$(auditctl -l 2>/dev/null | grep -cE '^-' || true)"
            [[ "$rules" =~ ^[0-9]+$ ]] || rules=0
            (( rules == 0 )) && { echo "active but no audit rules are loaded (nothing is being recorded)"; return 1; }
            echo "active; ${rules} audit rule(s) loaded"; return 0 ;;
        clamav)
            echo "present — signature freshness via check-security-currency"; return 0 ;;
        aide)
            echo "present — database init via check-security-currency, file checks via integrity"; return 0 ;;
        debsecan|arch-audit)
            echo "present — CVE scanning via check-security-currency"; return 0 ;;
        wazuh-ossec)
            local ctl=/var/ossec/bin/wazuh-control
            [[ -x "$ctl" ]] || ctl=/var/ossec/bin/ossec-control
            if _st_unit_active wazuh-agent || { [[ -x "$ctl" ]] && "$ctl" status >/dev/null 2>&1; }; then
                echo "agent present and running"; return 0
            fi
            echo "agent installed but not running"; return 1 ;;
        unattended-upgrades|dnf-automatic)
            echo "present — enabled-state via check-security-currency"; return 0 ;;
        *) echo "present"; return 0 ;;
    esac
}

# --- The scan ---------------------------------------------------------------
# Walk the registry: for every PRESENT tool emit an inventory row (+ a health row
# if degraded and the profile runs it), then emit an absent-defense finding for any
# defense class no present tool satisfies. Severity + profile-gating for the health
# and gap findings come from lib/profile.sh (the single source of severity), so a
# class that does not apply to this profile is silently skipped. No output beyond
# inventory = the box's defenses look healthy and well-covered.
sectools_scan() {
    local prof; prof="$(watchman_profile)"
    local id class cat unit detail rc hsev
    local -A satisfied=()

    while IFS='|' read -r id class cat unit; do
        [[ -n "$id" ]] || continue
        _st_present "$id" || continue
        satisfied[$class]=1
        [[ "$unit" == "-" ]] && unit=""

        rc=0; detail="$(_st_observe "$id" "$unit")" || rc=$?

        # Inventory row — always (context, not an alarm), like service_inventory.
        _st_emit config info safe sectool_inventory "$id" \
            "${id} present" "$detail" ""

        # Health row — only when degraded AND the profile runs the check.
        if (( rc != 0 )); then
            hsev="$(profile_severity sectool_health "$prof")"
            if [[ "$hsev" != skip ]]; then
                _st_emit "$cat" "$hsev" review sectool_health "$id" \
                    "${id} is installed but not effective" \
                    "${detail} — a defense that is installed but not running or configured gives false comfort." \
                    "Enable and configure it (e.g. 'sudo systemctl enable --now ${unit:-$id}', then load its jails/rules); apply via 'watchman fix'."
            fi
        fi
    done < <(_st_rows)

    # Absent-defense classes (the "adopt scope" inverse). MANUAL tier always —
    # installing software is the operator's decision; the loop can never apply it.
    _st_gap brute_force   defense_gap_bruteforce  security  "$prof" "${satisfied[brute_force]:-}" \
        "No brute-force protection is installed" \
        "Nothing is throttling password-guessing against SSH or the web server — no fail2ban, CrowdSec, or sshguard is present. On a public-facing host this is a primary path to credential compromise." \
        "Install one (operator's choice): $(pkg_install_cmd) fail2ban — or deploy CrowdSec."
    _st_gap rootkit       defense_gap_rootkit     integrity "$prof" "${satisfied[rootkit]:-}" \
        "No rootkit checker is installed" \
        "Neither rkhunter nor chkrootkit is present, so a rootkit dropped after a compromise could persist unnoticed between integrity scans." \
        "$(pkg_install_cmd) rkhunter (or chkrootkit); then schedule a periodic check."
    _st_gap host_audit    defense_gap_audit       security  "$prof" "${satisfied[host_audit]:-}" \
        "No host audit subsystem is installed" \
        "auditd is not present, so security-relevant kernel events (privilege use, sensitive file access, config changes) are not being recorded for forensics." \
        "$(pkg_install_cmd) audit (auditd); then load a rule set (e.g. the CIS/STIG audit rules)."
    _st_gap file_integrity defense_gap_integrity  integrity "$prof" "${satisfied[file_integrity]:-}" \
        "No file-integrity baseline tool is installed" \
        "AIDE is not installed, so there is no tamper-evidence baseline to catch quiet changes to system binaries and configuration files." \
        "$(pkg_install_cmd) aide; then run 'aide --init' to capture the baseline."

    # Antivirus-absent is opinionated on a typical Linux server, so it is OFF by
    # default — flagged only when the operator opts in (mail/file servers).
    if [[ "${WATCHMAN_FLAG_AV_ABSENT:-no}" == yes ]]; then
        _st_gap antivirus defense_gap_antivirus   security  "$prof" "${satisfied[antivirus]:-}" \
            "No antivirus engine is installed" \
            "ClamAV is not present. On a mail or file server that handles user-supplied content, on-access malware scanning is a meaningful layer." \
            "$(pkg_install_cmd) clamav clamav-daemon; then enable freshclam."
    fi
}

# Emit an absent-defense finding for one class, unless a present tool satisfies it
# or the profile does not run the check.
_st_gap() {
    local class="$1" check_id="$2" category="$3" prof="$4" satisfied="$5"
    local title="$6" detail="$7" rem="$8"
    [[ -n "$satisfied" ]] && return 0            # class is covered — nothing to flag
    local sev; sev="$(profile_severity "$check_id" "$prof")"
    [[ "$sev" == skip ]] && return 0
    _st_emit "$category" "$sev" manual "$check_id" "$class" "$title" "$detail" "$rem"
}

# --- Helpers for the skill summary and the preflight ------------------------
# The present tools, one id per line (for the skill's plain-language summary).
sectools_present() {
    local id rest
    while IFS='|' read -r id rest; do
        [[ -n "$id" ]] || continue
        _st_present "$id" && printf '%s\n' "$id"
    done < <(_st_rows)
}

# sectools_observe_commands — used ONLY by lib/preflight.sh (the `sectool_status`
# resolver_op). For each PRESENT tool whose observe needs a privileged command,
# emit a TSV line matching _pf_expand_resolver_op's contract:
#   <allow-args>\t<needs_sudo:0|1>\t<sudoers-cmd-or->
# Tools observed via service_status / log reads / cscli need nothing here (already
# granted by other resolver_ops or the sectool_log_paths read token). Emitting only
# for PRESENT tools keeps the allowlist least-privilege — install a new tool later
# and re-run `watchman preflight` to widen it.
sectools_observe_commands() {
    if _st_present fail2ban; then
        printf 'sudo fail2ban-client status*\t1\t%s\n' "$(command -v fail2ban-client 2>/dev/null || echo /usr/bin/fail2ban-client)"
    fi
    if _st_present auditd; then
        printf 'sudo auditctl -l*\t1\t%s\n' "$(command -v auditctl 2>/dev/null || echo /sbin/auditctl)"
        command -v aureport >/dev/null 2>&1 && printf 'sudo aureport*\t1\t%s\n' "$(command -v aureport)"
    fi
    if _st_present wazuh-ossec; then
        [[ -x /var/ossec/bin/wazuh-control ]] && printf 'sudo /var/ossec/bin/wazuh-control status*\t1\t/var/ossec/bin/wazuh-control\n'
        [[ -x /var/ossec/bin/ossec-control ]] && printf 'sudo /var/ossec/bin/ossec-control status*\t1\t/var/ossec/bin/ossec-control\n'
    fi
    return 0
}

# sectool_log_paths — a resolver token (a distro.sh-style function) declared in the
# skill's manifest `reads`. preflight grants Read on each directory emitted so the
# observe step can read a present tool's last-run log wherever it lives. Echoes only
# directories that actually exist on this host.
sectool_log_paths() {
    if _st_present rkhunter || _st_present chkrootkit; then
        [[ -d /var/log ]] && printf '%s\n' /var/log
    fi
    _st_present auditd      && [[ -d /var/log/audit ]] && printf '%s\n' /var/log/audit
    _st_present wazuh-ossec && [[ -d /var/ossec/logs ]] && printf '%s\n' /var/ossec/logs
    return 0
}
