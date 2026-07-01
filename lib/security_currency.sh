#!/usr/bin/env bash
# lib/security_currency.sh — are the server's defenses being kept CURRENT?
#
# Configuration checks ask "is it set up right." This asks the time-based question:
# "is it up to date, and is something keeping it up to date" — across families
# (Debian/RHEL/Arch) via lib/distro.sh's resolvers. As attackers gain new tricks,
# stale defenses (old signatures, unpatched packages, an outdated CrowdSec hub, an
# auto-updater that quietly turned off) are how a once-hardened box drifts open.
# The journal tracks the staleness as a trend, so the loop EMAILS you when a fresh
# defense goes stale — staleness is a slow drift, and the loop is built to catch drift.
#
# > PRIME DIRECTIVE. security_currency is READ-ONLY: it reads state and emits
# > finding-candidates. It NEVER syncs over the network (no apt update / pacman -Sy),
# > never installs, and NEVER applies an update — applying one can break a production
# > server, so every finding is detect-and-propose; the operator confirms via
# > `watchman fix` (review) or enables the automation. Detection only.

# Emit one finding-candidate the skill journals:
#   category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation
_sc_emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@"; }

# Scan everything and emit records (no output = defenses look current).
seccur_scan() {
    local fam stale_days update_stale cmd
    fam="$(watchman_family)"
    stale_days="${WATCHMAN_SIG_STALE_DAYS:-7}"
    update_stale="${WATCHMAN_UPDATE_STALE_DAYS:-30}"
    cmd="$(security_update_cmd)"

    # 1. Package metadata staleness — a stale DB makes "0 updates pending" a lie.
    # NB: package commands have quirky exit codes (pacman -Qu = 1 when none pending;
    # dnf check-update = 100 when updates exist), so every capture below ends in
    # `|| true` to stay correct under the caller's `set -euo pipefail`.
    local dbage; dbage="$(pkg_db_age_days 2>/dev/null || echo -1)"
    if [[ "$dbage" =~ ^[0-9]+$ ]] && (( dbage > update_stale )); then
        _sc_emit config medium manual pkg_db_stale package-db \
            "Package metadata not refreshed in ${dbage} days" \
            "The system's package database is ${dbage}d old (limit ${update_stale}d) — it cannot see new security fixes, so any 'up to date' reading is unreliable. The durable fix is automatic refresh." \
            "Refresh + enable auto-update: $cmd"
    fi

    # 2. Pending updates (read from CACHED state — no network sync here).
    local upg n
    upg="$(pkg_list_upgradable 2>/dev/null | awk 'NF' || true)"
    n="$(printf '%s\n' "$upg" | awk 'NF' | wc -l | tr -d ' ' || true)"
    if (( n > 0 )); then
        _sc_emit security medium review security_updates_pending packages \
            "${n} package update(s) available" \
            "${n} packages have updates pending — applying them is how you pick up fixes for known exploits. First: $(printf '%s\n' "$upg" | head -5 | paste -sd', ' -)" \
            "$cmd"
    fi

    # 3. CVE scanner — run it, or recommend installing one (visibility into known-bad).
    case "$(vuln_scanner)" in
        none)
            local vp=""
            [[ "$fam" == debian ]] && vp="debsecan"
            [[ "$fam" == arch   ]] && vp="arch-audit"
            if [[ -n "$vp" ]]; then
                _sc_emit config low review vuln_scanner_missing vuln-scanner \
                    "No CVE scanner installed" \
                    "Install '$vp' so claude-watchman can flag packages with known CVEs that have fixes available." \
                    "$(pkg_install_cmd) $vp"
            fi ;;
        *)
            local v vn; v="$(vuln_scan 2>/dev/null | awk 'NF' || true)"
            vn="$(printf '%s\n' "$v" | awk 'NF' | wc -l | tr -d ' ' || true)"
            if (( vn > 0 )); then
                _sc_emit security high review vuln_packages cve \
                    "${vn} package(s) with known vulnerabilities" \
                    "$(vuln_scanner) reports ${vn} vulnerable package(s) with fixes available. Top: $(printf '%s\n' "$v" | head -5 | paste -sd'; ' -)" \
                    "$cmd"
            fi ;;
    esac

    # 4. Auto security updates — the automation that keeps the OS current.
    if [[ "$(autoupdate_mechanism)" != rolling ]]; then
        if ! autoupdate_enabled; then
            _sc_emit security medium review auto_security_updates_off "$(autoupdate_mechanism)" \
                "Automatic security updates are not enabled" \
                "$(autoupdate_mechanism) is this family's auto-update path and it is not active — fixes won't apply on their own. Enabling it is the durable way to stay current; claude-watchman then just verifies it stays on." \
                "Install + enable $(autoupdate_mechanism) (its timer/service)."
        fi
    elif [[ "$dbage" =~ ^[0-9]+$ ]] && (( dbage > update_stale )); then
        : # rolling: staleness already covered by pkg_db_stale above
    fi

    # 5. Threat-intel freshness (only for tools that are present).
    if command -v freshclam >/dev/null 2>&1 || command -v clamscan >/dev/null 2>&1; then
        local cvd age
        cvd="$(ls -1t /var/lib/clamav/*.cvd /var/lib/clamav/*.cld 2>/dev/null | head -1 || true)"
        if [[ -n "$cvd" ]]; then
            age=$(( ( $(date +%s) - $(_stat_mtime "$cvd" 2>/dev/null || date +%s) ) / 86400 ))
            (( age > stale_days )) && _sc_emit security medium review clamav_sig_stale clamav \
                "ClamAV virus signatures are ${age} days old" \
                "Signatures older than ${stale_days}d miss recent malware. Refresh them and ensure the freshclam timer/daemon runs." \
                "sudo freshclam"
        fi
    fi
    if command -v aide >/dev/null 2>&1; then
        if ! ls /var/lib/aide/aide.db.gz /var/lib/aide/aide.db >/dev/null 2>&1; then
            _sc_emit integrity medium manual aide_db_missing aide \
                "AIDE is installed but has no initialized database" \
                "Without a baseline database AIDE cannot detect file tampering — the integrity check is blind." \
                "sudo aide --init  (then move aide.db.new.gz to aide.db.gz)"
        fi
    fi
    if command -v cscli >/dev/null 2>&1; then
        # cscli hub reads local state (works even when the LAPI/agent is down).
        if cscli hub list 2>/dev/null | grep -qiE 'tainted|outdated|⚠'; then
            _sc_emit security medium review crowdsec_hub_stale crowdsec \
                "CrowdSec hub has outdated or tainted items" \
                "Detection scenarios/collections are not current — refreshing them is how CrowdSec keeps up with new attack patterns." \
                "sudo cscli hub update && sudo cscli hub upgrade"
        fi
    fi
}
