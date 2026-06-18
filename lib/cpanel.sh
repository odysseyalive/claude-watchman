#!/usr/bin/env bash
# lib/cpanel.sh — the cPanel/WHM observe engine (wrap the control plane, never rebuild it).
#
# A cPanel & WHM server is not a new distro — modern cPanel runs on the RHEL family
# (AlmaLinux / Rocky / CloudLinux 8/9/10), with Ubuntu LTS the only non-RHEL option —
# so lib/distro.sh's existing rhel/debian path already resolves dnf, firewalld,
# rpm -V, /var/log/secure and SELinux for it. What cPanel adds is an opinionated
# CONTROL PLANE that puts logs and configs in non-standard places, ships its own
# security stack to QUERY rather than re-implement, and has hard "do not hand-edit"
# rules. This engine wraps that control plane read-only and emits finding-candidates,
# mirroring lib/security_currency.sh's seccur_scan shape.
#
# > PRIME DIRECTIVE. cpscan is READ-ONLY: it calls whmapi1 GET-style functions,
# > reads cPanel config files, counts the Exim queue (exim -bpc/-bp), and runs
# > check_cpanel_rpms WITHOUT --fix. It never edits a cPanel config (those are
# > rebuilt by buildeximconf / EasyApache4 anyway — hand-edits are clobbered),
# > never touches the firewall (CSF/cPHulk own that), and never applies an update.
# > Every finding is detect-and-propose; remediation routes back through the
# > operator and the control panel's OWN tools, at review/manual tier.

_CP_WHMAPI1="/usr/local/cpanel/bin/whmapi1"
_CP_RPMCHECK="/usr/local/cpanel/scripts/check_cpanel_rpms"

# Run a whmapi1 GET function and echo JSON; empty on any error (a missing/renamed
# function across cPanel versions degrades to "unknown -> no finding", not a false
# positive). --output=json keeps parsing deterministic.
_cp_whmapi1() {
    [[ -x "$_CP_WHMAPI1" ]] || return 0
    "$_CP_WHMAPI1" --output=json "$@" 2>/dev/null || true
}

# Pull a scalar by key from whmapi1 JSON. Echoes the first match, or empty.
_cp_json_field() {
    local key="$1"
    if command -v jq >/dev/null 2>&1; then
        jq -r --arg k "$key" '.. | objects | select(has($k)) | .[$k]' 2>/dev/null | head -1
    else
        grep -oE "\"$key\"[[:space:]]*:[[:space:]]*\"?[^,\"}]*" 2>/dev/null \
            | head -1 | sed -E 's/.*:[[:space:]]*"?//'
    fi
}

# Emit one finding-candidate (identical TSV to seccur_scan):
#   category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation
_cp_emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@"; }

# PHP branches end-of-life as of mid-2026 (8.1 EOL 2025-12). Override with
# WATCHMAN_EOL_PHP so the list stays tunable as branches age — no code change.
_CP_EOL_PHP_DEFAULT="ea-php54 ea-php55 ea-php56 ea-php70 ea-php71 ea-php72 ea-php73 ea-php74 ea-php80 ea-php81"

# Read every cPanel signal, emit finding-candidates. No output = healthy. Safe under
# set -euo pipefail: every quirky-exit capture ends in `|| true`.
cpscan() {
    [[ "$(control_panel_detect 2>/dev/null)" == cpanel ]] || return 0
    local ver; ver="$(cpanel_version 2>/dev/null || echo unknown)"

    # 1. cPHulk brute-force protection.
    local hulk; hulk="$(_cp_whmapi1 cphulk_status || true)"
    if [[ -n "$hulk" ]]; then
        local hen; hen="$(printf '%s' "$hulk" | _cp_json_field is_enabled || true)"
        if [[ "$hen" == "0" ]]; then
            _cp_emit security high review cpanel_cphulk_disabled cphulk \
                "cPHulk brute-force protection is disabled" \
                "cPHulk is cPanel's built-in brute-force defense for WHM/cPanel/webmail and (optionally) SSH logins. With it off, password guessing against those services is unthrottled." \
                "Enable cPHulk in WHM Security Center (review the per-service login/IP thresholds first)."
        fi
    fi

    # 2. EOL PHP per account (MultiPHP / EasyApache4).
    local phpv; phpv="$(_cp_whmapi1 php_get_vhost_versions || true)"
    if [[ -n "$phpv" ]]; then
        local eol="${WATCHMAN_EOL_PHP:-$_CP_EOL_PHP_DEFAULT}" tok hits
        for tok in $eol; do
            hits="$(printf '%s' "$phpv" | grep -oE "\"$tok\"" 2>/dev/null | wc -l | tr -d ' ' || true)"
            if [[ "${hits:-0}" =~ ^[0-9]+$ ]] && (( hits > 0 )); then
                _cp_emit security medium manual cpanel_eol_php "$tok" \
                    "$hits vhost(s) on end-of-life PHP ($tok)" \
                    "$hits virtual host(s) are assigned $tok, which no longer receives security fixes. Each site on it is exposed to known PHP-level vulnerabilities." \
                    "WHM MultiPHP Manager: move the listed accounts to a supported PHP version (test app compatibility first — moving PHP can break a site)."
            fi
        done
    fi

    # 3. cPanel update cadence + tier (/etc/cpupdate.conf — authoritative).
    if [[ -r /etc/cpupdate.conf ]]; then
        local upd tier
        upd="$(grep -iE '^UPDATES=' /etc/cpupdate.conf 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]' || true)"
        tier="$(grep -iE '^CPANEL=' /etc/cpupdate.conf 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]' || true)"
        if [[ -n "$upd" && "$upd" != "daily" && "$upd" != "automatic" ]]; then
            _cp_emit security medium review cpanel_autoupdate_off cpanel-updates \
                "cPanel automatic updates set to '$upd'" \
                "UPDATES=$upd in /etc/cpupdate.conf means cPanel & WHM (upcp) will not apply its own security releases automatically, so the control plane can drift behind known fixes." \
                "WHM Server Configuration > Update Preferences: set cPanel & WHM updates to Automatic."
        fi
        if [[ -n "$tier" && "$tier" =~ ^(edge|current)$ ]]; then
            _cp_emit config low manual cpanel_update_tier cpanel-tier \
                "cPanel release tier is '$tier'" \
                "The $tier tier ships newer, less-soaked builds than RELEASE/STABLE — fine for a test box, riskier for production." \
                "If this is production, consider WHM Update Preferences > RELEASE or STABLE tier."
        fi
    fi

    # 4. Exim outbound mail abuse — the #1 cPanel incident vector.
    if command -v exim >/dev/null 2>&1; then
        local qc frozen qmax fmax
        qmax="${WATCHMAN_EXIM_QUEUE_MAX:-1000}"; fmax="${WATCHMAN_EXIM_FROZEN_MAX:-100}"
        qc="$(exim -bpc 2>/dev/null || echo 0)"; [[ "$qc" =~ ^[0-9]+$ ]] || qc=0
        frozen="$(exim -bp 2>/dev/null | grep -c 'frozen' || true)"; [[ "$frozen" =~ ^[0-9]+$ ]] || frozen=0
        if (( qc > qmax )); then
            _cp_emit security high review cpanel_mail_queue_spike exim-queue \
                "Exim mail queue is large ($qc messages)" \
                "The Exim queue holds $qc messages (alert above $qmax). A sudden backlog often means a compromised account or script is sending bulk spam through this server, risking IP blacklisting." \
                "WHM Email > Mail Queue Manager / Track Delivery: identify the sending account; suspend it via the control panel if confirmed compromised. Do NOT mass-delete the queue blindly."
        elif (( frozen > fmax )); then
            _cp_emit security medium review cpanel_mail_frozen exim-frozen \
                "Exim queue has $frozen frozen messages" \
                "$frozen messages are frozen (alert above $fmax). A spike in frozen mail commonly indicates bounce-back from a spam run originating on this server." \
                "WHM Email > Mail Queue Manager: inspect frozen messages and identify the originating account."
        fi
    fi

    # 5. CSF/LFD currency (ConfigServer shut down 2025-08-31; cPanel forked + repoints).
    if [[ -x /usr/sbin/csf || -x /etc/csf/csf.pl ]]; then
        local csfsrc; csfsrc="$(grep -hiE '^[[:space:]]*(URL|DOWNLOADSERVER|UPDATE_URL)' /etc/csf/csf.conf 2>/dev/null | grep -i 'configserver.com' || true)"
        if [[ -n "$csfsrc" ]]; then
            _cp_emit security medium review cpanel_csf_orphaned csf \
                "CSF appears to point at the decommissioned ConfigServer update source" \
                "ConfigServer (CSF/LFD) shut down on 2025-08-31; its update server is offline, so a CSF still configured against configserver.com receives no rule/version updates. cPanel maintains a fork and repoints eligible servers." \
                "Confirm CSF is on cPanel's maintained fork/mirror (or migrate the firewall). Coordinate firewall changes through CSF/cPHulk — never raw nftables rules that fight LFD."
        fi
    fi

    # 6. Imunify360 / ImunifyAV — surface its own active malware detections (read-only).
    if command -v imunify360-agent >/dev/null 2>&1 || command -v imunify-antivirus >/dev/null 2>&1; then
        local infected
        infected="$(imunify360-agent malware malicious list --limit 1 2>/dev/null | grep -ciE 'malware|infected|/home/' || true)"
        [[ "$infected" =~ ^[0-9]+$ ]] || infected=0
        if (( infected > 0 )); then
            _cp_emit security high review cpanel_imunify_malware imunify \
                "Imunify reports malicious files on this server" \
                "Imunify's own scanner is flagging detected malicious file(s) — live detections from the installed security suite." \
                "WHM Imunify360 > Malware Scanner: review and clean via Imunify (do not delete by hand; let the tool quarantine)."
        fi
    fi

    # 7. cPanel RPM integrity — check_cpanel_rpms read-only (HEAVY; io-courtesy priced).
    if [[ -x "$_CP_RPMCHECK" ]]; then
        _cp_iv() { if declare -F io_run >/dev/null 2>&1; then io_run "$@"; else "$@"; fi; }
        local altered
        altered="$(_cp_iv "$_CP_RPMCHECK" --list 2>/dev/null | grep -icE 'altered|missing' || true)"
        [[ "$altered" =~ ^[0-9]+$ ]] || altered=0
        if (( altered > 0 )); then
            _cp_emit integrity high manual cpanel_rpm_altered cpanel-rpms \
                "$altered cPanel-shipped RPM(s) altered or missing" \
                "check_cpanel_rpms reports $altered cPanel RPM(s) whose files were modified or are missing — a benign side effect of an interrupted update, or evidence of tampering." \
                "Investigate the listed RPMs (check_cpanel_rpms --list); if benign, repair with its --fix flag (operator-run, reinstalls cPanel-shipped files)."
        fi
    fi
    return 0
}
