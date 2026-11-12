#!/usr/bin/env bash
# lib/interworx.sh — the InterWorx/NodeWorx observe engine (wrap the control plane, never rebuild it).
#
# InterWorx runs only on the RHEL family (AlmaLinux / Rocky / CloudLinux 8/9), so
# lib/distro.sh's rhel path already resolves dnf, rpm -V, /var/log/secure and SELinux.
# What the panel adds is its own layout: a bundled panel httpd (httpd-iworx) and panel
# database (iworx-db-mariadb) beside the system ones, remi PHP-FPM pools wired to
# panel-generated Apache vhosts, qmail/djbdns under daemontools instead of systemd,
# and CSF or APF as the firewall. This engine reads that layout and emits
# finding-candidates in the same TSV shape as cpscan / seccur_scan.
#
# > PRIME DIRECTIVE. iwscan is READ-ONLY. It reads config files, runs svstat,
# > qmail-qstat, ss and systemctl is-active, and nothing else. It does NOT call the
# > nodeworx/siteworx CLI at all (that CLI also suspends, deletes and changes PHP
# > versions, so it stays out of every allowlist), never runs varpermsfix.pex,
# > cvspermsfix.pex, fastpermsfix.sh, update.pex or any other fixer, never edits a
# > vhost (the panel rebuilds them), never touches the firewall, never clears the mail
# > queue. Every finding is detect-and-propose at review/manual tier.
#
# > SECRETS. <IW_ROOT>/iworx.ini holds the panel DB connection strings (dsn=,
# > rootdsn=). It is never printed and never granted to the model: _iw_ini_get reads
# > exactly one key under one exact section and callers emit only a normalized token,
# > never the raw value.
#
# Every path is an overridable variable so the engine can be exercised against a
# fixture tree: IW_ROOT, IW_SERVICE_DIR, IW_REMI_ETC, IW_HTTPD_CONF_D, IW_CSF_CONF,
# IW_APF_CONF, IW_YUM_REPOS_D, IW_QMAIL_QSTAT, IW_SVSTAT, IW_PANEL_UNITS,
# IW_PANEL_HTTP_PORT, IW_TODAY (and IW_VERSION, read by interworx_version).

# Emit one finding-candidate (identical TSV to cpscan / seccur_scan):
#   category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation
_iw_emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@"; }

# True when dotted version $1 sorts strictly before $2.
_iw_ver_lt() {
    [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]
}

# One INI value: exact [section] match, anchored key, last occurrence wins. The value
# is lowercased with quotes and whitespace stripped. Callers compare it to a fixed
# vocabulary and never print it.
_iw_ini_get() {
    local file="$1" section="$2" key="$3"
    [[ -r "$file" ]] || return 0
    awk -v want="$section" -v key="$key" '
        /^[[:space:]]*\[/ { sec=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", sec); next }
        sec==want {
            line=$0
            if (match(line, "^[[:space:]]*" key "[[:space:]]*=")) {
                val=substr(line, RLENGTH+1); gsub(/["\047[:space:]]/, "", val); last=tolower(val)
            }
        }
        END { if (last != "") print last }' "$file" 2>/dev/null || true
}

# One KEY = "value" from a flat shell-style config (csf.conf, conf.apf). Comment lines
# are skipped; last occurrence wins; quotes and whitespace are stripped.
_iw_conf_val() {
    local file="$1" key="$2"
    [[ -r "$file" ]] || return 0
    awk -v key="$key" '
        /^[[:space:]]*#/ { next }
        match($0, "^[[:space:]]*" key "[[:space:]]*=") {
            val=substr($0, RLENGTH+1); sub(/[[:space:]]+#.*$/, "", val); gsub(/["\047[:space:]]/, "", val); last=val
        }
        END { print last }' "$file" 2>/dev/null || true
}

# Is PORT in a CSF/APF-style list ("20,21,2080" with optional "lo:hi" ranges)?
_iw_port_in_list() {
    local port="$1" item lo hi
    local IFS=','
    for item in $2; do
        [[ -n "$item" ]] || continue
        if [[ "$item" == *:* ]]; then
            lo="${item%%:*}"; hi="${item##*:}"
            [[ "$lo" =~ ^[0-9]+$ && "$hi" =~ ^[0-9]+$ ]] && (( port >= lo && port <= hi )) && return 0
        elif [[ "$item" == "$port" ]]; then
            return 0
        fi
    done
    return 1
}

# /var/run and /run are the same tree on EL8/EL9; compare socket paths by string.
_iw_norm_sock() { sed -E 's#^/var/run/#/run/#'; }

# The svstat binary: IW_SVSTAT, else PATH, else the daemontools default locations.
_iw_svstat() {
    if [[ -n "${IW_SVSTAT:-}" ]]; then printf '%s\n' "$IW_SVSTAT"; return 0; fi
    local c
    c="$(command -v svstat 2>/dev/null || true)"
    [[ -z "$c" && -x /command/svstat ]] && c=/command/svstat
    [[ -z "$c" && -x /usr/local/bin/svstat ]] && c=/usr/local/bin/svstat
    [[ -n "$c" ]] && printf '%s\n' "$c"
    return 0
}

# Default end-of-life PHP branches, in remi's directory naming (/etc/opt/remi/phpNN).
# 8.1 reached EOL 2025-12. Override with WATCHMAN_EOL_PHP_IW (tokens like "74 80" or "php74").
_IW_EOL_PHP_DEFAULT="54 55 56 70 71 72 73 74 80 81"

# Read every InterWorx signal, emit finding-candidates. No output = healthy. Safe
# under set -euo pipefail: every capture that can exit non-zero ends in `|| true`.
iwscan() {
    [[ "$(control_panel_detect 2>/dev/null || true)" == interworx ]] || return 0

    local root="${IW_ROOT:-/usr/local/interworx}"
    local svcdir="${IW_SERVICE_DIR:-/service}"
    local remi="${IW_REMI_ETC:-/etc/opt/remi}"
    local confd="${IW_HTTPD_CONF_D:-/etc/httpd/conf.d}"
    local csfconf="${IW_CSF_CONF:-/etc/csf/csf.conf}"
    local apfconf="${IW_APF_CONF:-/etc/apf/conf.apf}"
    local reposd="${IW_YUM_REPOS_D:-/etc/yum.repos.d}"
    local qstat="${IW_QMAIL_QSTAT:-/var/qmail/bin/qmail-qstat}"
    local ini="$root/iworx.ini"

    # 1. InterWorx version: end of life, and the .htaccess exposure advisory.
    local ver major
    ver="$(interworx_version 2>/dev/null || true)"
    if [[ -n "$ver" ]]; then
        major="${ver%%.*}"
        case "$major" in
            6)
                _iw_emit security high manual interworx_eol interworx \
                    "InterWorx 6 is end-of-life ($ver)" \
                    "InterWorx $ver is on the 6.x line, which no longer receives security fixes. Known panel vulnerabilities (including IWX-CVE-2025-13057, .htaccess file exposure) stay open on it." \
                    "Plan a migration to a supported InterWorx release (InterWorx 8 on EL8/EL9). This is an OS and panel upgrade, so schedule it; it cannot be applied in place by claude-watchman."
                ;;
            7)
                local eol today
                eol="${WATCHMAN_IW7_EOL:-2026-12-31}"
                today="${IW_TODAY:-$(date +%F)}"
                if [[ "$today" > "$eol" ]]; then
                    _iw_emit security high manual interworx_eol interworx \
                        "InterWorx 7 is end-of-life ($ver, EOL $eol)" \
                        "InterWorx $ver is on the 7.x line, which reached public end of life on $eol and no longer receives security fixes." \
                        "Plan a migration to InterWorx 8 (which requires EL8/EL9). Schedule it; it cannot be applied in place by claude-watchman."
                else
                    _iw_emit security high manual interworx_eol interworx \
                        "InterWorx 7 reaches end-of-life on $eol ($ver)" \
                        "InterWorx $ver is on the 7.x line, which is in maintenance-only status and reaches public end of life on $eol. After that date it receives no security fixes." \
                        "Plan a migration to InterWorx 8 (which requires EL8/EL9) before $eol."
                fi
                ;;
            8)
                if _iw_ver_lt "$ver" "8.0.30"; then
                    _iw_emit security critical manual interworx_cve_2025_13057 interworx \
                        "InterWorx $ver is affected by IWX-CVE-2025-13057" \
                        "InterWorx 8 releases up to 8.0.29 are affected by IWX-CVE-2025-13057 (critical, .htaccess file exposure). It is fixed in 8.0.30." \
                        "Update InterWorx to 8.0.30 or later through the panel's own update path (NodeWorx software update settings). Do not run the updater from claude-watchman."
                fi
                ;;
        esac
    fi

    # 2. End-of-life PHP in use: remi pool files per EOL branch. Only a file that defines a
    #    pool (has a listen= line) counts: www.conf is the stock pool, not a site, and
    #    InterWorx drops shared settings files such as 10-iworx-process-control-timeout.conf
    #    into every branch's php-fpm.d, so a branch with no sites still holds a .conf.
    local tok n f d
    for tok in ${WATCHMAN_EOL_PHP_IW:-$_IW_EOL_PHP_DEFAULT}; do
        tok="${tok#php}"
        [[ "$tok" =~ ^[0-9]+$ ]] || continue
        d="$remi/php$tok/php-fpm.d"
        [[ -d "$d" ]] || continue
        n=0
        for f in "$d"/*.conf; do
            [[ -e "$f" ]] || continue
            [[ "${f##*/}" == www.conf ]] && continue
            grep -qE '^[[:space:]]*listen[[:space:]]*=' "$f" 2>/dev/null || continue
            n=$((n + 1))
        done
        if (( n > 0 )); then
            _iw_emit security medium manual interworx_eol_php "php$tok" \
                "$n PHP-FPM pool(s) on end-of-life PHP (php$tok)" \
                "$n site pool(s) under $d run php$tok, which no longer receives security fixes. Each site on it is exposed to known PHP-level vulnerabilities." \
                "In SiteWorx or NodeWorx (PHP options), move the affected sites to a supported PHP version. Test each application first; changing PHP can break a site."
        fi
    done

    # 3. PHP-FPM socket drift (the 503 cause): a vhost proxies to a unix socket that no
    #    pool listens on. Skipped entirely when no remi pool declares a listen path.
    local listens
    listens="$(
        for f in "$remi"/*/php-fpm.d/*.conf; do
            [[ -e "$f" ]] || continue
            awk '
                /^[[:space:]]*[;#]/ { next }
                /^[[:space:]]*\[/ { pool=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", pool); next }
                /^[[:space:]]*listen[[:space:]]*=/ {
                    v=$0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]*;.*$/, "", v); gsub(/["\047[:space:]]/, "", v)
                    gsub(/\$pool/, pool, v); if (v ~ /^\//) print v
                }' "$f" 2>/dev/null || true
        done | _iw_norm_sock | sort -u || true
    )"
    if [[ -n "$listens" ]]; then
        local v base socks s missing
        for v in "$confd"/vhost_*.conf; do
            [[ -e "$v" ]] || continue
            base="${v##*/}"
            socks="$(grep -vE '^[[:space:]]*#' "$v" 2>/dev/null \
                | grep -oE 'unix:[^|"[:space:]]+' 2>/dev/null \
                | sed 's/^unix://' | _iw_norm_sock | sort -u || true)"
            [[ -n "$socks" ]] || continue
            missing=""
            while IFS= read -r s; do
                [[ -n "$s" ]] || continue
                grep -qxF -- "$s" <<<"$listens" || missing="${missing:+$missing }$s"
            done <<<"$socks"
            if [[ -n "$missing" ]]; then
                _iw_emit config high review interworx_php_socket_drift "$base" \
                    "PHP-FPM socket in $base matches no pool" \
                    "$base proxies PHP to unix socket(s) that no PHP-FPM pool under $remi listens on: $missing. Requests for that site fail with 503. This happens when a PHP or SSL change rewrites the vhost with a socket name (remi vs remi-safe) that differs from an older pool file." \
                    "Do not hand-edit the vhost; the panel rebuilds it. In NodeWorx/SiteWorx, re-save the site's PHP version (or rebuild the vhost) so the vhost and the pool agree, then confirm the pool's listen path matches."
            fi
        done
    fi

    # 4a. daemontools services (qmail, djbdns, ...). A plain "down" can be deliberate
    #     (a ./down file), so only "down ..., normally up" and up < 30s (flapping) count.
    #     A per-IP service such as tinydns-<ip> journals as its base name.
    local sv; sv="$(_iw_svstat)"
    if [[ -n "$sv" && -d "$svcdir" ]]; then
        local -A seen=()
        local line name target secs
        for d in "$svcdir"/*; do
            [[ -d "$d" ]] || continue
            name="${d##*/}"
            target="$(sed -E 's/-([0-9]{1,3}\.){3}[0-9]{1,3}$//; s/-[0-9A-Fa-f]*:[0-9A-Fa-f:]*$//' <<<"$name")"
            [[ -n "$target" && -z "${seen[$target]:-}" ]] || continue
            line="$(timeout 10 "$sv" "$d" 2>/dev/null | head -1 || true)"
            if [[ "$line" =~ :\ down\ [0-9]+\ seconds,\ normally\ up ]]; then
                seen[$target]=1
                _iw_emit config high review interworx_service_down "$target" \
                    "daemontools service $target is down" \
                    "svstat reports $target down although it is configured to run (no ./down file). On InterWorx, mail (smtp, send) and DNS (tinydns, dnscache, axfrdns) run under daemontools, not systemd, so systemctl does not show this." \
                    "Read the service log under $svcdir/<service>/log/main (TAI64 timestamps: pipe through tai64nlocal) to find the cause, then restart it through NodeWorx or with svc after diagnosis."
            elif [[ "$line" =~ :\ up\ \(pid\ [0-9]+\)\ ([0-9]+)\ seconds ]]; then
                secs="${BASH_REMATCH[1]}"
                if (( secs < 30 )); then
                    seen[$target]=1
                    _iw_emit config high review interworx_service_flapping "$target" \
                        "daemontools service $target is restarting (up ${secs}s)" \
                        "svstat reports $target up for only ${secs} seconds. Repeated short uptimes mean supervise keeps restarting a crashing service." \
                        "Read the service log under $svcdir/<service>/log/main (TAI64 timestamps: pipe through tai64nlocal) to find why it exits."
                fi
            fi
        done
    fi

    # 4b. Panel systemd units: the panel's own web server and database. Only units that
    #     exist are checked.
    local u en st
    for u in ${IW_PANEL_UNITS:-httpd-iworx iworx-db-mariadb}; do
        en="$(service_enabled "$u" 2>/dev/null || true)"
        [[ -n "$en" && "$en" != not-found ]] || continue
        st="$(service_status "$u" 2>/dev/null || true)"
        case "$st" in
            active|activating|reloading) ;;
            *)
                _iw_emit config high review interworx_panel_unit_down "$u" \
                    "InterWorx panel unit $u is not running" \
                    "systemd reports $u as '${st:-unknown}'. It is part of the InterWorx control plane (the panel web server or the panel database, separate from the system httpd and mariadb), so NodeWorx/SiteWorx and panel cron jobs fail while it is down." \
                    "Inspect it with systemctl status $u and journalctl -u $u, then start it after diagnosis."
                ;;
        esac
    done

    # 5. Panel login reachable over plaintext HTTP. NodeWorx serves its login on the
    #    plain-HTTP panel port with no redirect on a default install.
    local port="${IW_PANEL_HTTP_PORT:-2080}" exposed=""
    if [[ "$port" =~ ^[0-9]+$ ]] && command -v ss >/dev/null 2>&1; then
        exposed="$(timeout 10 ss -ltn 2>/dev/null | awk -v p=":$port" '
            NR==1 && $1=="State" { next }
            { a=$4; if (substr(a, length(a)-length(p)+1) != p) next
              if (a ~ /^127\./ || a ~ /^\[::1\]:/ || a ~ /^::1:/) next
              print a; exit }' || true)"
    fi
    # Listening is not exposure: once the operator closes the port in the panel firewall
    # (the remediation below), the listener stays, so firing on it alone would journal a
    # false "regressed" every pass. With CSF or APF configured, require the port in its
    # inbound list; with neither, a bare listener is the best signal we have.
    if [[ -n "$exposed" ]]; then
        local fwports=""
        if [[ -r "$csfconf" ]]; then
            fwports="$(_iw_conf_val "$csfconf" TCP_IN),$(_iw_conf_val "$csfconf" TCP6_IN)"
        elif [[ -r "$apfconf" ]]; then
            fwports="$(_iw_conf_val "$apfconf" IG_TCP_CPORTS)"
        fi
        if [[ -n "$fwports" ]] && ! _iw_port_in_list "$port" "$fwports"; then
            exposed=""
        fi
    fi
    if [[ -n "$exposed" ]]; then
        _iw_emit security high review interworx_panel_plaintext "nodeworx-http" \
            "NodeWorx panel login served over plaintext HTTP on $port" \
            "The InterWorx panel listens on TCP $port (plain HTTP). On a default install the NodeWorx login is served there with no redirect to HTTPS, so panel credentials can cross the network unencrypted." \
            "After confirming no one relies on port $port, remove it from the firewall's inbound ports (CSF TCP_IN/TCP6_IN, or APF IG_TCP_CPORTS) and use the HTTPS panel port instead. Review tier: a firewall change, confirm the exact edit first."
    fi

    # 6. Firewall left in test mode, and panel brute-force lockout not wired into LFD.
    if [[ -r "$csfconf" ]]; then
        if [[ "$(_iw_conf_val "$csfconf" TESTING)" == 1 ]]; then
            _iw_emit security high review interworx_csf_testing csf \
                "CSF firewall is in TESTING mode" \
                "TESTING = \"1\" in csf.conf: CSF flushes its rules on a cron timer and LFD does not run, so the server is effectively unprotected by the firewall and brute-force blocking." \
                "After verifying the allowed ports (TCP_IN/TCP6_IN include SSH and the HTTPS panel port), set TESTING = \"0\" and restart csf/lfd. Review tier: a wrong port list can sever SSH."
        fi
        local iwi lfi
        iwi="$(_iw_conf_val "$csfconf" INTERWORX)"
        lfi="$(_iw_conf_val "$csfconf" LF_INTERWORX)"
        if [[ "$iwi" == 0 || "$lfi" == 0 ]]; then
            _iw_emit security medium review interworx_csf_integration_off csf-interworx \
                "Panel brute-force lockout not wired into CSF/LFD" \
                "csf.conf has the InterWorx integration disabled (INTERWORX or LF_INTERWORX set to 0), so LFD does not block repeated failed NodeWorx/SiteWorx logins." \
                "Enable INTERWORX and set LF_INTERWORX to a failure threshold in csf.conf, then restart lfd."
        fi
    fi
    if [[ -r "$apfconf" && "$(_iw_conf_val "$apfconf" DEVEL_MODE)" == 1 ]]; then
        _iw_emit security high review interworx_apf_devel apf \
            "APF firewall is in development mode" \
            "DEVEL_MODE=\"1\" in conf.apf: APF flushes the firewall every 5 minutes, so the rules never stay in force. InterWorx documents that it must not be left on." \
            "After verifying the allowed ports (IG_TCP_CPORTS includes SSH and the HTTPS panel port), set DEVEL_MODE=\"0\" and restart APF (NodeWorx firewall settings). Review tier: a wrong port list can sever SSH."
    fi

    # 7. qmail outbound queue: a sudden backlog usually means an account is spamming.
    if [[ -x "$qstat" ]]; then
        local qmax qn
        qmax="${WATCHMAN_QMAIL_QUEUE_MAX:-1000}"; [[ "$qmax" =~ ^[0-9]+$ ]] || qmax=1000
        qn="$(timeout 30 "$qstat" 2>/dev/null | sed -nE 's/^messages in queue:[[:space:]]*([0-9]+).*/\1/p' | head -1 || true)"
        [[ "$qn" =~ ^[0-9]+$ ]] || qn=0
        if (( qn > qmax )); then
            _iw_emit security high review interworx_mail_queue_spike qmail-queue \
                "qmail mail queue is large ($qn messages)" \
                "The qmail queue holds $qn messages (alert above $qmax). A sudden backlog often means a compromised account or script is sending bulk spam through this server, risking IP blacklisting." \
                "Use the NodeWorx mail queue tools (or qmail-qread) to identify the sending account; suspend it through the panel if confirmed compromised. Do NOT clear the queue blindly."
        fi
    fi

    # 8. Hotfix auto-apply turned off ([update] autohotfix). Only an explicit off value
    #    counts; anything else (including an unrecognized value) stays silent.
    case "$(_iw_ini_get "$ini" update autohotfix)" in
        0|false|off|no)
            _iw_emit security medium review interworx_autohotfix_off iworx-autohotfix \
                "InterWorx hotfix auto-apply is off" \
                "iworx.ini [update] autohotfix is off, so InterWorx security hotfixes are not applied automatically and the panel can sit behind a published fix." \
                "In the NodeWorx software update settings, turn automatic hotfixes back on, or document who applies hotfixes by hand."
            ;;
    esac

    # 9. Pre-release update channel (rc/beta) enabled in the InterWorx repo files.
    local chans="" rf
    for rf in "$reposd"/interworx-*.repo; do
        [[ -e "$rf" ]] || continue
        chans+="$(awk '
            /^[[:space:]]*\[/ { sec=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", sec); next }
            sec ~ /^interworx-[0-9]+-(rc|beta)$/ && /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*1[[:space:]]*$/ {
                c=sec; sub(/^interworx-[0-9]+-/, "", c); print c }' "$rf" 2>/dev/null || true)"$'\n'
    done
    chans="$(printf '%s' "$chans" | awk 'NF' | sort -u | paste -sd, - || true)"
    if [[ -n "$chans" ]]; then
        _iw_emit config low manual interworx_update_channel iworx-channel \
            "InterWorx pre-release update channel enabled ($chans)" \
            "The InterWorx yum repo has the $chans channel enabled. Those channels ship less-tested builds than the release channel, which is riskier on production." \
            "If this is production, switch the NodeWorx software update channel back to Release."
    fi

    # 10. Failed panel logins (security log review). login.log records successful sessions
    #     only; a failed NodeWorx/SiteWorx login is written to login_failures.log, which
    #     the panel creates on the first failure and LFD watches when CSF's InterWorx
    #     integration is on. Line format: "YYYY-MM-DD HH:MM:SS <NW|SW> <ip> <login>".
    #     Counts the last 24h; the login name is never emitted, only source IPs.
    local lfl="${IW_LOGIN_FAIL_LOG:-$root/var/log/login_failures.log}"
    if [[ -r "$lfl" ]]; then
        local since lmax lsum
        since="${IW_NOW_MINUS_24H:-$(date -d '24 hours ago' '+%F %T' 2>/dev/null || true)}"
        lmax="${WATCHMAN_IW_LOGIN_FAIL_MAX:-20}"; [[ "$lmax" =~ ^[0-9]+$ ]] || lmax=20
        if [[ -n "$since" ]]; then
            # Prints "<total> <distinct-ips> <top: ip(n), ...>" for lines at or after $since.
            lsum="$(awk -v since="$since" '
                $1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/ && ($1 " " $2) >= since && $4 != "" {
                    t++; if (!($4 in c)) d++; c[$4]++ }
                END {
                    if (!t) exit
                    top=""
                    for (k = 0; k < 3; k++) { best=""; for (ip in c) if (best == "" || c[ip] > c[best]) best=ip
                        if (best == "") break
                        top = top (top == "" ? "" : ", ") best "(" c[best] ")"; delete c[best] }
                    print t, d, top }' "$lfl" 2>/dev/null || true)"
            local ltot="${lsum%% *}"
            if [[ "$ltot" =~ ^[0-9]+$ ]] && (( ltot > lmax )); then
                local rest="${lsum#* }" ldist ltop
                ldist="${rest%% *}"; ltop="${rest#* }"
                _iw_emit security medium review interworx_login_failures nodeworx-login \
                    "$ltot failed panel logins in the last 24h" \
                    "login_failures.log recorded $ltot failed NodeWorx/SiteWorx logins in the last 24 hours (alert above $lmax) from $ldist source IP(s). Top sources: $ltop. Sustained failures mean someone is guessing panel passwords." \
                    "Confirm CSF's InterWorx lockout is on (INTERWORX=1 and LF_INTERWORX set in csf.conf) and that LFD is blocking the top sources (see /var/log/lfd.log). Consider limiting the panel ports to admin IPs and enabling two-factor login for panel users. Review tier: firewall changes go through the operator."
            fi
        fi
    fi

    # 11. Panel-installed web application auto-updates off ([scriptworx] autoupdate).
    #     ScriptWorx is the panel's one-click app installer; with autoupdate off, apps it
    #     installed (CMSs and the like) are not updated by the panel. Explicit off only.
    case "$(_iw_ini_get "$ini" scriptworx autoupdate)" in
        0|false|off|no)
            _iw_emit config low manual interworx_scriptworx_autoupdate_off iworx-scriptworx \
                "Auto-updates for panel-installed web apps are off" \
                "iworx.ini [scriptworx] autoupdate is off, so web applications installed through the panel's app installer are not updated automatically. An outdated CMS is a common way into a hosting server." \
                "If sites use panel-installed apps, either turn ScriptWorx auto-updates on in NodeWorx or confirm each site owner keeps their app patched."
            ;;
    esac
    return 0
}
