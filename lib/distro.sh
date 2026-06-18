#!/usr/bin/env bash
# lib/distro.sh — the resolver for the HOW.
#
# Detects the distro family ONCE from /etc/os-release and exposes a stable
# vocabulary so skills stay family-blind. A skill says `pkg_is_installed nginx`
# or `firewall_allow 443/tcp`; it never knows whether the command was apt,
# pacman, or dnf. Adding a fourth family means editing THIS file, not every skill.
#
# Family-specific truths this resolver encodes (CLAUDE.md):
#   * MAC differs: AppArmor (Debian) / SELinux (RHEL) / none (Arch).
#   * Auto-update differs: unattended-upgrades / dnf-automatic / (rolling: n/a).
#   * Firewall front-end differs: ufw / firewalld / nftables.
#   * Integrity verifier differs: debsums / rpm -V / pacman -Qkk.
#   * Auth log path differs: /var/log/auth.log vs /var/log/secure vs journald.
#
# READ-ONLY by nature for the observe path. The mutating ops (firewall_allow,
# service_restart, pkg_install) exist for the installer and the operator-run
# fixer; under the loop's dontAsk allowlist they are never granted, so the
# unattended loop physically cannot call them — a deliberate second seatbelt.

# --- Family detection -------------------------------------------------------
# WATCHMAN_FAMILY: debian | rhel | arch. Cached after first detection.
watchman_detect_family() {
    if [[ -n "${WATCHMAN_FAMILY:-}" ]]; then
        printf '%s\n' "$WATCHMAN_FAMILY"; return 0
    fi
    local id="" like=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        id="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")"
        like="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID_LIKE:-}")"
    fi
    local f=""
    case " $id $like " in
        *" debian "*|*" ubuntu "*) f="debian" ;;
        *" rhel "*|*" fedora "*|*" centos "*) f="rhel" ;;
        *" arch "*) f="arch" ;;
    esac
    # Fallback: probe the package manager if os-release was unhelpful.
    if [[ -z "$f" ]]; then
        if   command -v apt-get >/dev/null 2>&1; then f="debian"
        elif command -v dnf     >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then f="rhel"
        elif command -v pacman  >/dev/null 2>&1; then f="arch"
        else f="unknown"; fi
    fi
    WATCHMAN_FAMILY="$f"
    printf '%s\n' "$f"
}

# Convenience guard for callers.
watchman_family() { watchman_detect_family; }

# --- Package operations -----------------------------------------------------
pkg_is_installed() {
    local p="$1"
    case "$(watchman_family)" in
        debian) dpkg -s "$p"     >/dev/null 2>&1 ;;
        rhel)   rpm -q "$p"      >/dev/null 2>&1 ;;
        arch)   pacman -Qi "$p"  >/dev/null 2>&1 ;;
        *) return 2 ;;
    esac
}

# MUTATING — installer/operator only; absent from the loop's allowlist.
pkg_install() {
    case "$(watchman_family)" in
        debian) sudo apt-get install -y "$@" ;;
        rhel)   sudo dnf install -y "$@" ;;
        arch)   sudo pacman -S --noconfirm "$@" ;;
        *) echo "pkg_install: unknown family" >&2; return 2 ;;
    esac
}

# NON-mutating: echo the install command for THIS family (no -y/--noconfirm — it is
# shown to the operator to run, not executed). Used by selfcheck to direct the user.
pkg_install_cmd() {
    case "$(watchman_family)" in
        debian) echo "sudo apt-get install" ;;
        rhel)   echo "sudo dnf install" ;;
        arch)   echo "sudo pacman -S" ;;
        *) echo "" ;;
    esac
}

# NON-mutating: echo the package name for a command on THIS family (names diverge:
# sqlite3 -> sqlite on Arch; cscli ships in the crowdsec package).
pkg_for_cmd() {
    case "$1:$(watchman_family)" in
        sqlite3:arch) echo sqlite ;;
        cscli:*)      echo crowdsec ;;
        *)            echo "$1" ;;
    esac
}

# --- Security currency (keeping defenses current) --------------------------
# NON-mutating: the command that APPLIES pending security/system updates (shown to
# the operator, never run by the loop — applying an update can break a server).
security_update_cmd() {
    case "$(watchman_family)" in
        debian) echo "sudo apt-get update && sudo apt-get upgrade" ;;
        rhel)   echo "sudo dnf upgrade --security" ;;
        arch)   echo "sudo pacman -Syu" ;;
        *) echo "" ;;
    esac
}

# Days since the package metadata was last synced — i.e. how stale our VIEW of
# available updates is. -1 when it cannot be determined. Read-only (no network).
pkg_db_age_days() {
    local f="" now
    case "$(watchman_family)" in
        debian) f="/var/lib/apt/periodic/update-success-stamp"; [[ -e "$f" ]] || f="/var/cache/apt/pkgcache.bin" ;;
        arch)   f="$(ls -1t /var/lib/pacman/sync/*.db 2>/dev/null | head -1 || true)" ;;
        rhel)   f="/var/cache/dnf" ;;
    esac
    [[ -n "$f" && -e "$f" ]] || { echo -1; return; }
    now="$(date +%s)"
    echo $(( (now - $(stat -c%Y "$f" 2>/dev/null || echo "$now")) / 86400 ))
}

# Which CVE/vulnerability scanner is available for THIS family (none if absent).
vuln_scanner() {
    case "$(watchman_family)" in
        debian) command -v debsecan   >/dev/null 2>&1 && echo debsecan   || echo none ;;
        arch)   command -v arch-audit >/dev/null 2>&1 && echo arch-audit || echo none ;;
        rhel)   command -v dnf        >/dev/null 2>&1 && echo dnf        || echo none ;;
        *) echo none ;;
    esac
}

# Run the available scanner read-only; echo vulnerable-package lines (empty = none).
vuln_scan() {
    case "$(vuln_scanner)" in
        debsecan)   debsecan --only-fixed 2>/dev/null ;;
        arch-audit) arch-audit -u 2>/dev/null ;;                       # -u: vulnerable AND fixable
        dnf)        dnf updateinfo list --security -q 2>/dev/null | awk 'NF>=3{print $3" ("$2")"}' ;;
        *) return 2 ;;
    esac
}

pkg_list_installed() {
    case "$(watchman_family)" in
        debian) dpkg-query -W -f='${Package}\n' 2>/dev/null ;;
        rhel)   rpm -qa --qf '%{NAME}\n' 2>/dev/null ;;
        arch)   pacman -Qq 2>/dev/null ;;
        *) return 2 ;;
    esac
}

pkg_list_upgradable() {
    case "$(watchman_family)" in
        debian) apt-get -s upgrade 2>/dev/null | awk '/^Inst /{print $2}' ;;
        rhel)   dnf -q check-update 2>/dev/null | awk 'NF>=3 && $0!~/^Last metadata/{print $1}' ;;
        arch)   pacman -Qu 2>/dev/null | awk '{print $1}' ;;
        *) return 2 ;;
    esac
}

# --- Service operations -----------------------------------------------------
# Read-only status is observe-path; enable/restart are mutating (fixer only).
service_status()  { systemctl is-active "$1" 2>/dev/null; }
service_enabled() { systemctl is-enabled "$1" 2>/dev/null; }
service_enable()  { sudo systemctl enable --now "$1"; }     # MUTATING
service_restart() { sudo systemctl restart "$1"; }          # MUTATING

# --- Firewall operations ----------------------------------------------------
# Resolves to ufw / firewalld / nftables. firewall_list is read-only; allow/deny
# are MUTATING and, per the Prime Directive + risk tiers, must be shown exactly
# and confirmed per-rule by the operator before the fixer applies them — a wrong
# rule can sever SSH.
watchman_firewall_backend() {
    if [[ -n "${WATCHMAN_FIREWALL:-}" ]]; then printf '%s\n' "$WATCHMAN_FIREWALL"; return; fi
    local b=""
    case "$(watchman_family)" in
        debian) command -v ufw       >/dev/null 2>&1 && b="ufw" ;;
        rhel)   command -v firewall-cmd >/dev/null 2>&1 && b="firewalld" ;;
        arch)   command -v ufw       >/dev/null 2>&1 && b="ufw" ;;
    esac
    # Fall back by what is actually present, then to nftables/iptables.
    [[ -z "$b" ]] && command -v firewall-cmd >/dev/null 2>&1 && b="firewalld"
    [[ -z "$b" ]] && command -v ufw          >/dev/null 2>&1 && b="ufw"
    [[ -z "$b" ]] && command -v nft          >/dev/null 2>&1 && b="nftables"
    [[ -z "$b" ]] && b="none"
    WATCHMAN_FIREWALL="$b"
    printf '%s\n' "$b"
}

firewall_list() {
    case "$(watchman_firewall_backend)" in
        ufw)       sudo ufw status verbose ;;
        firewalld) sudo firewall-cmd --list-all ;;
        nftables)  sudo nft list ruleset ;;
        *) echo "firewall_list: no backend detected" >&2; return 2 ;;
    esac
}

# MUTATING — review-tier. spec=PORT/proto e.g. 443/tcp
firewall_allow() {
    local spec="$1"
    case "$(watchman_firewall_backend)" in
        ufw)       sudo ufw allow "$spec" ;;
        firewalld) sudo firewall-cmd --permanent --add-port="${spec/\//\/}" && sudo firewall-cmd --reload ;;
        nftables)  echo "firewall_allow: nftables changes are operator-authored; refusing to guess a rule." >&2; return 3 ;;
        *) return 2 ;;
    esac
}
firewall_deny() {  # MUTATING — review-tier
    local spec="$1"
    case "$(watchman_firewall_backend)" in
        ufw)       sudo ufw deny "$spec" ;;
        firewalld) sudo firewall-cmd --permanent --remove-port="$spec" && sudo firewall-cmd --reload ;;
        nftables)  echo "firewall_deny: nftables changes are operator-authored; refusing to guess a rule." >&2; return 3 ;;
        *) return 2 ;;
    esac
}

# --- Log paths --------------------------------------------------------------
# On systemd hosts the auth trail may live only in journald (esp. Arch). We echo
# the canonical file path where one exists, else the journald sentinel so callers
# (and the preflight) know to read via journalctl rather than a file.
log_path_auth() {
    case "$(watchman_family)" in
        debian) [[ -f /var/log/auth.log ]] && { echo /var/log/auth.log; return; } ;;
        rhel)   [[ -f /var/log/secure   ]] && { echo /var/log/secure;   return; } ;;
        arch)   [[ -f /var/log/auth.log ]] && { echo /var/log/auth.log; return; } ;;
    esac
    echo "journald:_SYSTEMD_UNIT=sshd.service"   # sentinel: read via journalctl
}

# --- Web server discovery (config-derived, NOT /var/log guesswork) ----------
# Real deployments put web logs wherever the config says: custom access_log /
# CustomLog targets, per-vhost logs under sites-enabled/conf.d, niche servers,
# non-default prefixes. Assuming /var/log/<wellknown> silently misses all of that
# and blinds inspect-logs. These resolvers instead SCAN the config roots under
# /etc (and other known roots) to learn which servers are present, then PARSE
# their configs for the ACTUAL log destinations. All read-only and fail-safe:
# any parse failure degrades to the well-known dirs, never an error.

# webserver_detect — echo "<server>\t<config_root>" for every web server present
# (detected by config dir, package, or known service unit). config_root may be
# empty when only the package/service is found. Covers the niche builds too.
    # Detection signal: a config dir OR an installed package. Deliberately NOT
    # `systemctl is-active`, which prints "unknown"/"inactive" for a unit that
    # does not exist and would false-positive every server (running-vs-stopped is
    # inventory-services' job, on the resolved unit). Package names vary by family
    # (Debian apache2 / RHEL httpd / Arch apache).
webserver_detect() {
    # nginx
    if [[ -d /etc/nginx ]] || pkg_is_installed nginx 2>/dev/null; then
        printf 'nginx\t%s\n' "$([[ -d /etc/nginx ]] && echo /etc/nginx)"
    fi
    # apache — Debian ships apache2, RHEL ships httpd, Arch ships apache
    if   [[ -d /etc/apache2 ]]; then printf 'apache\t%s\n' /etc/apache2
    elif [[ -d /etc/httpd   ]]; then printf 'apache\t%s\n' /etc/httpd
    elif pkg_is_installed apache2 2>/dev/null || pkg_is_installed httpd 2>/dev/null \
        || pkg_is_installed apache 2>/dev/null; then
        printf 'apache\t\n'
    fi
    # caddy
    if [[ -d /etc/caddy ]] || pkg_is_installed caddy 2>/dev/null; then
        printf 'caddy\t%s\n' "$([[ -d /etc/caddy ]] && echo /etc/caddy)"
    fi
    # lighttpd
    if [[ -d /etc/lighttpd ]] || pkg_is_installed lighttpd 2>/dev/null; then
        printf 'lighttpd\t%s\n' "$([[ -d /etc/lighttpd ]] && echo /etc/lighttpd)"
    fi
    # openlitespeed / litespeed
    if   [[ -d /usr/local/lsws/conf ]]; then printf 'litespeed\t%s\n' /usr/local/lsws/conf
    elif [[ -d /etc/openlitespeed   ]]; then printf 'litespeed\t%s\n' /etc/openlitespeed
    fi
    return 0
}

# webserver_config_roots — just the present config roots, one per line, deduped.
# Granted Read by the preflight so the in-session skill can re-parse configs.
webserver_config_roots() {
    webserver_detect | awk -F'\t' 'NF>=2 && $2!="" {print $2}' | sort -u
}

# webserver_log_paths — the DIRECTORIES that actually hold web logs on this host,
# parsed from each present server's config, deduped, one per line. The preflight
# grants Read on each; inspect-logs scans each. Safety net: any well-known dir
# that exists is unioned in, and a last-resort default guarantees ≥1 line.
webserver_log_paths() {
    local -A seen=()
    local results=()
    local WLP_RELBASE=""

    # ${APACHE_LOG_DIR} is set in Debian's envvars (default /var/log/apache2).
    local apache_log_dir=""
    [[ -r /etc/apache2/envvars ]] && apache_log_dir="$(
        grep -hE 'APACHE_LOG_DIR=' /etc/apache2/envvars 2>/dev/null \
            | tail -1 | sed -E 's/.*APACHE_LOG_DIR=//; s/\$\{[^}]*\}//g; s/["'\'' ]//g')"
    [[ -n "$apache_log_dir" ]] || apache_log_dir=/var/log/apache2

    _wlp_add() {  # record the dir holding a parsed log target; relies on dynamic scope
        local p="${1:-}" d
        [[ -n "$p" ]] || return 0
        p="${p%;}"; p="${p%\"}"; p="${p#\"}"; p="${p%\'}"; p="${p#\'}"
        p="${p//\$\{APACHE_LOG_DIR\}/$apache_log_dir}"
        p="${p//\$APACHE_LOG_DIR/$apache_log_dir}"
        case "$p" in
            ''|off|none|stderr|stdout|/dev/*|syslog:*) return 0 ;;
            '|'*|'$'*|'"'*) return 0 ;;            # pipe sink or unresolved variable
        esac
        if [[ "$p" != /* ]]; then                  # relative → resolve against this server's base
            [[ -n "$WLP_RELBASE" ]] || return 0
            p="$WLP_RELBASE/$p"
        fi
        d="$(dirname "$p")"
        [[ -n "${seen[$d]:-}" ]] || { seen[$d]=1; results+=("$d"); }
        return 0
    }
    _wlp_add_dir() {  # record a directory directly (no dirname)
        local d="${1:-}"
        [[ -n "$d" && -z "${seen[$d]:-}" ]] && { seen[$d]=1; results+=("$d"); }
        return 0
    }

    local server root p ar sroot
    while IFS=$'\t' read -r server root; do
        [[ -n "$server" ]] || continue
        case "$server" in
            nginx)
                [[ -n "$root" && -d "$root" ]] || root=/etc/nginx
                WLP_RELBASE="$root"
                while IFS= read -r p; do _wlp_add "$p"; done < <(
                    grep -rhE '^[[:space:]]*(access_log|error_log)[[:space:]]+' "$root" 2>/dev/null \
                        | awk '{print $2}' | sed 's/;.*//' )
                ;;
            apache)
                local aroots=()
                [[ -n "$root" && -d "$root" ]] && aroots+=("$root")
                for ar in /etc/apache2 /etc/httpd; do [[ -d "$ar" ]] && aroots+=("$ar"); done
                for ar in "${aroots[@]}"; do
                    sroot="$(grep -rhiE '^[[:space:]]*ServerRoot[[:space:]]+' "$ar" 2>/dev/null \
                                | tail -1 | awk '{print $2}' | tr -d '"')"
                    [[ -n "$sroot" ]] || sroot="$ar"
                    WLP_RELBASE="$sroot"
                    while IFS= read -r p; do _wlp_add "$p"; done < <(
                        grep -rhiE '^[[:space:]]*(CustomLog|ErrorLog|TransferLog)[[:space:]]+' "$ar" 2>/dev/null \
                            | awk '{print $2}' )
                done
                ;;
            caddy)
                [[ -n "$root" && -d "$root" ]] || root=/etc/caddy
                WLP_RELBASE=""
                while IFS= read -r p; do _wlp_add "$p"; done < <(
                    grep -rhE 'output[[:space:]]+file[[:space:]]+' "$root" 2>/dev/null \
                        | awk '{for(i=1;i<NF;i++) if($i=="file"){print $(i+1); break}}' )
                ;;
            lighttpd)
                [[ -n "$root" && -d "$root" ]] || root=/etc/lighttpd
                WLP_RELBASE=""
                while IFS= read -r p; do _wlp_add "$p"; done < <(
                    grep -rhE '(accesslog\.filename|server\.errorlog)[[:space:]]*=' "$root" 2>/dev/null \
                        | sed -E 's/.*=[[:space:]]*//' )
                ;;
            litespeed)
                [[ -d /usr/local/lsws/logs ]] && _wlp_add_dir /usr/local/lsws/logs
                ;;
        esac
    done < <(webserver_detect)

    # Safety-net union: well-known dirs that actually exist on disk.
    for p in /var/log/nginx /var/log/apache2 /var/log/httpd /var/log/caddy /var/log/lighttpd; do
        [[ -d "$p" ]] && _wlp_add_dir "$p"
    done

    # Guarantee ≥1 line so callers and the preflight always have a target.
    (( ${#results[@]} )) || results+=(/var/log/nginx)
    printf '%s\n' "${results[@]}"
    return 0
}

# Back-compat singular: the primary web-log dir (first discovered). Prefer
# webserver_log_paths in new code — a host can have several.
log_path_webserver() { webserver_log_paths | head -n1; }

log_path_lynis() { echo /var/log/lynis-report.dat; }

# --- Mandatory Access Control ----------------------------------------------
# Three DIFFERENT findings, never one. Echoes "layer:state" so the skill journals
# the correct family-specific finding (and never checks AppArmor on RHEL, etc.).
mac_layer() {   # echoes one of: apparmor | selinux | none
    case "$(watchman_family)" in
        debian) echo apparmor ;;
        rhel)   echo selinux ;;
        arch)   echo none ;;
        *) echo none ;;
    esac
}
mac_state() {   # echoes: enforcing | complain | permissive | disabled | absent
    case "$(mac_layer)" in
        apparmor)
            if command -v aa-status >/dev/null 2>&1; then
                sudo aa-status --enabled >/dev/null 2>&1 && echo enforcing || echo complain
            else echo absent; fi ;;
        selinux)
            if command -v getenforce >/dev/null 2>&1; then
                local s; s="$(getenforce 2>/dev/null)"
                case "$s" in Enforcing) echo enforcing;; Permissive) echo permissive;; *) echo disabled;; esac
            else echo absent; fi ;;
        none) echo absent ;;
    esac
}

# --- Auto-update mechanism --------------------------------------------------
# Returns the family's mechanism, or "rolling" for Arch where "security updates
# not automated" is a meaningless finding — callers must NOT emit one there.
autoupdate_mechanism() {  # echoes: unattended-upgrades | dnf-automatic | rolling
    case "$(watchman_family)" in
        debian) echo unattended-upgrades ;;
        rhel)   echo dnf-automatic ;;
        arch)   echo rolling ;;
        *) echo unknown ;;
    esac
}
autoupdate_enabled() {    # 0=enabled, 1=not, 2=n/a(rolling)
    case "$(autoupdate_mechanism)" in
        unattended-upgrades) pkg_is_installed unattended-upgrades && [[ "$(service_enabled unattended-upgrades)" == enabled ]] ;;
        dnf-automatic)       pkg_is_installed dnf-automatic && [[ "$(service_enabled dnf-automatic.timer)" == enabled ]] ;;
        rolling)             return 2 ;;
        *) return 1 ;;
    esac
}

# --- Package/file integrity verifier ---------------------------------------
# Wraps the family's own verification tool; the resolver hides which ran.
# integrity_verifier echoes the tool name; integrity_verify_all runs it read-only
# and prints modified files (empty output = clean).
integrity_verifier() {  # echoes: debsums | rpm | pacman | aide | none
    if command -v aide >/dev/null 2>&1 && [[ -f /var/lib/aide/aide.db.gz || -f /var/lib/aide/aide.db ]]; then
        echo aide; return
    fi
    case "$(watchman_family)" in
        debian) command -v debsums >/dev/null 2>&1 && echo debsums || echo none ;;
        rhel)   command -v rpm     >/dev/null 2>&1 && echo rpm     || echo none ;;
        arch)   command -v pacman  >/dev/null 2>&1 && echo pacman  || echo none ;;
        *) echo none ;;
    esac
}
integrity_verify_all() {
    # Whole-filesystem verification is the heaviest disk read in the project. If the
    # caller sourced lib/io-courtesy.sh, run it at idle I/O priority so it can't
    # compete with a busy server's real workload; otherwise run it plain.
    _iv() { if declare -F io_run >/dev/null 2>&1; then io_run "$@"; else "$@"; fi; }
    case "$(integrity_verifier)" in
        debsums) _iv sudo debsums -c 2>/dev/null ;;            # prints failures only
        rpm)     _iv rpm -Va 2>/dev/null | awk '$1 ~ /5/{print $NF}' ;;  # files w/ MD5 mismatch
        pacman)  _iv pacman -Qkk 2>/dev/null | awk '/warning|FAILED/{print}' ;;
        aide)    _iv sudo aide --check 2>/dev/null ;;
        *) echo "integrity: no verifier available" >&2; return 2 ;;
    esac
}

# --- Control panel (cPanel/WHM) --------------------------------------------
# cPanel is orthogonal to the distro family (it rides on RHEL/Ubuntu), so it is a
# separate attribute, not a fourth family. Detection is unambiguous: the cpanel
# binary at a fixed path. control_panel_detect echoes "cpanel" or "" so a skill/
# profile can branch, and the preflight (which sources this file) can resolve the
# cpanel_log_paths read token to grant Read on the real cPanel log dirs.
control_panel_detect() {   # echoes: cpanel | (empty)
    if [[ -n "${WATCHMAN_CONTROL_PANEL:-}" ]]; then printf '%s\n' "$WATCHMAN_CONTROL_PANEL"; return; fi
    local cp=""
    [[ -x /usr/local/cpanel/cpanel ]] && cp="cpanel"
    WATCHMAN_CONTROL_PANEL="$cp"
    printf '%s\n' "$cp"
}

# The authoritative cPanel version string (empty if not a cPanel box).
cpanel_version() {
    [[ -r /usr/local/cpanel/version ]] && tr -d '[:space:]' < /usr/local/cpanel/version 2>/dev/null
}

# The DIRECTORIES holding cPanel/WHM logs on this host (only those that exist).
# Granted Read by the preflight (resolver token, like webserver_log_paths) so
# inspect-cpanel can read cpsrvd/cphulkd/Exim/per-domain logs wherever they live.
cpanel_log_paths() {
    [[ "$(control_panel_detect)" == cpanel ]] || return 0
    local d
    for d in /usr/local/cpanel/logs /var/log /var/cpanel/logs \
             /usr/local/apache/domlogs /etc/apache2/logs/domlogs; do
        [[ -d "$d" ]] && printf '%s\n' "$d"
    done
}
