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

log_path_webserver() {
    # Prefer whichever tree exists; both families ship under /var/log.
    if   [[ -d /var/log/nginx  ]]; then echo /var/log/nginx
    elif [[ -d /var/log/apache2 ]]; then echo /var/log/apache2     # Debian
    elif [[ -d /var/log/httpd  ]]; then echo /var/log/httpd        # RHEL
    else echo /var/log/nginx; fi                                   # default target
}

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
    case "$(integrity_verifier)" in
        debsums) sudo debsums -c 2>/dev/null ;;            # prints failures only
        rpm)     rpm -Va 2>/dev/null | awk '$1 ~ /5/{print $NF}' ;;  # files w/ MD5 mismatch
        pacman)  pacman -Qkk 2>/dev/null | awk '/warning|FAILED/{print}' ;;
        aide)    sudo aide --check 2>/dev/null ;;
        *) echo "integrity: no verifier available" >&2; return 2 ;;
    esac
}
