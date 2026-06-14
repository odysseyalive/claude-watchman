#!/usr/bin/env bash
# lib/preflight.sh — ONE manifest, TWO generated allowlists.
#
# There is exactly one declaration of what a skill may touch — its per-skill
# manifest.json — and EVERY privilege artifact is generated from it. Nothing is
# hand-maintained, so nothing can drift (CLAUDE.md "One manifest, two generated
# allowlists"):
#
#   skills/<stage>/<name>/manifest.json   (the single source of truth)
#        │  collated here, resolved through lib/distro.sh + lib/profile.sh
#        ├─► .claude/settings.local.json   what the AGENT may invoke
#        └─► /etc/sudoers.d/watchman (body) what the watchman USER may run as root
#
# Both come from the SAME resolved set in the SAME run, so they cannot drift: a
# command can never be allowed at one layer but missing from the other.
#
# Scope: the generated allowlist covers ONLY read-only Observe/Analyze and the
# report/email path. It deliberately does NOT grant the fixer's mutating actions
# (firewall_*, service_*, config edits) — under dontAsk those auto-deny, so the
# headless loop physically cannot apply a review/manual remediation. That is the
# second seatbelt; the sudoers file (no mutating families) is the third.
#
# This script writes settings.local.json and STAGES the sudoers body to a file.
# It NEVER writes /etc/sudoers.d/watchman itself — install.sh, running as root,
# validates the staged body with `visudo -cf` and installs it. And it NEVER
# clobbers an existing base settings.json (fixed policy the operator may tune).

set -o pipefail
_PF_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCHMAN_ROOT="${WATCHMAN_ROOT:-$(cd "$_PF_LIB_DIR/.." && pwd)}"
# shellcheck source=lib/distro.sh
source "$_PF_LIB_DIR/distro.sh"
# shellcheck source=lib/profile.sh
source "$_PF_LIB_DIR/profile.sh"

WATCHMAN_USER="${WATCHMAN_USER:-watchman}"
WATCHMAN_CLAUDE_DIR="${WATCHMAN_CLAUDE_DIR:-$WATCHMAN_ROOT/.claude}"
WATCHMAN_SUDOERS_STAGE="${WATCHMAN_SUDOERS_STAGE:-$WATCHMAN_ROOT/.watchman-sudoers.staged}"

# --- Framework base ---------------------------------------------------------
# Commands the framework itself runs regardless of any skill: the journal gate
# (sqlite3) and manifest tooling (jq). Fixed, not manifest-derived — same spirit
# as the deny base. Never needs sudo.
_pf_framework_allow() {
    printf '%s\n' \
        'Bash(sqlite3 *)' \
        'Bash(jq *)'
}

# --- resolver_op expansion --------------------------------------------------
# A manifest declares LOGICAL ops (so it stays family-blind); the preflight maps
# each to the concrete command(s) for THIS family. Output lines are TSV:
#   <allow-args>\t<needs_sudo:0|1>\t<sudoers-cmd-or-->
# allow-args is what goes inside Bash(...) (already prefixed with sudo when root).
_pf_expand_resolver_op() {
    local op="$1" fam; fam="$(watchman_family)"
    case "$op" in
        pkg_query)
            case "$fam" in
                arch)   printf 'pacman -Q*\t0\t-\n' ;;
                debian) printf 'dpkg -s *\t0\t-\n'; printf 'dpkg-query *\t0\t-\n'; printf 'apt-get -s *\t0\t-\n' ;;
                rhel)   printf 'rpm -q*\t0\t-\n'; printf 'dnf -q check-update*\t0\t-\n' ;;
            esac ;;
        service_status)
            printf 'systemctl is-active *\t0\t-\n'
            printf 'systemctl is-enabled *\t0\t-\n'
            printf 'systemctl status *\t0\t-\n'
            printf 'systemctl show *\t0\t-\n' ;;
        journal_read)   # journald often needs root to read across boots
            printf 'sudo journalctl *\t1\t/usr/bin/journalctl\n' ;;
        net_connections)
            printf 'ss *\t0\t-\n' ;;
        firewall_list)
            case "$(watchman_firewall_backend)" in
                ufw)       printf 'sudo ufw status*\t1\t%s\n' "$(_pf_abspath ufw)" ;;
                firewalld) printf 'sudo firewall-cmd --list*\t1\t%s\n' "$(_pf_abspath firewall-cmd)" ;;
                nftables)  printf 'sudo nft list*\t1\t%s\n' "$(_pf_abspath nft)" ;;
            esac ;;
        integrity_verify)
            case "$(integrity_verifier)" in
                pacman)  printf 'pacman -Qkk*\t0\t-\n' ;;
                debsums) printf 'sudo debsums *\t1\t%s\n' "$(_pf_abspath debsums)" ;;
                rpm)     printf 'rpm -Va*\t0\t-\n' ;;
                aide)    printf 'sudo aide --check*\t1\t%s\n' "$(_pf_abspath aide)" ;;
            esac ;;
        mac_status)
            case "$(mac_layer)" in
                apparmor) printf 'sudo aa-status*\t1\t%s\n' "$(_pf_abspath aa-status)" ;;
                selinux)  printf 'getenforce*\t0\t-\n'; printf 'sestatus*\t0\t-\n' ;;
                none)     : ;;   # no command — absence is the finding, nothing to run
            esac ;;
        *) echo "preflight: unknown resolver_op '$op'" >&2 ;;
    esac
}

_pf_abspath() { command -v "$1" 2>/dev/null || printf '/usr/bin/%s' "$1"; }

# --- reads resolution -------------------------------------------------------
# A read entry is either a resolver token (a function in distro.sh, e.g.
# log_path_auth) or a literal path. Tokens are resolved by CALLING the function
# (no eval). A resolved value that is the journald sentinel is skipped here — it
# is covered by the journal_read resolver_op's journalctl allow, not a file Read.
# For every real path we grant its containing directory tree once.
_pf_resolve_read() {
    local entry="$1"
    local val="$entry"   # NB: keep on its own line — `local a=$1 b=$a` does NOT
                         # populate b from the just-assigned a in bash.
    if [[ "$entry" != /* ]] && declare -F "$entry" >/dev/null 2>&1; then
        val="$("$entry")"
    fi
    [[ "$val" == journald:* ]] && return 0   # not a file path
    [[ "$val" == /* ]] || return 0           # ignore anything non-absolute/unknown
    printf '%s\n' "$val"
}

# --- Collation --------------------------------------------------------------
# Walk every manifest, resolve, and accumulate de-duplicated allow rules,
# additionalDirectories, and sudoers command paths.
preflight_collate() {
    local -a allow=() adddirs=() sudoers=()
    mapfile -t allow < <(_pf_framework_allow)

    local m
    while IFS= read -r m; do
        [[ -r "$m" ]] || continue

        # reads → Read globs + additionalDirectories
        local r path dir
        while IFS= read -r r; do
            [[ -n "$r" ]] || continue
            path="$(_pf_resolve_read "$r")"
            [[ -n "$path" ]] || continue
            # If the path is a file, grant its dir; if a dir, grant the dir itself.
            if [[ -d "$path" ]]; then dir="$path"; else dir="$(dirname "$path")"; fi
            allow+=("Read(${dir}/**)")
            adddirs+=("/${dir}")            # doubled leading slash (dir already starts with /)
        done < <(jq -r '.reads[]?' "$m" 2>/dev/null)

        # direct commands
        local fam args sudo
        while IFS=$'\t' read -r fam args sudo; do
            [[ -n "$fam" ]] || continue
            [[ "$args" == "null" || -z "$args" ]] && args='*'
            if [[ "$sudo" == "true" ]]; then
                allow+=("Bash(sudo ${fam} ${args})")
                sudoers+=("$(_pf_abspath "$fam") ${args}")
            else
                allow+=("Bash(${fam} ${args})")
            fi
        done < <(jq -r '.commands[]? | [.family, (.args // "*"), (.needs_sudo // false | tostring)] | @tsv' "$m" 2>/dev/null)

        # resolver_ops → concrete per-family commands
        local op line aargs nsudo scmd
        while IFS= read -r op; do
            [[ -n "$op" ]] || continue
            while IFS=$'\t' read -r aargs nsudo scmd; do
                [[ -n "$aargs" ]] || continue
                allow+=("Bash(${aargs})")
                if [[ "$nsudo" == "1" && "$scmd" != "-" ]]; then
                    # strip the leading 'sudo ' to recover the bare command+args for sudoers
                    local bare="${aargs#sudo }"
                    local bare_args="${bare#* }"
                    sudoers+=("${scmd} ${bare_args}")
                fi
            done < <(_pf_expand_resolver_op "$op")
        done < <(jq -r '.resolver_ops[]?' "$m" 2>/dev/null)

    done < <(find "$WATCHMAN_ROOT/skills" -mindepth 3 -maxdepth 3 -name manifest.json 2>/dev/null | sort)

    # Emit three NUL-free, de-duplicated, sorted lists on FDs via globals.
    printf '%s\n' "${allow[@]}"   | awk 'NF' | sort -u > "$WATCHMAN_ROOT/.pf.allow"
    printf '%s\n' "${adddirs[@]}" | awk 'NF' | sort -u > "$WATCHMAN_ROOT/.pf.dirs"
    printf '%s\n' "${sudoers[@]}" | awk 'NF' | sort -u > "$WATCHMAN_ROOT/.pf.sudoers"
}

# --- Base policy (fixed, not manifest-derived) ------------------------------
# Written to <claude>/settings.json ONLY if absent — never clobbered, since the
# operator may tune it. defaultMode dontAsk: anything in allow runs, everything
# else auto-DENIES and fails loudly (no silent hang, no prompt). The deny list is
# defense-in-depth against destructive actions that an allow can never override.
preflight_write_base_settings() {
    local claude_dir="$1" target="$1/settings.json"
    mkdir -p "$claude_dir"
    if [[ -e "$target" ]]; then
        echo "preflight: base settings.json exists — leaving it untouched." >&2
        return 0
    fi
    cat >"$target" <<'JSON'
{
  "permissions": {
    "defaultMode": "dontAsk",
    "deny": [
      "Read(.env)",
      "Read(./.env)",
      "Bash(rm *)",
      "Bash(rm -rf *)",
      "Bash(sudo rm *)",
      "Bash(dd *)",
      "Bash(mkfs *)",
      "Bash(mkfs.*)",
      "Bash(shutdown *)",
      "Bash(reboot *)",
      "Bash(systemctl stop *)",
      "Bash(systemctl disable *)",
      "Bash(sudo systemctl stop *)",
      "Bash(sudo systemctl disable *)",
      "Bash(userdel *)",
      "Bash(usermod *)",
      "Bash(passwd *)",
      "Bash(visudo *)",
      "Bash(* /etc/sudoers*)"
    ]
  }
}
JSON
    echo "preflight: wrote base policy $target" >&2
}

# --- Emit settings.local.json ----------------------------------------------
preflight_write_local_settings() {
    local claude_dir="$1" target="$1/settings.local.json"
    mkdir -p "$claude_dir"
    local allow dirs
    allow="$(cat "$WATCHMAN_ROOT/.pf.allow" 2>/dev/null)"
    dirs="$(cat "$WATCHMAN_ROOT/.pf.dirs" 2>/dev/null)"
    jq -n --arg allow "$allow" --arg dirs "$dirs" '
      {permissions: {
         allow: ($allow | split("\n") | map(select(length>0))),
         additionalDirectories: ($dirs | split("\n") | map(select(length>0)))
      }}' > "$target"
    echo "preflight: wrote agent allowlist $target ($(jq '.permissions.allow|length' "$target") allow rules)" >&2
}

# --- Stage sudoers body -----------------------------------------------------
# install.sh (root) validates this with `visudo -cf` and installs it to
# /etc/sudoers.d/watchman. Only needs_sudo read/observe commands appear — never a
# blanket ALL, never a mutating family.
preflight_stage_sudoers() {
    local out="$1"
    {
        echo "# /etc/sudoers.d/watchman — GENERATED by lib/preflight.sh. Do not edit by hand."
        echo "# Only the read/observe commands the skill manifests declared as needs_sudo."
        echo "# The fixer's mutating commands are deliberately ABSENT (third seatbelt)."
        echo "Defaults:${WATCHMAN_USER} !requiretty"
        local cmd
        while IFS= read -r cmd; do
            [[ -n "$cmd" ]] || continue
            echo "${WATCHMAN_USER} ALL=(root) NOPASSWD: ${cmd}"
        done < "$WATCHMAN_ROOT/.pf.sudoers"
    } > "$out"
    echo "preflight: staged sudoers body at $out ($(grep -c NOPASSWD "$out") commands)" >&2
}

# --- Public entry -----------------------------------------------------------
# Regenerate every privilege artifact from the manifests. Safe to re-run.
preflight_run() {
    command -v jq >/dev/null 2>&1 || { echo "preflight: jq is required (install.sh adds it)." >&2; return 1; }
    preflight_collate
    preflight_write_base_settings  "$WATCHMAN_CLAUDE_DIR"
    preflight_write_local_settings "$WATCHMAN_CLAUDE_DIR"
    preflight_stage_sudoers        "$WATCHMAN_SUDOERS_STAGE"
    rm -f "$WATCHMAN_ROOT/.pf.allow" "$WATCHMAN_ROOT/.pf.dirs" "$WATCHMAN_ROOT/.pf.sudoers"
}

# Allow running directly: `bash lib/preflight.sh`
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then preflight_run; fi
