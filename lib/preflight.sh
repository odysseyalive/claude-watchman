#!/usr/bin/env bash
# lib/preflight.sh — ONE manifest, ONE generated allowlist.
#
# There is exactly one declaration of what a skill may touch — its per-skill
# manifest.json — and the Claude permission allowlist is generated from it.
# Nothing is hand-maintained, so nothing can drift (CLAUDE.md "One manifest,
# one generated allowlist"):
#
#   skills/<stage>/<name>/manifest.json   (the single source of truth)
#        │  collated here, resolved through lib/distro.sh + lib/profile.sh
#        └─► .claude/settings.local.json   what the AGENT may invoke
#
# claude-watchman runs as ROOT (CLAUDE.md "How it runs"), so there is no
# separate watchman user and no OS sudoers file — root invokes the read/observe
# commands directly. The safety boundary is therefore the Claude permission
# layer alone: the deny base in settings.json blocks destructive command
# patterns even as root, and under dontAsk anything not in `allow` auto-denies.
#
# Scope: the generated allowlist covers ONLY read-only Observe/Analyze and the
# report/email path. It deliberately does NOT grant the fixer's mutating actions
# (firewall_*, service_*, config edits) — under dontAsk those auto-deny, so the
# loop physically cannot apply a review/manual remediation. That is the second
# seatbelt; the deny base is the backstop beneath it.
#
# This script writes settings.local.json and NEVER clobbers an existing base
# settings.json (fixed policy the operator may tune).

set -o pipefail
_PF_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCHMAN_ROOT="${WATCHMAN_ROOT:-$(cd "$_PF_LIB_DIR/.." && pwd)}"
# shellcheck source=lib/distro.sh
source "$_PF_LIB_DIR/distro.sh"
# shellcheck source=lib/profile.sh
source "$_PF_LIB_DIR/profile.sh"

WATCHMAN_CLAUDE_DIR="${WATCHMAN_CLAUDE_DIR:-$WATCHMAN_ROOT/.claude}"

# --- Framework base ---------------------------------------------------------
# Commands the framework itself runs regardless of any skill: the journal gate
# (sqlite3) and manifest tooling (jq). Fixed, not manifest-derived — same spirit
# as the deny base. Never needs sudo.
#
# Also permit INVOCATION of each in-session command (the `/<name>` slash command
# deployed from commands/<name>/). Under dontAsk, the model autonomously calling
# the Skill tool — including how /loop re-invokes `/watchman loop` each interval —
# is permission-gated; without this it auto-denies and the unattended loop can
# stall. This grants invocation ONLY; what the command may actually DO is still
# bounded by the Bash/Read allow rules below (read-only observe + report), so it
# is belt-and-suspenders, never a widening of the fixer's scope. One rule per
# deployed command so it stays correct as commands are added.
# NB: the Skill(<name>) rule syntax mirrors the documented Agent(<name>) form;
# if a future Claude Code build names it differently, regenerate via preflight.
_pf_framework_allow() {
    printf '%s\n' \
        'Bash(sqlite3 *)' \
        'Bash(jq *)'
    local src="$WATCHMAN_ROOT/commands" d name
    [[ -d "$src" ]] || return 0
    while IFS= read -r d; do
        [[ -f "$d/SKILL.md" ]] || continue
        name="$(basename "$d")"
        printf 'Skill(%s)\n' "$name"
    done < <(find "$src" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
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
    local entry="$1" line
    # A resolver token (a distro.sh function) may emit MULTIPLE absolute paths,
    # one per line — e.g. webserver_log_paths discovers every log dir on the host.
    # Emit each valid line; the collation grants Read on every one.
    if [[ "$entry" != /* ]] && declare -F "$entry" >/dev/null 2>&1; then
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            [[ "$line" == journald:* ]] && continue   # not a file path
            [[ "$line" == /* ]] || continue           # ignore non-absolute/unknown
            printf '%s\n' "$line"
        done < <("$entry")
        return 0
    fi
    # Literal path entry.
    [[ "$entry" == journald:* ]] && return 0
    [[ "$entry" == /* ]] || return 0
    printf '%s\n' "$entry"
}

# --- Collation --------------------------------------------------------------
# Walk every manifest, resolve, and accumulate de-duplicated allow rules,
# additionalDirectories, and sudoers command paths.
preflight_collate() {
    local -a allow=() adddirs=() sudoers=()
    while IFS= read -r _pf_line; do allow+=("$_pf_line"); done < <(_pf_framework_allow)

    local m
    while IFS= read -r m; do
        [[ -r "$m" ]] || continue

        # reads → Read globs + additionalDirectories. A single read token may
        # resolve to several paths (e.g. webserver_log_paths), so iterate each.
        local r path dir
        while IFS= read -r r; do
            [[ -n "$r" ]] || continue
            while IFS= read -r path; do
                [[ -n "$path" ]] || continue
                # If the path is a file, grant its dir; if a dir, grant it directly.
                if [[ -d "$path" ]]; then dir="$path"; else dir="$(dirname "$path")"; fi
                allow+=("Read(${dir}/**)")
                adddirs+=("/${dir}")        # doubled leading slash (dir already starts with /)
            done < <(_pf_resolve_read "$r")
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

# --- Deploy in-session command skills ---------------------------------------
# The token-spending operator commands (audit, report, loop, fix, inventory) run
# IN a Claude Code session so token use is visible — never as headless `claude -p`.
# Their committed source lives in commands/<name>/SKILL.md; here we copy each into
# <claude>/skills/ so Claude Code discovers it as the `/<name>` slash command.
# .claude/ is gitignored, so these are local artifacts regenerated per machine —
# the same pattern as the allowlist. Refreshed on every preflight to stay in sync
# with the committed skills they orchestrate.
preflight_deploy_commands() {
    local src="$WATCHMAN_ROOT/commands" dst="$WATCHMAN_CLAUDE_DIR/skills"
    [[ -d "$src" ]] || return 0
    mkdir -p "$dst"
    local n=0 d
    while IFS= read -r d; do
        [[ -f "$d/SKILL.md" ]] || continue
        local name; name="$(basename "$d")"
        mkdir -p "$dst/$name"
        cp "$d/SKILL.md" "$dst/$name/SKILL.md"
        n=$((n+1))
    done < <(find "$src" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    echo "preflight: deployed $n in-session command skill(s) to $dst" >&2
}

# --- Public entry -----------------------------------------------------------
# Regenerate the Claude permission allowlist + in-session command skills from the
# committed source. Safe to re-run. No sudoers file: claude-watchman runs as root,
# which invokes read/observe commands directly (CLAUDE.md "How it runs").
preflight_run() {
    command -v jq >/dev/null 2>&1 || { echo "preflight: jq is required (install.sh adds it)." >&2; return 1; }
    preflight_collate
    preflight_write_base_settings  "$WATCHMAN_CLAUDE_DIR"
    preflight_write_local_settings "$WATCHMAN_CLAUDE_DIR"
    preflight_deploy_commands
    rm -f "$WATCHMAN_ROOT/.pf.allow" "$WATCHMAN_ROOT/.pf.dirs" "$WATCHMAN_ROOT/.pf.sudoers"
}

# Allow running directly: `bash lib/preflight.sh`
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then preflight_run; fi
