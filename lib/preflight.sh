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
#        ├─► .claude/settings.local.json   LOOP/audit allowlist (read-only)
#        ├─► .claude/settings.fix.json     FIX profile (default mode, + safe fix ops)
#        └─► .claude/settings.dev.json     maintainer profile (acceptEdits, repo write)
#
# claude-watchman runs as ROOT (CLAUDE.md "How it runs"), so there is no
# separate watchman user and no OS sudoers file — root invokes the read/observe
# commands directly. The safety boundary is therefore the Claude permission
# layer alone: the deny base blocks destructive command patterns even as root.
#
# THREE permission profiles, one shared deny base (_pf_deny_base, the backstop):
#
#   * LOOP/audit  — settings.json (dontAsk) + settings.local.json. Read-only
#     Observe/Analyze + report/email ONLY. The mutating fixer ops are deliberately
#     ABSENT, and under dontAsk anything not in `allow` auto-denies — so the
#     unattended loop physically cannot apply a remediation. Second seatbelt.
#   * FIX  — settings.fix.json, "default" mode. The read-only allowlist PLUS the
#     manifests' SAFE-tier fix ops. review-tier ops are intentionally left OUT so
#     "default" mode PROMPTS per finding — the confirmation the risk tiers require.
#     manual-tier is never granted. Selected by `watchman fix`'s launcher.
#   * DEV  — settings.dev.json, acceptEdits. Repo-write for maintainers, so editing
#     source no longer means hand-editing settings.json + restarting. `watchman dev`.
#
# The deny base is RETAINED in all three (rm/dd/systemctl stop/disable/sudoers,
# plus Edit/Write of shadow & sudoers) — an allow can never override a deny.
#
# settings.json (the base) is NEVER clobbered if present (operator may tune it);
# settings.local.json / settings.fix.json / settings.dev.json are regenerated each
# run from the manifests.

set -o pipefail
_PF_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCHMAN_ROOT="${WATCHMAN_ROOT:-$(cd "$_PF_LIB_DIR/.." && pwd)}"
# shellcheck source=lib/distro.sh
source "$_PF_LIB_DIR/distro.sh"
# shellcheck source=lib/profile.sh
source "$_PF_LIB_DIR/profile.sh"
# shellcheck source=lib/sectools.sh
# Sourced so the sectool_status resolver_op and the sectool_log_paths read token
# (the security-tooling registry) resolve to the right commands/paths for THIS host.
source "$_PF_LIB_DIR/sectools.sh"

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
        sectool_status)
            # The security-tooling registry: for each defensive tool PRESENT on this
            # host that needs a privileged observe command, grant exactly that command.
            # sectools.sh already emits the <args>\t<sudo>\t<sudoers-cmd> TSV contract.
            sectools_observe_commands ;;
        *) echo "preflight: unknown resolver_op '$op'" >&2 ;;
    esac
}

_pf_abspath() { command -v "$1" 2>/dev/null || printf '/usr/bin/%s' "$1"; }

# --- fix_op expansion (FIX profile only) ------------------------------------
# A manifest's fixes[] entry declares a LOGICAL mutating op + its risk_tier; this
# maps each to the concrete allow rule(s) for THIS family, mirroring the read-only
# _pf_expand_resolver_op. Output lines are TSV:  <allow-rule>\t<additional-dir-or->
# The allow-rule is a full permission entry (Bash(...) OR Edit/Write(...)), not just
# the Bash args, because a config edit is an Edit, not a shell command. Only SAFE-tier
# ops are ever fed here (see _pf_collate_fix) — review-tier ops are deliberately not
# granted so "default" mode prompts for them per finding.
_pf_expand_fix_op() {
    local op="$1"
    case "$op" in
        firewall_allow)
            case "$(watchman_firewall_backend)" in
                ufw)       printf 'Bash(sudo ufw allow *)\t-\n' ;;
                firewalld) printf 'Bash(sudo firewall-cmd --permanent --add-port=*)\t-\n'
                           printf 'Bash(sudo firewall-cmd --reload)\t-\n' ;;
                *)         : ;;   # nftables: operator-authored; resolver refuses to guess
            esac ;;
        firewall_deny)
            case "$(watchman_firewall_backend)" in
                ufw)       printf 'Bash(sudo ufw deny *)\t-\n' ;;
                firewalld) printf 'Bash(sudo firewall-cmd --permanent --remove-port=*)\t-\n'
                           printf 'Bash(sudo firewall-cmd --reload)\t-\n' ;;
                *)         : ;;
            esac ;;
        service_enable)  printf 'Bash(sudo systemctl enable --now *)\t-\n' ;;
        service_restart) printf 'Bash(sudo systemctl restart *)\t-\n' ;;
        config_edit)     # config files live under /etc; grant Edit (modify) + Write (create,
                         # e.g. a new /etc/logrotate.d entry). Crown-jewel files stay denied
                         # by the deny base (shadow / sudoers), which an allow cannot override.
                         printf 'Edit(/etc/**)\t/etc\n'
                         printf 'Write(/etc/**)\t/etc\n' ;;
        *) echo "preflight: unknown fix_op '$op'" >&2 ;;
    esac
}

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
    mapfile -t allow < <(_pf_framework_allow)

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

# --- FIX-profile collation --------------------------------------------------
# Walk every manifest's fixes[] and accumulate the allow rules + extra dirs that
# the FIX profile grants ON TOP OF the read-only allowlist. TIER-AWARE: only
# `safe`-tier ops are granted (they apply without a permission prompt); `review`
# ops are deliberately omitted so "default" mode prompts per finding, and `manual`
# is never granted. The dir convention mirrors preflight_collate's doubled leading
# slash ("/${dir}" where dir already starts with /), so additionalDirectories match.
_pf_collate_fix() {
    local -a allow=() dirs=()
    local m op tier rule dir
    while IFS= read -r m; do
        [[ -r "$m" ]] || continue
        while IFS=$'\t' read -r op tier; do
            [[ -n "$op" ]] || continue
            [[ "$tier" == "safe" ]] || continue   # tier-aware: safe ops only
            while IFS=$'\t' read -r rule dir; do
                [[ -n "$rule" ]] || continue
                allow+=("$rule")
                [[ -n "$dir" && "$dir" != "-" ]] && dirs+=("/${dir}")
            done < <(_pf_expand_fix_op "$op")
        done < <(jq -r '.fixes[]? | [.op, (.risk_tier // "manual")] | @tsv' "$m" 2>/dev/null)
    done < <(find "$WATCHMAN_ROOT/skills" -mindepth 3 -maxdepth 3 -name manifest.json 2>/dev/null | sort)

    printf '%s\n' "${allow[@]}" | awk 'NF' | sort -u > "$WATCHMAN_ROOT/.pf.fix.allow"
    printf '%s\n' "${dirs[@]}"  | awk 'NF' | sort -u > "$WATCHMAN_ROOT/.pf.fix.dirs"
}

# --- Deny base (the backstop, shared by ALL profiles) -----------------------
# One declaration of the destructive-action denylist, emitted one rule per line.
# Every generated profile (loop/fix/dev) embeds this verbatim so the backstop can
# never drift between them. An allow can never override a deny, so even the fix
# profile's Edit(/etc/**) grant cannot touch the crown-jewel files denied here.
_pf_deny_base() {
    printf '%s\n' \
        'Read(.env)' \
        'Read(./.env)' \
        'Bash(rm *)' \
        'Bash(rm -rf *)' \
        'Bash(sudo rm *)' \
        'Bash(dd *)' \
        'Bash(mkfs *)' \
        'Bash(mkfs.*)' \
        'Bash(shutdown *)' \
        'Bash(reboot *)' \
        'Bash(systemctl stop *)' \
        'Bash(systemctl disable *)' \
        'Bash(sudo systemctl stop *)' \
        'Bash(sudo systemctl disable *)' \
        'Bash(userdel *)' \
        'Bash(usermod *)' \
        'Bash(passwd *)' \
        'Bash(visudo *)' \
        'Bash(* /etc/sudoers*)' \
        'Edit(/etc/shadow)' \
        'Edit(/etc/gshadow)' \
        'Edit(/etc/sudoers)' \
        'Edit(/etc/sudoers.d/**)' \
        'Write(/etc/shadow)' \
        'Write(/etc/gshadow)' \
        'Write(/etc/sudoers)' \
        'Write(/etc/sudoers.d/**)'
}

# --- Base policy (fixed, not manifest-derived) ------------------------------
# The base IS the loop/audit profile. When ABSENT we write it fresh. When PRESENT
# we do NOT clobber operator tuning — but we DO re-assert the loop's two safety
# CONTRACTS, because each can silently drift and each quietly breaks the seatbelt:
#   1. defaultMode=dontAsk — anything unallowed auto-denies and fails loudly (no
#      silent hang, no prompt). A Shift-Tab mode-cycle can persist a weaker mode.
#   2. the destructive deny base — the backstop an allow can never override. A
#      stray edit can truncate it, removing the loop's protection against
#      rm/dd/mkfs/systemctl-stop/etc. even though it runs as root.
# defaultMode is repaired back to dontAsk; the deny base is UNIONED into whatever
# denies are present (operator-added denies preserved in order, the backstop's
# rules appended where missing). Both repairs are non-destructive — they only
# TIGHTEN the seatbelt, never loosen or delete — so the Prime Directive permits
# them as create-or-update. Maintainers who want acceptEdits use `watchman dev`
# (its own profile via --permission-mode), never the base; fix/dev pass
# --permission-mode explicitly, so re-asserting the base never affects them.
preflight_write_base_settings() {
    local claude_dir="$1" target="$1/settings.json"
    mkdir -p "$claude_dir"
    local deny; deny="$(_pf_deny_base)"
    if [[ -e "$target" ]]; then
        local cur; cur="$(jq -r '.permissions.defaultMode // "unset"' "$target" 2>/dev/null)" || cur="unset"
        # How many deny-base rules are MISSING from the present file (0 = intact).
        local missing; missing="$(jq -r --arg deny "$deny" \
            '(($deny | split("\n") | map(select(length>0))) - (.permissions.deny // [])) | length' \
            "$target" 2>/dev/null)" || missing=""
        if [[ "$cur" == dontAsk && "${missing:-x}" == 0 ]]; then
            echo "preflight: base settings.json present (defaultMode=dontAsk, deny base intact) — operator tuning kept." >&2
            return 0
        fi
        local tmp; tmp="$(mktemp "${target}.XXXXXX" 2>/dev/null)" || tmp="${target}.tmp"
        # Re-assert BOTH contracts in one pass: defaultMode=dontAsk, and deny =
        # existing denies (in their order) + any base rules not already present.
        if jq --arg deny "$deny" '
              ($deny | split("\n") | map(select(length>0)))      as $base
            | (.permissions.deny // [])                          as $existing
            | .permissions.defaultMode = "dontAsk"
            | .permissions.deny = ($existing + ($base - $existing))
            ' "$target" > "$tmp" 2>/dev/null && [[ -s "$tmp" ]]; then
            mv "$tmp" "$target"
            echo "preflight: repaired base settings.json (defaultMode=$cur->dontAsk, +${missing:-?} deny-base rule(s) re-asserted) — the loop requires both (use 'watchman dev' for an edit session)." >&2
        else
            rm -f "$tmp"
            echo "preflight: WARNING base settings.json could not be normalized (defaultMode=$cur, loop needs dontAsk + full deny base) and auto-repair failed — fix it by hand." >&2
        fi
        return 0
    fi
    jq -n --arg deny "$deny" '
      {permissions: {
         defaultMode: "dontAsk",
         deny: ($deny | split("\n") | map(select(length>0)))
      }}' > "$target"
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

# --- Emit settings.fix.json (the FIX profile) -------------------------------
# Regenerated every run (like settings.local.json). "default" mode: allow rules
# auto-run, deny rules block, EVERYTHING ELSE PROMPTS — and that prompt is the
# per-finding confirmation the review tier requires. allow = the read-only loop
# allowlist (.pf.allow) PLUS the SAFE-tier fix ops (.pf.fix.allow); review ops are
# absent on purpose. The shared deny base is retained as the backstop. Selected by
# `watchman fix`, which launches a fresh session bound to this file.
preflight_write_fix_settings() {
    local claude_dir="$1" target="$1/settings.fix.json"
    mkdir -p "$claude_dir"
    local allow dirs deny
    allow="$(cat "$WATCHMAN_ROOT/.pf.allow" "$WATCHMAN_ROOT/.pf.fix.allow" 2>/dev/null | awk 'NF' | sort -u)"
    dirs="$(cat "$WATCHMAN_ROOT/.pf.dirs"  "$WATCHMAN_ROOT/.pf.fix.dirs"  2>/dev/null | awk 'NF' | sort -u)"
    deny="$(_pf_deny_base)"
    jq -n --arg allow "$allow" --arg dirs "$dirs" --arg deny "$deny" '
      {permissions: {
         defaultMode: "default",
         deny:  ($deny  | split("\n") | map(select(length>0))),
         allow: ($allow | split("\n") | map(select(length>0))),
         additionalDirectories: ($dirs | split("\n") | map(select(length>0)))
      }}' > "$target"
    echo "preflight: wrote fix profile $target ($(jq '.permissions.allow|length' "$target") allow rules, default mode)" >&2
}

# --- Emit settings.dev.json (the maintainer profile) ------------------------
# acceptEdits: file edits inside the repo auto-apply (no settings.json hand-edit +
# restart dance), while Bash still prompts and the deny base still blocks the
# destructive patterns. Scoped to the product tree, not the host. `watchman dev`.
preflight_write_dev_settings() {
    local claude_dir="$1" target="$1/settings.dev.json"
    mkdir -p "$claude_dir"
    local deny root allow; deny="$(_pf_deny_base)"; root="$WATCHMAN_ROOT"
    allow="$(printf '%s\n' \
        "Read(${root}/**)" \
        "Edit(${root}/**)" \
        "Write(${root}/**)" \
        'Bash(git *)' \
        'Bash(jq *)' \
        'Bash(shellcheck *)' \
        'Bash(sqlite3 *)' \
        'Skill(watchman)')"
    jq -n --arg allow "$allow" --arg deny "$deny" --arg root "$root" '
      {permissions: {
         defaultMode: "acceptEdits",
         deny:  ($deny  | split("\n") | map(select(length>0))),
         allow: ($allow | split("\n") | map(select(length>0))),
         additionalDirectories: [$root]
      }}' > "$target"
    echo "preflight: wrote dev profile $target (acceptEdits, repo-write)" >&2
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
    _pf_collate_fix
    preflight_write_base_settings  "$WATCHMAN_CLAUDE_DIR"
    preflight_write_local_settings "$WATCHMAN_CLAUDE_DIR"
    preflight_write_fix_settings   "$WATCHMAN_CLAUDE_DIR"
    preflight_write_dev_settings   "$WATCHMAN_CLAUDE_DIR"
    preflight_deploy_commands
    rm -f "$WATCHMAN_ROOT/.pf.allow" "$WATCHMAN_ROOT/.pf.dirs" "$WATCHMAN_ROOT/.pf.sudoers" \
          "$WATCHMAN_ROOT/.pf.fix.allow" "$WATCHMAN_ROOT/.pf.fix.dirs"
}

# Allow running directly: `bash lib/preflight.sh`
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then preflight_run; fi
