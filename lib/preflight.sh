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
# run from the manifests. settings.local.json keeps the operator's own read-only
# approvals across regeneration, and any file that changes is backed up first to
# journal/pre-update-backup-*-preflight/ (see preflight_write_local_settings).

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
# Commands the framework itself runs regardless of any skill: the LIB-FUNCTION
# DISPATCHER (lib/wm), the journal gate (sqlite3), and manifest tooling (jq).
# Fixed, not manifest-derived — same spirit as the deny base. Never needs sudo.
#
# `Bash(bash lib/wm:*)` is the load-bearing rule. Every skill calls its claude-watchman
# functions through `bash lib/wm <fn> …`; lib/wm sources the libs INTERNALLY (under bash,
# invisible to the permission layer) and dispatches. This is required because Claude Code's
# dontAsk mode REFUSES any compound command that dot-sources a file (verified on 2.1.181) —
# so a skill could never `source lib/… && fn …` in the single Bash call it is forced to use.
# The colon-arg form `bash lib/wm:*` is what the permission matcher honors. The wrapper is
# read-only: a mutation must be requested as `WM_APPLY=1 bash lib/wm <fn>`, whose leading
# assignment makes a DIFFERENT prefix this rule does not match — so the loop cannot mutate.
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
        'Bash(bash lib/wm:*)' \
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
# maps each to the concrete allow rule(s). Output lines are TSV:  <allow-rule>\t<additional-dir-or->
# The allow-rule is a full permission entry (Bash(...) OR Edit/Write(...)), not just
# the Bash args, because a config edit is an Edit, not a shell command. Only SAFE-tier
# ops are ever fed here (see _pf_collate_fix) — review-tier ops are deliberately not
# granted so "default" mode prompts for them per finding.
#
# Mutating functions run through the dispatcher with the WM_APPLY env prefix:
# `Bash(WM_APPLY=1 bash lib/wm <fn>:*)`. This is FAMILY-BLIND — lib/wm sources distro.sh,
# whose firewall_allow/deny resolve ufw/firewalld/csf/apf and self-refuse nftables (and csf/apf
# port specs, which are csf.conf/conf.apf edits) at runtime, so
# the preflight no longer enumerates backends here. The WM_APPLY prefix is what lib/wm
# requires to run a mutator AND what the read-only loop rule (`Bash(bash lib/wm:*)`) cannot
# match — so granting it here scopes mutation to the FIX profile alone.
_pf_expand_fix_op() {
    local op="$1"
    case "$op" in
        firewall_allow)  printf 'Bash(WM_APPLY=1 bash lib/wm firewall_allow:*)\t-\n' ;;
        firewall_deny)   printf 'Bash(WM_APPLY=1 bash lib/wm firewall_deny:*)\t-\n' ;;
        service_enable)  printf 'Bash(WM_APPLY=1 bash lib/wm service_enable:*)\t-\n' ;;
        service_restart) printf 'Bash(WM_APPLY=1 bash lib/wm service_restart:*)\t-\n' ;;
        config_edit)     # Deliberately NO allow rule. A blanket Edit(//etc/**) would apply every
                         # /etc edit with no prompt, including review-tier files such as
                         # sshd_config, because a rule cannot tell which finding an edit serves.
                         # Default mode prompts for the edit instead. (The old Edit(/etc/**) form
                         # was project-relative, so it never granted anything: this keeps the
                         # behavior hosts already have.)
                         : ;;
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

# True when a path, once canonicalized, is the filesystem root or a whole system tree.
# realpath -m also handles paths that do not exist yet; where it is unavailable (older macOS)
# the path is compared as given, with trailing slashes removed.
_pf_is_system_tree() {
    local canon
    canon="$(realpath -m -- "$1" 2>/dev/null)" || canon=""
    if [[ -z "$canon" ]]; then
        canon="$1"
        while [[ "$canon" == */ && "$canon" != / ]]; do canon="${canon%/}"; done
    fi
    case "$canon" in
        /|/etc|/var|/var/lib|/var/log|/home|/root|/usr|/usr/local|/opt|/srv|/tmp|/boot|/proc|/sys|/dev|/run) return 0 ;;
    esac
    return 1
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
        local r path
        while IFS= read -r r; do
            [[ -n "$r" ]] || continue
            while IFS= read -r path; do
                [[ -n "$path" ]] || continue
                # Resolver output depends on the host (a web server config can log anywhere),
                # so a manifest check alone cannot catch this: refuse it here, on every host.
                if _pf_is_system_tree "$path"; then
                    echo "preflight: refusing read grant on system tree '$path' (from $r)" >&2
                    continue
                fi
                path="${path%/}"
                # Grant EXACTLY what the manifest declares, never its parent: granting the parent
                # of a file or a not-yet-existing path turned /etc/logrotate.conf into all of /etc
                # and /var/cpanel into all of /var, credentials included. A denylist cannot list
                # an unknown host's secrets, so the grant itself has to be narrow.
                #
                # Two different path grammars, tested against Claude Code 2.1.318: a permission
                # RULE needs // to mean absolute (a single / is relative to the settings source,
                # so Read(/etc/**) grants nothing), while additionalDirectories takes a PLAIN
                # path (//etc grants nothing). path already starts with /. A Read rule works
                # alone, so only a real directory is added to additionalDirectories.
                if [[ -d "$path" ]]; then
                    allow+=("Read(/${path}/**)")
                    adddirs+=("${path}")
                elif [[ -e "$path" ]]; then
                    allow+=("Read(/${path})")
                else
                    # Absent today, may be either kind once installed. Covers only this path.
                    allow+=("Read(/${path})" "Read(/${path}/**)")
                fi
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
# is never granted. Dirs are plain absolute paths, as in preflight_collate.
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
                [[ -n "$dir" && "$dir" != "-" ]] && dirs+=("${dir}")
            done < <(_pf_expand_fix_op "$op")
        done < <(jq -r '.fixes[]? | [.op, (.risk_tier // "manual")] | @tsv' "$m" 2>/dev/null)
    done < <(find "$WATCHMAN_ROOT/skills" -mindepth 3 -maxdepth 3 -name manifest.json 2>/dev/null | sort)

    printf '%s\n' "${allow[@]}" | awk 'NF' | sort -u > "$WATCHMAN_ROOT/.pf.fix.allow"
    printf '%s\n' "${dirs[@]}"  | awk 'NF' | sort -u > "$WATCHMAN_ROOT/.pf.fix.dirs"
}

# --- Deny base (the backstop, shared by ALL profiles) -----------------------
# One declaration of the destructive-action denylist, emitted one rule per line.
# Every generated profile (loop/fix/dev) embeds this verbatim so the backstop can
# never drift between them. An allow can never override a deny.
#
# Absolute paths MUST use the // form. A single leading slash is relative to the settings
# source, so Edit(/etc/shadow) only ever matched <project>/etc/shadow; a test on Claude Code
# 2.1.318 confirmed a single-slash deny does not block the real path. `update --check`
# fails if a single-slash absolute path comes back.
#
# The Read denies are a backstop beneath narrow grants, not the protection itself: what a
# session reads goes to the model provider and persists in its transcript, so credentials,
# private keys, shell history, customer sessions and past transcripts must stay out of it.
# //**/wp-config.php (WordPress database credentials, at any depth) was tested on Claude
# Code 2.1.322: with it, Read of a nested wp-config.php is refused; without it the same
# Read succeeds; a sibling file in the same tree stays readable.
_pf_deny_base() {
    printf '%s\n' \
        'Read(.env)' \
        'Read(./.env)' \
        'Read(//etc/shadow)' \
        'Read(//etc/gshadow)' \
        'Read(//etc/ssh/ssh_host_*_key)' \
        'Read(//root/.ssh/**)' \
        'Read(//home/*/.ssh/**)' \
        'Read(//root/.claude/.credentials.json)' \
        'Read(//home/*/.claude/.credentials.json)' \
        'Read(//root/.claude.json)' \
        'Read(//home/*/.claude.json)' \
        'Read(//root/.claude/projects/**)' \
        'Read(//home/*/.claude/projects/**)' \
        'Read(//root/.*_history)' \
        'Read(//home/*/.*_history)' \
        'Read(//root/.history)' \
        'Read(//home/*/.history)' \
        'Read(//root/.local/share/fish/**)' \
        'Read(//home/*/.local/share/fish/**)' \
        'Read(//etc/csf/**)' \
        'Read(//var/lib/php/session/**)' \
        'Read(//var/cpanel/php/sessions/**)' \
        'Read(//etc/letsencrypt/**)' \
        'Read(//etc/ssl/private/**)' \
        'Read(//etc/crowdsec/*credentials*)' \
        'Read(//var/lib/php/sessions/**)' \
        'Read(//**/wp-config.php)' \
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
        'Edit(//etc/shadow)' \
        'Edit(//etc/gshadow)' \
        'Edit(//etc/sudoers)' \
        'Edit(//etc/sudoers.d/**)' \
        'Write(//etc/shadow)' \
        'Write(//etc/gshadow)' \
        'Write(//etc/sudoers)' \
        'Write(//etc/sudoers.d/**)'
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
            _pf_replace_settings "$target" "$tmp" || return 0
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

# --- Never lose a settings file to regeneration ------------------------------
# Rewriting a settings file is an overwrite, which the Prime Directive treats as
# destructive. So before any regenerated profile replaces a file whose content
# differs, the old file is copied to journal/pre-update-backup-<stamp>-preflight/
# (gitignored; retention never prunes it). One directory per preflight run.
_PF_BACKUP_DIR=""
_pf_replace_settings() {   # <target> <new-file>: back up target if it changes, then move new into place
    local target="$1" new="$2"
    if [[ -f "$target" ]] && ! cmp -s "$target" "$new"; then
        if [[ -z "$_PF_BACKUP_DIR" ]]; then
            _PF_BACKUP_DIR="$WATCHMAN_ROOT/journal/pre-update-backup-$(date +%Y%m%d-%H%M%S)-$$-preflight"
        fi
        mkdir -p "$_PF_BACKUP_DIR/.claude" && cp -p "$target" "$_PF_BACKUP_DIR/.claude/" || {
            rm -f "$new"
            echo "preflight: could not back up $target — left it unchanged." >&2
            return 1
        }
    fi
    mv -f "$new" "$target"
}

# Which operator rules may be carried into the read-only loop allowlist? An ALLOWLIST,
# not a denylist: a rule is carried only when it is recognisably read-only, and
# everything else (bare tool names, MCP tools, WebFetch, Edit/Write, unknown commands,
# wildcards on anything that reads file contents) is held, listed, and kept in the
# backup. A rule that reads arbitrary files as a wildcard (Bash(cat *)) is held because
# it would read past the deny base, which only guards the Read tool.
#
#   _PF_RO_ANYARGS  read-only whatever the arguments, and never print file contents.
#   _PF_RO_PREFIX   read-only subcommands of tools that also have writing ones.
#   _PF_RO_EXACT    read-only only as the exact command the operator approved (no '*').
# Interpreters (bash, php, python, awk), and tools that can write a file or set state
# from an ordinary-looking argument (sort, uniq, date, hostname), are on no list, so
# they are always held.
_PF_RO_ANYARGS='ls|stat|df|du|free|uptime|id|whoami|uname|lsof|last|lastb|lastlog|who|w|dpkg-query|lsattr|lsblk|findmnt|echo|printf|true|which|readlink|realpath|basename|dirname|nproc|lscpu|lsmod'
_PF_RO_PREFIX='apt list|apt-get (-s|--simulate|--dry-run)|apt-cache (show|policy|search|depends|rdepends)|dpkg (-l|-s|-L|--list|--status)|systemctl (status|is-active|is-enabled|is-failed|show|list-units|list-unit-files|list-timers|cat)|(apachectl|apache2ctl) (configtest|-t|-S|-M|-v|-V)|nginx (-t|-T|-v|-V)|sysctl -a|swapon --show|command -v'
_PF_RO_EXACT='cat|head|tail|wc|grep|egrep|fgrep|zgrep|zcat|cut|tr|jq|diff|cmp|file|md5sum|sha1sum|sha256sum|ss|ps|getent|set|shellcheck|journalctl|sysctl|test|git( -C [^ ]+)? (status|log|diff|show|rev-parse|ls-files|describe)'
_pf_rule_carryable() {
    local r="$1" cmd
    case "$r" in
        Read\(*\)) r="${r#Read(}"; _pf_path_narrow "${r%)}"; return ;;
        Bash\(*\)) ;;
        *) return 1 ;;
    esac
    cmd="${r#Bash(}"; cmd="${cmd%)}"; cmd="${cmd#sudo }"
    [[ -n "$cmd" && "$cmd" != \** ]] || return 1
    # Substitution, redirection, pipes, chaining and newlines make a rule do more than it shows.
    [[ "$cmd" == *'`'* || "$cmd" == *'$('* || "$cmd" == *'$\('* || "$cmd" == *'<('* || "$cmd" == *'>'* \
       || "$cmd" == *'|'* || "$cmd" == *';'* || "$cmd" == *'&'* || "$cmd" == *$'\n'* ]] && return 1
    _pf_rule_mutates "Bash($cmd)" && return 1
    [[ "$cmd" =~ ^(${_PF_RO_ANYARGS})(\ |:|$) ]] && return 0
    [[ "$cmd" =~ ^(${_PF_RO_PREFIX})(\ |:|$) ]] && return 0
    [[ "$cmd" != *'*'* && "$cmd" =~ ^(${_PF_RO_EXACT})(\ |$) ]] && return 0
    return 1
}

# Can this command change the system? A second check under _pf_rule_carryable, so
# an exact command built from a read-only verb is still refused when it writes.
_pf_rule_mutates() {
    local rule="$1" cmd
    case "$rule" in
        Edit\(*|Write\(*|NotebookEdit*) return 0 ;;
        Bash\(*) ;;
        *) return 1 ;;
    esac
    cmd="${rule#Bash(}"; cmd="${cmd%)}"
    cmd="${cmd#sudo }"
    [[ "$cmd" =~ ^journalctl\ .*--(vacuum|rotate|flush|sync|relinquish|setup-keys) ]] && return 0
    [[ "$cmd" =~ ^ss\ .*(-K|--kill) ]] && return 0
    # git can write a file or run a program from a read subcommand's flags.
    [[ "$cmd" =~ ^git\ .*(--output|--no-index|--ext-diff|--textconv|--exec|--upload-pack|--receive-pack|\ -c\ |--config) ]] && return 0
    # Secrets rather than changes, held the same way: the shadow databases, and process environments.
    [[ "$cmd" =~ ^getent\ +(shadow|gshadow) ]] && return 0
    [[ "$cmd" =~ ^ps(\ |$) && ( " ${cmd#ps} " =~ \ [a-zA-Z]*e[a-zA-Z]*\  || "$cmd" == *environ* ) ]] && return 0
    [[ "$cmd" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] && return 0      # env-prefixed (WM_APPLY=1 …)
    [[ "$cmd" =~ ^(rm|rmdir|mv|cp|ln|chmod|chown|chgrp|chattr|tee|truncate|install|dd|mkfs[^\ ]*|mkdir|touch|kill|pkill|killall|reboot|shutdown|halt|poweroff|useradd|usermod|userdel|groupadd|groupdel|passwd|chpasswd|visudo|crontab|mount|umount|ufw|firewall-cmd|nft|iptables|ip6tables|pacman|dnf|yum|zypper|snap|flatpak|pip3?|npm|a2en[a-z]*|a2dis[a-z]*|phpenmod|phpdismod|service|curl|wget|scp|rsync|ssh|etckeeper)([\ ]|$) ]] && return 0
    [[ "$cmd" =~ ^(apt|apt-get|aptitude)\ +(install|remove|purge|upgrade|full-upgrade|dist-upgrade|autoremove|update|reinstall) ]] && return 0
    [[ "$cmd" =~ ^(dpkg|rpm)\ +-[a-zA-Z]*[iUePr] ]] && return 0
    [[ "$cmd" =~ ^systemctl\ +(start|stop|restart|reload|try-restart|reload-or-restart|enable|disable|mask|unmask|set-property|daemon-reload|daemon-reexec|kill|edit|isolate|set-default|link|revert|reset-failed) ]] && return 0
    [[ "$cmd" =~ ^(apachectl|apache2ctl|httpd)\ +(-k\ +)?(graceful|restart|start|stop|graceful-stop) ]] && return 0
    [[ "$cmd" =~ ^nginx\ +-s ]] && return 0
    [[ "$cmd" =~ ^sysctl\ +(-w|-p|--write|--load) ]] && return 0
    [[ "$cmd" =~ ^sed\ +(-[a-zA-Z]*i|--in-place) ]] && return 0
    [[ "$cmd" =~ ^git\ +(-C\ +[^\ ]+\ +)?(commit|push|pull|fetch|reset|checkout|switch|restore|merge|rebase|clean|stash|add|rm|mv|tag|branch|init|clone|apply|am|cherry-pick|revert) ]] && return 0
    # An interpreter given a script (not just a flag such as -n or --version) runs arbitrary code.
    [[ "$cmd" =~ ^(bash|sh|zsh|dash|php|python[0-9.]*|perl|ruby|node)\ +[^-] ]] && return 0
    return 1
}

# Is this path (a Read rule's path, or an additionalDirectories entry) narrow enough to
# carry? Not a whole system tree (the trees `update --check` refuses in a manifest: what a
# session reads goes to the model provider), not home-relative, no '..', and no wildcard
# except a trailing /* or /** on an otherwise specific path. Read(//home/*/**) is held.
_PF_BROAD_TREES='(etc|var|var/lib|var/log|var/run|home|root|usr|usr/local|opt|srv|tmp|boot|proc|sys|dev|run)?'
_pf_path_narrow() {
    local p="$1" stem
    [[ -n "$p" && "$p" != \~* && "$p" != *..* ]] || return 1
    # Unnormalised paths (//etc//**, //etc/./**) would slip past the tree match below.
    local body="${p#//}"; body="${body#/}"
    [[ "$body" == *//* || "$body" == *'/./'* || "$body" == ./* || "$body" == */. || "$body" == . ]] && return 1
    stem="${p%/\*\*}"; stem="${stem%/\*}"
    [[ "$stem" == *'*'* ]] && return 1
    [[ "$stem" =~ ^/?/${_PF_BROAD_TREES}/*$ ]] && return 1
    return 0
}

# --- Emit settings.local.json ----------------------------------------------
# Claude Code writes the operator's "always allow" approvals into this same file, so
# regenerating it wholesale silently deleted them on every update. The generated
# rules are therefore recorded in .claude/.watchman-generated.json, and on the next
# run anything in the file that is NOT in that record is the operator's and is kept.
#
# An install from before the record existed has no record to compare against. Its
# generator output is recognised by two signatures that Claude Code itself never
# writes: path rules with a single leading slash (Read(/etc/**)) and doubled-slash
# additionalDirectories (//etc). Rules the current generator produces are generated
# by definition. Everything else is treated as the operator's.
#
# Only operator rules _pf_rule_carryable recognises as read-only are carried into this
# profile: it is the read-only loop allowlist, and dontAsk would run them unattended.
# Everything else, and every key other than the rule lists, stays in the backup and is
# listed, so the operator can re-grant any of it deliberately.
preflight_write_local_settings() {
    local claude_dir="$1" target="$1/settings.local.json"
    local record="$1/.watchman-generated.json"
    mkdir -p "$claude_dir"
    local allow dirs
    allow="$(cat "$WATCHMAN_ROOT/.pf.allow" 2>/dev/null)"
    dirs="$(cat "$WATCHMAN_ROOT/.pf.dirs" 2>/dev/null)"

    local -a kept=() held=() kept_dirs=()
    if [[ -f "$target" ]] && jq -e . "$target" >/dev/null 2>&1; then
        local prev_allow="" prev_dirs="" legacy=no r
        if [[ -f "$record" ]] && jq -e . "$record" >/dev/null 2>&1; then
            prev_allow="$(jq -r '.allow[]?' "$record")"
            prev_dirs="$(jq -r '.additionalDirectories[]?' "$record")"
        else
            legacy=yes
        fi
        while IFS= read -r r; do
            [[ -n "$r" ]] || continue
            grep -qxF -- "$r" <<< "$allow" && continue
            grep -qxF -- "$r" <<< "$prev_allow" && continue
            [[ "$legacy" == yes && "$r" =~ ^(Read|Edit|Write)\(/[^/] ]] && continue
            if _pf_rule_carryable "$r"; then kept+=("$r"); else held+=("$r"); fi
        done < <(jq -r '.permissions.allow[]? | strings' "$target")
        while IFS= read -r r; do
            [[ -n "$r" ]] || continue
            grep -qxF -- "$r" <<< "$dirs" && continue
            grep -qxF -- "$r" <<< "$prev_dirs" && continue
            [[ "$legacy" == yes && "$r" == //* ]] && continue
            if [[ "$r" == /* ]] && _pf_path_narrow "$r"; then kept_dirs+=("$r"); else held+=("additionalDirectories: $r"); fi
        done < <(jq -r '.permissions.additionalDirectories[]? | strings' "$target")
        # Only the rule lists are carried. Any other key (defaultMode, hooks, env, MCP
        # server approvals …) would outrank or widen the loop's base settings.json, so it
        # is held. deny and ask are carried below because they can only tighten.
        while IFS= read -r r; do
            [[ -n "$r" ]] && held+=("setting: $r")
        done < <(jq -r '(keys_unsorted[] | select(. != "permissions")),
                        ((.permissions // {}) | keys_unsorted[]
                           | select(IN("allow","additionalDirectories","deny","ask") | not)
                           | "permissions.\(.)")' "$target" 2>/dev/null)
    fi

    local new; new="$(mktemp "${target}.XXXXXX")" || return 1
    local extra_allow extra_dirs
    extra_allow="$(printf '%s\n' "${kept[@]}")"
    extra_dirs="$(printf '%s\n' "${kept_dirs[@]}")"
    jq -n --arg allow "$allow" --arg dirs "$dirs" --arg xa "$extra_allow" --arg xd "$extra_dirs" \
          --slurpfile old <( [[ -f "$target" ]] && jq -e . "$target" 2>/dev/null || echo '{}' ) '
      def lines: split("\n") | map(select(length>0));
      def ordered_unique: reduce .[] as $x ([]; if any(.[]; . == $x) then . else . + [$x] end);
      def strlist: if type == "array" then map(strings) else [] end;
      (($old[0] // {}).permissions // {}) as $p
      | {permissions: (
            {allow: (($allow | lines) + ($xa | lines) | ordered_unique),
             additionalDirectories: (($dirs | lines) + ($xd | lines) | ordered_unique)}
          + (if ($p.deny | strlist | length) > 0 then {deny: ($p.deny | strlist)} else {} end)
          + (if ($p.ask  | strlist | length) > 0 then {ask:  ($p.ask  | strlist)} else {} end))}
      ' > "$new" || { rm -f "$new"; echo "preflight: could not build $target" >&2; return 1; }
    _pf_replace_settings "$target" "$new" || return 1
    jq -n --arg allow "$allow" --arg dirs "$dirs" '
      def lines: split("\n") | map(select(length>0));
      {allow: ($allow | lines), additionalDirectories: ($dirs | lines)}' > "$record"

    echo "preflight: wrote agent allowlist $target ($(jq '.permissions.allow|length' "$target") allow rules)" >&2
    if (( ${#kept[@]} + ${#kept_dirs[@]} )); then
        echo "preflight: kept $(( ${#kept[@]} + ${#kept_dirs[@]} )) operator-approved rule(s)/dir(s) already in that file." >&2
    fi
    if (( ${#held[@]} )); then
        echo "preflight: NOTICE — ${#held[@]} operator-approved rule(s)/setting(s) are not recognisably read-only, so they" >&2
        echo "           were NOT carried into the read-only loop allowlist (dontAsk would run them unattended):" >&2
        printf '             %s\n' "${held[@]}" >&2
        echo "           The previous file, with these rules, is saved in $_PF_BACKUP_DIR/.claude/" >&2
        echo "           In the loop they now auto-deny; for remediation work use 'watchman fix', which prompts for each." >&2
    fi
    [[ -n "$_PF_BACKUP_DIR" ]] && echo "preflight: previous settings saved to $_PF_BACKUP_DIR/.claude/" >&2
    return 0
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
    # The FIX profile also grants the web-research tools so fix-redflag can fill a
    # knowledge gap (verify a remediation against vendor/distro docs / NVD) with no
    # prompt friction. Read-only and never bypasses a tier — proposing is not applying.
    # Deliberately NOT in the loop's read-only allowlist (.pf.allow): the unattended
    # loop has no operator and no remediation to research.
    allow="$( { cat "$WATCHMAN_ROOT/.pf.allow" "$WATCHMAN_ROOT/.pf.fix.allow" 2>/dev/null; printf 'WebSearch\nWebFetch\n'; } | awk 'NF' | sort -u)"
    dirs="$(cat "$WATCHMAN_ROOT/.pf.dirs"  "$WATCHMAN_ROOT/.pf.fix.dirs"  2>/dev/null | awk 'NF' | sort -u)"
    deny="$(_pf_deny_base)"
    local new; new="$(mktemp "${target}.XXXXXX")" || return 1
    jq -n --arg allow "$allow" --arg dirs "$dirs" --arg deny "$deny" '
      {permissions: {
         defaultMode: "default",
         deny:  ($deny  | split("\n") | map(select(length>0))),
         allow: ($allow | split("\n") | map(select(length>0))),
         additionalDirectories: ($dirs | split("\n") | map(select(length>0)))
      }}' > "$new" || { rm -f "$new"; return 1; }
    _pf_replace_settings "$target" "$new" || return 1
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
        "Read(/${root}/**)" \
        "Edit(/${root}/**)" \
        "Write(/${root}/**)" \
        'Bash(bash lib/wm:*)' \
        'Bash(git *)' \
        'Bash(jq *)' \
        'Bash(shellcheck *)' \
        'Bash(sqlite3 *)' \
        'Skill(watchman)')"
    local new; new="$(mktemp "${target}.XXXXXX")" || return 1
    jq -n --arg allow "$allow" --arg deny "$deny" --arg root "$root" '
      {permissions: {
         defaultMode: "acceptEdits",
         deny:  ($deny  | split("\n") | map(select(length>0))),
         allow: ($allow | split("\n") | map(select(length>0))),
         additionalDirectories: [$root]
      }}' > "$new" || { rm -f "$new"; return 1; }
    _pf_replace_settings "$target" "$new" || return 1
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
