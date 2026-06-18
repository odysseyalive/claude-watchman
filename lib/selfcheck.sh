#!/usr/bin/env bash
# lib/selfcheck.sh — prove the plumbing works on THIS host, with NO Claude in the
# loop. This isolates "does the tool work on this box" (resolvers, journal, deps,
# permissions, mail, auth, real observe commands) from "does headless Claude
# execute the skills correctly" — which only `/watchman audit` (live) can prove.
#
# > PRIME DIRECTIVE. selfcheck is READ-ONLY: it observes and reports, and writes
# > nothing except a throwaway scratch DB under a temp dir (removed before return).
# > It never installs, never edits config, never touches the real journal's data.
#
# Exit code: 0 = healthy (warnings allowed); 1 = a CRITICAL plumbing fault
# (missing sqlite3/jq, broken journal code, syntax-broken lib) that would stop the
# tool from functioning at all.

_SC_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCHMAN_ROOT="${WATCHMAN_ROOT:-$(cd "$_SC_LIB_DIR/.." && pwd)}"

_SC_FAIL=0; _SC_WARN=0
_ok()   { printf '  \033[1;32m[ ok ]\033[0m %s\n' "$*"; }
_warn() { printf '  \033[1;33m[warn]\033[0m %s\n' "$*"; _SC_WARN=$((_SC_WARN+1)); }
_fail() { printf '  \033[1;31m[FAIL]\033[0m %s\n' "$*"; _SC_FAIL=$((_SC_FAIL+1)); }
_na()   { printf '  \033[2m[ -- ]\033[0m %s\n' "$*"; }
_hdr()  { printf '\n\033[1m%s\033[0m\n' "$*"; }

selfcheck_run() {
    echo "claude-watchman selfcheck — direct plumbing test (no Claude)"
    echo "root: $WATCHMAN_ROOT"

    # --- lib integrity (syntax) --------------------------------------------
    _hdr "1. Library integrity (bash -n)"
    local f
    for f in journal distro profile smtp preflight selfcheck; do
        if [[ -f "$WATCHMAN_ROOT/lib/$f.sh" ]]; then
            if bash -n "$WATCHMAN_ROOT/lib/$f.sh" 2>/dev/null; then _ok "lib/$f.sh"; else _fail "lib/$f.sh has a syntax error"; fi
        else _fail "lib/$f.sh missing"; fi
    done
    [[ -f "$WATCHMAN_ROOT/journal/schema.sql" ]] && _ok "journal/schema.sql present" || _fail "journal/schema.sql missing"

    # Source resolvers now that they parse.
    # shellcheck source=lib/distro.sh
    source "$WATCHMAN_ROOT/lib/distro.sh"
    # shellcheck source=lib/profile.sh
    source "$WATCHMAN_ROOT/lib/profile.sh"
    # shellcheck source=lib/smtp.sh
    source "$WATCHMAN_ROOT/lib/smtp.sh"

    # --- environment + resolvers -------------------------------------------
    _hdr "2. Detection & resolvers"
    local fam prof
    fam="$(watchman_family)"; prof="$(watchman_profile)"
    if [[ "$fam" == unknown ]]; then _fail "distro family unknown (need debian/rhel/arch)"; else _ok "family=$fam"; fi
    _ok "profile=$prof"
    _ok "firewall backend  = $(watchman_firewall_backend)"
    _ok "MAC layer/state   = $(mac_layer)/$(mac_state)"
    _ok "auto-update mech   = $(autoupdate_mechanism)"
    _ok "integrity verifier = $(integrity_verifier)"
    _ok "auth log path      = $(log_path_auth)"
    local _ws; _ws="$(webserver_detect | awk -F'\t' '{printf "%s ", $1}')"
    _ok "web servers found  = ${_ws:-none detected}"
    _ok "web log dirs       = $(webserver_log_paths | paste -sd' ' -)"

    # --- dependencies (degradation map) ------------------------------------
    _hdr "3. Dependencies"
    local b miss=() cscli_aur=no
    for b in sqlite3 jq; do
        if command -v "$b" >/dev/null 2>&1; then _ok "$b present (required)"
        else _fail "$b MISSING — required"; miss+=("$(pkg_for_cmd "$b")"); fi
    done
    for b in journalctl ss df free; do
        command -v "$b" >/dev/null 2>&1 && _ok "$b present" || _warn "$b missing — some observe checks degrade"
    done
    command -v lynis >/dev/null 2>&1 && _ok "lynis present (audit-system)" \
        || { _warn "lynis missing — audit-system degrades until installed"; miss+=(lynis); }
    command -v msmtp >/dev/null 2>&1 && _ok "msmtp present (send-report)" \
        || { _warn "msmtp missing — mail dispatch disabled"; miss+=(msmtp); }
    if command -v cscli >/dev/null 2>&1; then _ok "cscli present (crowdsec)"
    elif [[ "$(watchman_family)" == arch ]]; then _warn "cscli missing — inspect-logs falls back to log scan (crowdsec is AUR-only on Arch)"; cscli_aur=yes
    else _warn "cscli missing — inspect-logs falls back to log scan"; miss+=(crowdsec); fi

    # Direct the operator to install what's missing (selfcheck never installs — it tells you).
    if (( ${#miss[@]} )) || [[ "$cscli_aur" == yes ]]; then
        local ic uniq; ic="$(pkg_install_cmd)"
        printf '\n  \033[1;33m[ →  ]\033[0m install the missing packages:\n'
        if (( ${#miss[@]} )); then
            uniq="$(printf '%s\n' "${miss[@]}" | awk 'NF && !s[$0]++' | paste -sd' ' -)"
            if [[ -n "$ic" ]]; then printf '        %s %s\n' "$ic" "$uniq"
            else printf '        (use your package manager) %s\n' "$uniq"; fi
        fi
        [[ "$cscli_aur" == yes ]] && printf '        crowdsec: AUR-only on Arch — install with your AUR helper (e.g. yay -S crowdsec)\n'
    fi

    # --- journal: real DB status + scratch roundtrip -----------------------
    _hdr "4. Journal"
    if [[ -f "$WATCHMAN_ROOT/journal/findings.db" ]]; then
        local n; n="$(sqlite3 "$WATCHMAN_ROOT/journal/findings.db" "SELECT COUNT(*) FROM findings;" 2>/dev/null)"
        [[ -n "$n" ]] && _ok "real findings.db opens ($n findings)" || _warn "findings.db present but unreadable — inspect it"
    else
        _warn "findings.db not yet initialized (created by install.sh / first audit)"
    fi
    # Prove journal.sh works end-to-end without touching the real DB.
    if command -v sqlite3 >/dev/null 2>&1; then
        local tmp rc=0; tmp="$(mktemp -d)"
        (
            export JOURNAL_DIR="$tmp" JOURNAL_DB="$tmp/findings.db" JOURNAL_SCHEMA="$WATCHMAN_ROOT/journal/schema.sql"
            source "$WATCHMAN_ROOT/lib/journal.sh"
            journal_init || exit 11
            fp="$(journal_upsert "$fam" "$prof" config info safe selfcheck_probe "" "selfcheck probe" "n/a" "n/a")" || exit 12
            journal_set_status "$fp" fixed "selfcheck" || exit 13
            # re-observe → must regress
            journal_upsert "$fam" "$prof" config info safe selfcheck_probe "" "selfcheck probe" "n/a" "n/a" >/dev/null || exit 14
            [[ "$(sqlite3 "$tmp/findings.db" "SELECT status FROM findings WHERE fingerprint='$fp';")" == regressed ]] || exit 15
            [[ "$(sqlite3 "$tmp/findings.db" "SELECT COUNT(*) FROM findings;")" == 1 ]] || exit 16
        ) || rc=$?
        rm -rf "$tmp"
        (( rc == 0 )) && _ok "journal.sh roundtrip OK (init→upsert→regress→dedup, scratch DB)" \
                       || _fail "journal.sh roundtrip FAILED (code $rc) — the journal engine is broken on this host"
    else
        _fail "cannot test journal roundtrip — sqlite3 missing"
    fi

    # --- permissions artifacts --------------------------------------------
    _hdr "5. Permission artifacts"
    local cdir="${WATCHMAN_CLAUDE_DIR:-$WATCHMAN_ROOT/.claude}"
    if [[ -f "$cdir/settings.json" ]]; then
        local mode; mode="$(jq -r '.permissions.defaultMode // "unset"' "$cdir/settings.json" 2>/dev/null)"
        [[ "$mode" == dontAsk ]] && _ok "settings.json defaultMode=dontAsk" || _warn "settings.json defaultMode=$mode — the loop needs dontAsk; run 'watchman preflight' to repair it (use 'watchman dev' for edit sessions)"
    else _warn "settings.json absent — run install.sh / watchman preflight"; fi
    if [[ -f "$cdir/settings.local.json" ]]; then
        local na; na="$(jq -r '.permissions.allow | length' "$cdir/settings.local.json" 2>/dev/null)"
        [[ -n "$na" && "$na" -gt 0 ]] && _ok "settings.local.json has $na allow rules" || _warn "settings.local.json has no allow rules — run watchman preflight"
    else _warn "settings.local.json absent — run install.sh / watchman preflight"; fi
    if [[ $EUID -eq 0 ]]; then _ok "running as root — reads logs/journal directly (no sudoers needed)"
    else _warn "not running as root — claude-watchman is designed to run as root so it can read all logs"; fi

    # --- mail + auth -------------------------------------------------------
    _hdr "6. Mail & Claude Code"
    SMTP_ENV_FILE="${SMTP_ENV_FILE:-$WATCHMAN_ROOT/.env}"
    if smtp_is_configured; then _ok "SMTP configured (reports will send)"; else _warn "SMTP unconfigured — send-report degrades (logs & skips)"; fi
    if command -v claude >/dev/null 2>&1; then
        _ok "claude CLI on PATH — audit/loop/fix run on this user's Claude Code login ('claude' + /login if needed)"
    else
        _warn "claude CLI not on PATH — audit/loop/fix cannot run (selfcheck still works)"
    fi

    # --- live read-only observe smoke -------------------------------------
    _hdr "7. Observe smoke (real read-only commands)"
    if command -v df >/dev/null 2>&1; then _ok "df: $(df -P / 2>/dev/null | awk 'NR==2{print $5" used on /"}')"; else _warn "df missing"; fi
    if command -v free >/dev/null 2>&1; then _ok "free: $(free -m 2>/dev/null | awk '/^Mem:/{print $7" MiB available"}')"; else _warn "free missing"; fi
    if command -v journalctl >/dev/null 2>&1; then
        if journalctl -n1 --no-pager >/dev/null 2>&1; then _ok "journalctl readable by $(id -un)"
        else _warn "journalctl not readable as $(id -un) — run as root (the intended model)"; fi
    fi

    # --- verdict -----------------------------------------------------------
    _hdr "Verdict"
    echo "  failures: $_SC_FAIL   warnings: $_SC_WARN"
    echo
    echo "  NOTE: selfcheck does NOT exercise the live 'claude -p' → SKILL.md path or"
    echo "        the dontAsk allowlist matching of compound commands. Run a supervised"
    echo "        '/watchman audit' once and read the output to validate that path."
    if (( _SC_FAIL > 0 )); then
        printf '\n  \033[1;31mFAIL\033[0m — critical plumbing fault; fix the [FAIL] items before deploying.\n'
        return 1
    elif (( _SC_WARN > 0 )); then
        printf '\n  \033[1;33mPASS with warnings\033[0m — plumbing works; review [warn] items for full coverage.\n'
        return 0
    fi
    printf '\n  \033[1;32mPASS\033[0m — plumbing healthy on this host.\n'
    return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then selfcheck_run; fi
