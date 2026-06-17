#!/usr/bin/env bash
# lib/shellhist.sh — forensic-trail tamper detection (shell history + login records).
#
# Detects whether the evidence has been WIPED — a classic post-compromise move:
# clearing ~/.bash_history, redirecting it to /dev/null, disabling history in a
# shell rc, or truncating /var/log/wtmp / btmp / lastlog. It enumerates every
# login user (and root) and the system login records.
#
# METADATA ONLY — it never reads the CONTENTS of anyone's shell history. Whether
# the trail was tampered is answered from size / mtime / symlink target / mode /
# immutable bit / shell-rc settings / "logged in but no history" — which is both
# more reliable than grepping for "bad commands" and privacy-respecting (it does
# not expose what users typed). Most effective when run as root (it can stat every
# home); non-readable homes are skipped, not guessed.
#
# > PRIME DIRECTIVE. shellhist is READ-ONLY: it stats files and reports. It writes
# > nothing, changes no permissions, removes no immutable bit, restores no history.
# > Acting on a finding (re-enabling history, investigating) is the operator's job;
# > a wiped trail is detect-and-explain, never auto-"fixed".
#
# Honest limit: a root-level attacker who knows claude-watchman is present can also
# tamper with its journal. The durable value is the loop's regression EMAIL, which
# leaves the host before suppression — and pointing the operator at append-only
# logging (auditd / remote syslog) as the real fix.

# "<user>\t<home>\t<shell>" for every account with a real login shell whose home
# exists — plus root.
shellhist_login_users() {
    getent passwd 2>/dev/null | awk -F: '
        $7 ~ /\/(bash|zsh|sh|ksh|fish|tcsh|csh)$/ && $7 !~ /nologin|false/ { print $1 "\t" $6 "\t" $7 }'
}

# Emit one finding-candidate TSV record the skill journals through lib/journal.sh:
#   category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation
_sh_emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@"; }

# Does this user have any real login record? (robust — no date parsing.)
# Excludes the "wtmp begins <date>" footer line, which is not a login.
_sh_has_logins() { last -n1 "$1" 2>/dev/null | awk 'NF>3 && $0 !~ /wtmp begins/ {f=1} END{exit !f}'; }

# Scan everything and emit finding-candidate records (none = clean).
shellhist_scan() {
    local lf sz user home shell hf tgt mode owner rc

    # --- system login record: wiped/truncated = log wiping ---------------------
    # Only wtmp — it always accumulates boot + login records, so 0 bytes is
    # abnormal. lastlog is sparse (0 is common on minimal systems) and btmp is
    # empty when there are no failed logins (a good thing); neither is a tamper
    # signal on its own.
    lf=/var/log/wtmp
    if [[ -e "$lf" ]]; then
        sz="$(stat -c%s "$lf" 2>/dev/null || echo 0)"
        if [[ "$sz" -eq 0 ]]; then
            _sh_emit security high manual login_record_wiped "$lf" \
                "Login record $lf is empty" \
                "$lf is 0 bytes — login history appears wiped (a common post-compromise step). On a minimal/container host with no login accounting this can be benign; confirm." \
                "Investigate for compromise. Use append-only logging (auditd / remote syslog) so records can't be erased."
        fi
    else
        _sh_emit security high manual login_record_missing "$lf" \
            "Login record $lf is missing" \
            "$lf does not exist; login accounting may be off or the trail deleted." \
            "Investigate. Enable login accounting and append-only logging."
    fi

    # --- per-user shell history -----------------------------------------------
    while IFS=$'\t' read -r user home shell; do
        [[ -n "$user" && -d "$home" ]] || continue
        # If we can't actually traverse the home (e.g. running non-root against a
        # mode-700 home), we cannot assess it — SKIP rather than false-positive.
        # As root (the deployment), every home is accessible.
        [[ -r "$home" && -x "$home" ]] || continue

        local found_hist=no
        for hf in "$home/.bash_history" "$home/.zsh_history" "$home/.sh_history" \
                  "$home/.local/share/fish/fish_history" "$home/.history"; do
            if [[ -L "$hf" ]]; then
                tgt="$(readlink "$hf" 2>/dev/null)"
                found_hist=yes
                if [[ "$tgt" == /dev/null ]]; then
                    _sh_emit integrity high manual shell_history_devnull "$user" \
                        "Shell history redirected to /dev/null" \
                        "$hf is a symlink to /dev/null — history is being silently discarded." \
                        "Investigate. Replace the symlink with a real, mode-600 history file."
                fi
                continue
            fi
            [[ -f "$hf" ]] || continue
            found_hist=yes
            sz="$(stat -c%s "$hf" 2>/dev/null || echo 0)"
            mode="$(stat -c%a "$hf" 2>/dev/null)"
            owner="$(stat -c%U "$hf" 2>/dev/null)"
            # world/group access on a history file (should be 600)
            if [[ -n "$mode" && "${mode: -1}" -gt 0 ]]; then
                _sh_emit integrity low review shell_history_perms "$user" \
                    "Shell history is accessible to others (mode $mode)" \
                    "$hf is mode $mode — others can read $user's command history." \
                    "chmod 600 $hf"
            fi
            [[ -n "$owner" && "$owner" != "$user" ]] && _sh_emit integrity medium manual shell_history_owner "$user" \
                "Shell history owned by $owner, not $user" \
                "$hf is owned by $owner — unexpected for $user's history." \
                "Investigate; restore correct ownership."
            # immutable bit — unusual on history (attacker lock, or hardening)
            if lsattr -d "$hf" 2>/dev/null | awk '{print $1}' | grep -q i; then
                _sh_emit integrity info review shell_history_immutable "$user" \
                    "Shell history has the immutable bit set" \
                    "$hf is +i (immutable). Could be hardening, or an attacker pinning a planted history." \
                    "Confirm it was set intentionally (lsattr $hf); if not, investigate."
            fi
        done

        # logged in but no usable history → the trail was cut
        if _sh_has_logins "$user"; then
            local biggest=0 s
            for hf in "$home/.bash_history" "$home/.zsh_history" "$home/.sh_history"; do
                [[ -f "$hf" ]] || continue
                s="$(stat -c%s "$hf" 2>/dev/null || echo 0)"; (( s > biggest )) && biggest="$s"
            done
            if [[ "$found_hist" == no || "$biggest" -eq 0 ]]; then
                _sh_emit integrity medium manual shell_history_login_gap "$user" \
                    "$user has login records but no shell history" \
                    "$user appears in the login records but has no (or empty) shell history — consistent with a cleared trail." \
                    "Investigate. A service account that genuinely never runs interactive shells can be marked 'ignored'."
            fi
        fi

        # shell rc disables history (evasion)
        for rc in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.zshrc" "$home/.kshrc"; do
            [[ -f "$rc" ]] || continue
            if grep -qE 'HISTFILE=(/dev/null|""|'\'\'')|HISTSIZE=0|HISTFILESIZE=0|unset[[:space:]]+HISTFILE|set[[:space:]]+\+o[[:space:]]+history' "$rc" 2>/dev/null; then
                _sh_emit security high manual shell_history_disabled "$user" \
                    "Shell history logging disabled in $user's config" \
                    "$rc disables shell history (HISTFILE/HISTSIZE/+o history) — a common evasion." \
                    "Investigate. Re-enable history unless there is a documented reason."
            fi
        done
    done < <(shellhist_login_users)

    # --- system-wide rc history disabling -------------------------------------
    for rc in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/*.sh /etc/zsh/zshrc; do
        [[ -f "$rc" ]] || continue
        if grep -qE 'HISTFILE=(/dev/null|""|'\'\'')|HISTSIZE=0|unset[[:space:]]+HISTFILE|set[[:space:]]+\+o[[:space:]]+history' "$rc" 2>/dev/null; then
            _sh_emit security high manual shell_history_disabled_system "$rc" \
                "Shell history disabled system-wide in $rc" \
                "$rc disables shell history for ALL users — strong tamper/evasion signal." \
                "Investigate immediately. Remove the history-disabling directive unless documented."
        fi
    done
}
