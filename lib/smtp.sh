#!/usr/bin/env bash
# lib/smtp.sh — the ONLY code that reads SMTP credentials and dispatches mail.
#
# Just as lib/journal.sh is the sole gate to findings.db, this is the sole gate to
# the SMTP secrets. Skills never read credentials directly — they call the
# send-report skill, which calls send_report() here. Credentials live ONLY in the
# gitignored .env at the repo root (never watchman.conf, never hardcoded). See
# CLAUDE.md "Mail dispatch".
#
# Transport: wraps `msmtp` (a small sendmail-compatible client install.sh adds as
# a dependency). Credentials are passed without writing a world-readable
# ~/.msmtprc: we build a mode-600 temp config and remove it after sending.
#
# Graceful degradation: if .env is missing or SMTP_PASS is blank, mail is treated
# as UNCONFIGURED — send_report logs and returns success-ish (skips) rather than
# crashing the loop. A monitoring tool must never die because mail is not set up.

_SMTP_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCHMAN_ROOT="${WATCHMAN_ROOT:-$(cd "$_SMTP_LIB_DIR/.." && pwd)}"
SMTP_ENV_FILE="${SMTP_ENV_FILE:-$WATCHMAN_ROOT/.env}"

# Load .env into the environment (only the keys we use). Returns 1 if unreadable.
_smtp_load_env() {
    [[ -r "$SMTP_ENV_FILE" ]] || return 1
    # Read KEY=VALUE lines safely: ignore comments/blank, strip optional quotes.
    local line key val
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        key="${line%%=*}"; val="${line#*=}"
        key="$(printf '%s' "$key" | tr -d '[:space:]')"
        # strip surrounding single/double quotes if present
        val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
        case "$key" in
            SMTP_HOST|SMTP_PORT|SMTP_USER|SMTP_PASS|REPORT_EMAIL)
                printf -v "$key" '%s' "$val"; export "${key?}" ;;
        esac
    done < "$SMTP_ENV_FILE"
    return 0
}

# 0 = configured (host/user/pass/recipient present), 1 = not.
smtp_is_configured() {
    _smtp_load_env || return 1
    [[ -n "${SMTP_HOST:-}" && -n "${SMTP_USER:-}" && -n "${SMTP_PASS:-}" && -n "${REPORT_EMAIL:-}" ]]
}

# send_report SUBJECT [BODY_FILE]
#   Reads BODY_FILE (or stdin if omitted) as the message body and emails it to
#   REPORT_EMAIL. Degrades gracefully when unconfigured.
send_report() {
    local subject="$1" body_file="${2:-}"
    if ! smtp_is_configured; then
        echo "smtp: mail unconfigured (.env missing or SMTP_PASS blank) — skipping dispatch." >&2
        return 0   # not an error: the loop continues
    fi
    if ! command -v msmtp >/dev/null 2>&1; then
        echo "smtp: msmtp not installed — skipping dispatch. Install it via the resolver (pkg_install msmtp)." >&2
        return 0
    fi

    local port="${SMTP_PORT:-587}" tls_line="tls on" tls_starttls="tls_starttls on"
    [[ "$port" == "465" ]] && tls_starttls="tls_starttls off"   # implicit TLS

    # System CA bundle via the distro resolver (the path differs per family — the
    # Debian one does not exist on RHEL/macOS). When smtp.sh was sourced standalone
    # (bin/watchman testmail), pull in the resolver rather than duplicating its path
    # list here. No bundle found → omit tls_trust_file and let msmtp's built-in
    # default apply rather than pointing TLS at a missing file.
    # shellcheck source=lib/distro.sh
    declare -F ca_bundle_path >/dev/null || source "$_SMTP_LIB_DIR/distro.sh"
    local trust trust_line=""
    trust="$(ca_bundle_path || true)"
    [[ -n "$trust" ]] && trust_line="tls_trust_file $trust"

    # The whole send runs in a subshell that owns the mode-600 temp config: its EXIT
    # trap (with INT/TERM routed through exit) removes the password-bearing file on
    # success, failure, and interrupt alike — and no trap leaks into the sourcing
    # shell (a RETURN trap set here would re-fire, with cfg unbound, on the next
    # `source` completion in this process).
    local rc=0
    (
        cfg="$(mktemp)" || exit 1
        chmod 600 "$cfg"
        trap 'rm -f "$cfg"' EXIT
        trap 'exit 130' INT TERM
        cat >"$cfg" <<EOF
account watchman
host ${SMTP_HOST}
port ${port}
auth on
user ${SMTP_USER}
password ${SMTP_PASS}
from ${SMTP_USER}
${tls_line}
${tls_starttls}
${trust_line}
account default : watchman
EOF
        {
            printf 'From: %s\n' "$SMTP_USER"
            printf 'To: %s\n' "$REPORT_EMAIL"
            printf 'Subject: %s\n' "$subject"
            printf 'Content-Type: text/plain; charset=UTF-8\n\n'
            if [[ -n "$body_file" && -r "$body_file" ]]; then cat "$body_file"; else cat; fi
        } | msmtp --file="$cfg" "$REPORT_EMAIL"
    ) || rc=$?

    if (( rc != 0 )); then
        echo "smtp: msmtp exited $rc — report not delivered." >&2
        return "$rc"
    fi
    echo "smtp: report sent to $REPORT_EMAIL" >&2
}

# smtp_send_test — send a fixed test message to prove the .env credentials and the
# msmtp transport actually deliver, end to end. This is the plumbing-verification
# path behind `watchman testmail`, so it does NOT degrade silently the way
# send_report does for the loop: an operator running a test wants a loud, explicit
# result. Unconfigured or msmtp-missing is a FAILURE here (returns non-zero with a
# pointer to the fix), not a quiet skip.
#
# Read-only: it sends one email and writes nothing to the system or the journal.
smtp_send_test() {
    if ! smtp_is_configured; then
        cat >&2 <<EOF
smtp: mail is NOT configured — cannot send a test.
      Fill in $SMTP_ENV_FILE: SMTP_HOST, SMTP_USER, SMTP_PASS, REPORT_EMAIL.
      (Copy .env.example to .env if you have not yet.)
EOF
        return 1
    fi
    if ! command -v msmtp >/dev/null 2>&1; then
        echo "smtp: msmtp is not installed — cannot send a test. Install it (pkg_install msmtp)." >&2
        return 1
    fi

    local host="${HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"
    echo "smtp: sending test to ${REPORT_EMAIL} via ${SMTP_HOST}:${SMTP_PORT:-587} ..." >&2

    local body
    body="claude-watchman test email from ${host}.

If you are reading this, SMTP delivery works: .env credentials authenticated
to ${SMTP_HOST} and msmtp delivered to ${REPORT_EMAIL}. No findings are attached —
this is only a transport check.

Reports will arrive here when the loop's delta crosses a notify threshold."

    if printf '%s\n' "$body" | send_report "claude-watchman: test email from ${host}"; then
        echo "smtp: test sent — check the ${REPORT_EMAIL} inbox (and spam folder)." >&2
        return 0
    fi
    echo "smtp: test FAILED to send (see the msmtp error above)." >&2
    return 1
}
