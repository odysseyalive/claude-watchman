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

    # mode-600 temp config so the password never lands in a world-readable file.
    local cfg; cfg="$(mktemp)"; chmod 600 "$cfg"
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
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default : watchman
EOF

    local rc=0
    {
        printf 'From: %s\n' "$SMTP_USER"
        printf 'To: %s\n' "$REPORT_EMAIL"
        printf 'Subject: %s\n' "$subject"
        printf 'Content-Type: text/plain; charset=UTF-8\n\n'
        if [[ -n "$body_file" && -r "$body_file" ]]; then cat "$body_file"; else cat; fi
    } | msmtp --file="$cfg" "$REPORT_EMAIL" || rc=$?

    rm -f "$cfg"
    if (( rc != 0 )); then
        echo "smtp: msmtp exited $rc — report not delivered." >&2
        return "$rc"
    fi
    echo "smtp: report sent to $REPORT_EMAIL" >&2
}
