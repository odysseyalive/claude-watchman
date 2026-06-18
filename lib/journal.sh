#!/usr/bin/env bash
# lib/journal.sh — THE ONLY code that reads or writes journal/findings.db.
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. Routine
# > create-or-update of findings through this library is the tool's core function
# > and is NOT a destructive database modification. What IS destructive — wiping
# > findings.db, mass-deleting findings, or a lossy schema migration — falls fully
# > under the Prime Directive: stop, warn, and ask before doing it. journal_migrate
# > below enforces that: it backs up first and refuses a lossy migration without
# > explicit operator confirmation.
#
# Contract (CLAUDE.md "The journal contract"):
#   * Single writer in code: no skill or one-off command opens findings.db; they
#     all call the functions here.
#   * Single writer at runtime: WAL mode + busy_timeout, and writes serialized
#     behind an flock so a loop iteration and a manual run cannot corrupt state.
#   * Findings are created-or-updated, never blindly appended (stable fingerprint).
#
# Source this file, then call journal_init once before any other function.

set -o pipefail

# --- Paths ------------------------------------------------------------------
# Resolve the repo root from this file's location so the library works no matter
# the caller's CWD (the loop, a manual verb, or a headless claude -p run).
_JOURNAL_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCHMAN_ROOT="${WATCHMAN_ROOT:-$(cd "$_JOURNAL_LIB_DIR/.." && pwd)}"
JOURNAL_DIR="${JOURNAL_DIR:-$WATCHMAN_ROOT/journal}"
JOURNAL_DB="${JOURNAL_DB:-$JOURNAL_DIR/findings.db}"
JOURNAL_SCHEMA="${JOURNAL_SCHEMA:-$JOURNAL_DIR/schema.sql}"
_JOURNAL_LOCK="$JOURNAL_DIR/.write.lock"

# Schema version this library expects. Must match PRAGMA user_version in schema.sql.
JOURNAL_SCHEMA_VERSION=1

# --- Low-level sqlite wrappers ---------------------------------------------
# Every connection gets WAL + a busy timeout so concurrent readers/writers wait
# instead of erroring. The setup pragmas are silenced (.output /dev/null) so their
# return values never pollute query output. Reads use this directly; writes go
# through _journal_write.
_journal_sqlite() {
    sqlite3 "$JOURNAL_DB" <<EOF
.output /dev/null
PRAGMA busy_timeout=10000;
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
.output stdout
$1
EOF
}

# Serialize writes behind an flock so two processes never write at once. The lock
# is advisory and process-scoped; readers are unaffected (WAL allows concurrent reads).
_journal_write() {
    local sql="$1"
    exec 9>"$_JOURNAL_LOCK"
    # flock is Linux-only; on Darwin fall back to unlocked write (SQLite WAL
    # provides sufficient concurrency safety for the single-writer use case).
    command -v flock >/dev/null 2>&1 && flock 9
    _journal_sqlite "$sql"
    local rc=$?
    command -v flock >/dev/null 2>&1 && flock -u 9
    exec 9>&-
    return $rc
}

# Double single-quotes so values are safe inside SQL string literals.
_sql_escape() { printf "%s" "${1//\'/\'\'}"; }

# --- Initialization & migration --------------------------------------------
# Idempotent: create the DB from schema.sql if absent, else verify the version
# and migrate if needed. Call once at the top of any entry point.
journal_init() {
    mkdir -p "$JOURNAL_DIR"
    if [[ ! -f "$JOURNAL_DB" ]]; then
        if [[ ! -f "$JOURNAL_SCHEMA" ]]; then
            echo "journal: schema.sql not found at $JOURNAL_SCHEMA" >&2
            return 1
        fi
        # Fresh create is additive (no data to lose) — proceed without gating.
        flock_dir_init
        sqlite3 "$JOURNAL_DB" "PRAGMA journal_mode=WAL;" >/dev/null
        sqlite3 "$JOURNAL_DB" < "$JOURNAL_SCHEMA"
        return $?
    fi
    journal_migrate
}

# Ensure the lock dir/file is writable before the first lock.
flock_dir_init() { mkdir -p "$JOURNAL_DIR"; : >"$_JOURNAL_LOCK" 2>/dev/null || true; }

# Compare on-disk user_version to the expected one and migrate.
#   * Same version            → no-op.
#   * On-disk < expected, additive → CREATE TABLE/INDEX IF NOT EXISTS from
#     schema.sql is lossless; apply automatically.
#   * Lossy migration (would drop/rewrite data) → PRIME DIRECTIVE: back up and
#     refuse without WATCHMAN_CONFIRM_MIGRATION=yes (the operator's explicit OK).
journal_migrate() {
    local on_disk
    on_disk="$(_journal_sqlite "PRAGMA user_version;")"
    [[ -z "$on_disk" ]] && on_disk=0
    if (( on_disk == JOURNAL_SCHEMA_VERSION )); then
        return 0
    fi
    if (( on_disk > JOURNAL_SCHEMA_VERSION )); then
        echo "journal: DB is newer (v$on_disk) than this code (v$JOURNAL_SCHEMA_VERSION). Refusing to downgrade." >&2
        return 1
    fi

    # Additive path: re-applying schema.sql only runs IF NOT EXISTS DDL.
    # schema.sql is authored to be additive; if a future version needs a lossy
    # change, this gate stops it until the operator confirms.
    echo "journal: migrating findings.db from v$on_disk to v$JOURNAL_SCHEMA_VERSION (additive)." >&2
    journal_backup "pre-migration"      # always back up before touching structure
    if [[ "${WATCHMAN_LOSSY_MIGRATION:-no}" == "yes" && "${WATCHMAN_CONFIRM_MIGRATION:-no}" != "yes" ]]; then
        cat >&2 <<'EOF'
journal: STOP — a LOSSY schema migration was requested. This is a destructive
database operation under the Prime Directive: it can lose finding history.
A backup was taken, but the migration will NOT proceed without explicit operator
confirmation. Re-run with WATCHMAN_CONFIRM_MIGRATION=yes to authorize it.
EOF
        return 1
    fi
    _journal_write "$(cat "$JOURNAL_SCHEMA")"
}

# Timestamped backup of findings.db (additive, never destructive). Used before
# any structural change and available to the operator on demand.
journal_backup() {
    [[ -f "$JOURNAL_DB" ]] || return 0
    local tag="${1:-manual}" ts backup
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="$JOURNAL_DB.backup-$ts-$tag"
    # Use sqlite's own backup so a concurrent writer can't tear the copy.
    sqlite3 "$JOURNAL_DB" ".backup '$backup'" && echo "journal: backed up to $backup" >&2
}

# --- Fingerprint ------------------------------------------------------------
# Stable dedup key. The same conceptual problem on a different family/profile
# yields a DIFFERENT fingerprint by design (different remediation/urgency).
journal_fingerprint() {
    local family="$1" profile="$2" category="$3" check_id="$4" target="${5:-}"
    printf '%s|%s|%s|%s|%s' "$family" "$profile" "$category" "$check_id" "$target" \
        | sha256sum | cut -d' ' -f1
}

# --- Create-or-update -------------------------------------------------------
# The core Observe→Journal operation. Computes the fingerprint, then upserts:
#   * new fingerprint              → INSERT (status open)
#   * exists & status 'fixed'      → REGRESSED (highest-signal event for the loop)
#   * exists & status 'ignored'    → stay ignored (operator accepted the risk)
#   * otherwise                    → update fields + last_seen_at, keep status
# Args (positional):
#   1 family 2 profile 3 category 4 severity 5 risk_tier
#   6 check_id 7 target 8 title 9 detail 10 remediation
journal_upsert() {
    local family="$1" profile="$2" category="$3" severity="$4" risk_tier="$5"
    local check_id="$6" target="${7:-}" title="$8" detail="${9:-}" remediation="${10:-}"
    local fp; fp="$(journal_fingerprint "$family" "$profile" "$category" "$check_id" "$target")"

    local ef ep ec esv ert ecid etg etl edt erm
    ef="$(_sql_escape "$family")";       ep="$(_sql_escape "$profile")"
    ec="$(_sql_escape "$category")";     esv="$(_sql_escape "$severity")"
    ert="$(_sql_escape "$risk_tier")";   ecid="$(_sql_escape "$check_id")"
    etg="$(_sql_escape "$target")";      etl="$(_sql_escape "$title")"
    edt="$(_sql_escape "$detail")";      erm="$(_sql_escape "$remediation")"

    _journal_write "
INSERT INTO findings
    (fingerprint, family, profile, category, severity, risk_tier,
     check_id, target, title, detail, remediation, status,
     discovered_at, last_seen_at)
VALUES
    ('$fp','$ef','$ep','$ec','$esv','$ert','$ecid','$etg','$etl','$edt','$erm','open',
     datetime('now'), datetime('now'))
ON CONFLICT(fingerprint) DO UPDATE SET
    severity     = excluded.severity,
    risk_tier    = excluded.risk_tier,
    title        = excluded.title,
    detail       = excluded.detail,
    remediation  = excluded.remediation,
    last_seen_at = datetime('now'),
    status = CASE
                 WHEN findings.status = 'fixed'   THEN 'regressed'
                 WHEN findings.status = 'ignored' THEN 'ignored'
                 ELSE findings.status
             END;"
    printf '%s\n' "$fp"
}

# --- Status & metrics -------------------------------------------------------
# Transition a finding's status. 'fixed' stamps fix_applied_at. Appending an
# operator note never overwrites prior notes.
# NOTE: avoid the local name `status` — it is a read-only special variable in zsh,
# and this library may be sourced into a non-bash shell.
journal_set_status() {
    local fp; fp="$(_sql_escape "$1")"
    local new_status; new_status="$(_sql_escape "$2")"
    local note="${3:-}"
    local set_fix=""
    [[ "$2" == "fixed" ]] && set_fix=", fix_applied_at = datetime('now')"
    local set_note=""
    [[ -n "$note" ]] && set_note=", notes = TRIM(notes || char(10) || '$(_sql_escape "$note")')"
    _journal_write "UPDATE findings SET status='$new_status'$set_fix$set_note WHERE fingerprint='$fp';"
}

# Record a point in a tracked time series (e.g. Lynis hardening index).
journal_record_metric() {
    local name; name="$(_sql_escape "$1")"
    local value="$2"
    _journal_write "INSERT INTO metrics(name, value) VALUES('$name', $value);"
}

# Open a run row, returning its id; close it with journal_run_finish.
journal_run_start() {
    local kind; kind="$(_sql_escape "${1:-audit}")"
    _journal_write "INSERT INTO runs(kind) VALUES('$kind'); SELECT last_insert_rowid();" | tail -n1
}
journal_run_finish() {
    local id="$1" summary; summary="$(_sql_escape "${2:-}")"
    _journal_write "UPDATE runs SET finished_at=datetime('now'), summary='$summary' WHERE id=$id;"
}

# --- Read helpers (no writes) ----------------------------------------------
journal_count_open()  { _journal_sqlite "SELECT COUNT(*) FROM findings WHERE status IN ('open','regressed');"; }
journal_count_regressed() { _journal_sqlite "SELECT COUNT(*) FROM findings WHERE status='regressed';"; }
# Pretty-print findings, optionally filtered by status.
journal_list() {
    local where=""
    [[ -n "${1:-}" ]] && where="WHERE status='$(_sql_escape "$1")'"
    _journal_sqlite ".mode column
.headers on
SELECT id, severity, risk_tier, status, category, title FROM findings $where ORDER BY
  CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
  last_seen_at DESC;"
}
# Machine-readable single finding by fingerprint (pipe-separated).
journal_get() {
    local fp; fp="$(_sql_escape "$1")"
    _journal_sqlite "SELECT id,fingerprint,severity,risk_tier,status,category,title,detail,remediation FROM findings WHERE fingerprint='$fp';"
}
