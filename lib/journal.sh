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
    flock 9
    _journal_sqlite "$sql"
    local rc=$?
    flock -u 9
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

# --- Retention prune (DESTRUCTIVE — Prime Directive, WM_APPLY only) ----------
# Deleting old rows from findings.db is a destructive database operation, so it is
# listed in lib/wm's _WM_MUTATORS (the read-only dispatcher refuses it without
# WM_APPLY=1 — the unattended loop can never set that) and it ALWAYS backs up the
# database before deleting. It is driven by the operator's `watchman fix` session
# (fix-redflag, review tier), never the loop. What it removes, by retention window:
#   * findings whose status is terminal ('fixed'/'ignored') and whose last_seen_at
#     predates WATCHMAN_RETAIN_FINDINGS_DAYS — active findings (open/regressed/
#     in-review) are NEVER pruned, whatever their age;
#   * metrics rows older than WATCHMAN_RETAIN_METRICS_DAYS;
#   * runs rows older than WATCHMAN_RETAIN_RUNS_DAYS;
# then VACUUMs to return the freed pages to the filesystem.
journal_prune() {
    local fdays="${WATCHMAN_RETAIN_FINDINGS_DAYS:-180}"
    local mdays="${WATCHMAN_RETAIN_METRICS_DAYS:-90}"
    local rdays="${WATCHMAN_RETAIN_RUNS_DAYS:-90}"
    [[ -f "$JOURNAL_DB" ]] || { echo "journal: no findings.db to prune." >&2; return 0; }

    cat >&2 <<EOF
journal: PRUNE is a DESTRUCTIVE database operation under the Prime Directive — it
journal: deletes old terminal findings (fixed/ignored, last seen >${fdays}d ago),
journal: metrics rows >${mdays}d, and runs rows >${rdays}d, then VACUUMs. Active
journal: findings (open/regressed/in-review) are NEVER pruned. Backing up first.
EOF
    journal_backup "pre-prune"
    _journal_write "
DELETE FROM findings
  WHERE status IN ('fixed','ignored')
    AND last_seen_at < datetime('now','-$fdays days');
DELETE FROM metrics WHERE recorded_at < datetime('now','-$mdays days');
DELETE FROM runs    WHERE started_at  < datetime('now','-$rdays days');
VACUUM;"
    local rc=$?
    (( rc == 0 )) && echo "journal: prune complete (database vacuumed)." >&2 \
                  || echo "journal: prune FAILED (rc=$rc) — the pre-prune backup is intact." >&2
    return $rc
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
    # family/profile are machine constants. A skill may pass them explicitly, OR pass
    # "" "" and let the journal resolve them here — this is deliberate, because under
    # Claude Code's dontAsk the skill CANNOT use `$(bash lib/wm watchman_family)` command
    # substitution to compute them (a substituted command does not match the allowlist).
    # The dispatcher always sources distro.sh before us, so the resolvers are present;
    # the fallback keeps the fingerprint deterministic if ever called without them.
    [[ -z "$family"  ]] && family="$(declare -F watchman_family  >/dev/null 2>&1 && watchman_family  || echo unknown)"
    [[ -z "$profile" ]] && profile="$(declare -F watchman_profile >/dev/null 2>&1 && watchman_profile || echo unknown)"
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
# What journal_prune WOULD delete right now, given the configured windows. Read-only
# (no DELETE), so check-data-footprint can size the database-side prune without
# touching a row. One "<label>\t<count>" line per class.
journal_prune_candidates() {
    local fdays="${WATCHMAN_RETAIN_FINDINGS_DAYS:-180}"
    local mdays="${WATCHMAN_RETAIN_METRICS_DAYS:-90}"
    local rdays="${WATCHMAN_RETAIN_RUNS_DAYS:-90}"
    [[ -f "$JOURNAL_DB" ]] || { echo "findings	0"; echo "metrics	0"; echo "runs	0"; return 0; }
    printf 'terminal findings >%sd\t%s\n' "$fdays" \
        "$(_journal_sqlite "SELECT COUNT(*) FROM findings WHERE status IN ('fixed','ignored') AND last_seen_at < datetime('now','-$fdays days');")"
    printf 'metrics rows >%sd\t%s\n' "$mdays" \
        "$(_journal_sqlite "SELECT COUNT(*) FROM metrics WHERE recorded_at < datetime('now','-$mdays days');")"
    printf 'runs rows >%sd\t%s\n' "$rdays" \
        "$(_journal_sqlite "SELECT COUNT(*) FROM runs WHERE started_at < datetime('now','-$rdays days');")"
}

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
# Read-only: the last N runs (newest first), so report-lastrun can lead with WHEN the
# cycle last ran and WHAT changed. correlate-findings writes one row per loop pass with a
# plain-language `summary` (counts of new/regressed/cleared) — that summary IS the
# per-run account. Pipe-separated: id|kind|started_at|finished_at|summary. Default N=5.
journal_recent_runs() {
    local n="${1:-5}"
    [[ "$n" =~ ^[0-9]+$ ]] || n=5
    _journal_sqlite "SELECT id,kind,started_at,COALESCE(finished_at,''),summary FROM runs ORDER BY started_at DESC LIMIT $n;"
}
# Read-only: the open/regressed findings worth EXPLAINING to a non-technical operator —
# everything regressed (came back), plus high/critical severity — WITH detail and
# remediation (journal_list omits those). Regressed first, then by severity. This is what
# report-lastrun expands on after the brief overview. Pipe-separated:
# id|severity|risk_tier|status|category|title|detail|remediation.
journal_important_open() {
    _journal_sqlite "SELECT id,severity,risk_tier,status,category,title,detail,remediation
FROM findings
WHERE status IN ('open','regressed')
  AND (status='regressed' OR severity IN ('high','critical'))
ORDER BY
  CASE status WHEN 'regressed' THEN 0 ELSE 1 END,
  CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
  last_seen_at DESC;"
}
