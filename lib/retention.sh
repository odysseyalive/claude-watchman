#!/usr/bin/env bash
# lib/retention.sh — keep claude-watchman a disciplined guest on its host's disk.
#
# claude-watchman collects data as it runs — the journal database, the headless
# run log and cost ledger, pre-migration/pre-prune backups, and attended-monitor
# snapshot state — and all of it lives under journal/. Left alone it only grows.
# This engine MEASURES that footprint (read-only, every loop pass, via
# check-data-footprint) and, on the operator's confirmed command, PRUNES the
# file-side artifacts. The database side (old findings/metrics/runs rows) is the
# journal's own to prune and lives in lib/journal.sh (journal_prune) — the
# single-writer contract: no other code touches findings.db.
#
# > **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.sh. This rule has no exceptions and no mode that overrides it.
#
# SEATBELT. retention_report and retention_file_candidates are READ-ONLY (sizing and
# enumeration only). retention_prune_files DELETES files and is therefore a MUTATOR:
# it is listed in lib/wm's _WM_MUTATORS, so the read-only dispatcher refuses it unless
# WM_APPLY=1 — which the unattended loop can never set. It runs only from the
# operator's `watchman fix` session, driven by fix-redflag under the review tier.

# Resolve journal paths. journal.sh is sourced before this file by the dispatcher and
# sets these; the fallbacks keep retention.sh correct if ever sourced standalone.
_RET_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCHMAN_ROOT="${WATCHMAN_ROOT:-$(cd "$_RET_LIB_DIR/.." && pwd)}"
JOURNAL_DIR="${JOURNAL_DIR:-$WATCHMAN_ROOT/journal}"

# --- sizing helpers ---------------------------------------------------------
# Bytes of one file (0 if absent). wc -c is portable across Linux and macOS and
# needs no -c%s / -f%z stat dialect branching.
_ret_bytes() { [[ -f "$1" ]] && wc -c <"$1" 2>/dev/null | tr -d ' ' || echo 0; }

# Sum bytes of every regular file directly inside a directory tree (0 if absent).
_ret_dir_bytes() {
    [[ -d "$1" ]] || { echo 0; return; }
    find "$1" -type f -printf '%s\n' 2>/dev/null | awk '{t+=$1} END{print t+0}'
}

# Humanise a byte count to IEC units (du -h style), no per-file fork.
_ret_human() {
    awk -v b="${1:-0}" 'BEGIN{
        split("B KB MB GB TB PB",u," "); i=1
        while (b>=1024 && i<6){b/=1024;i++}
        printf (i==1 ? "%dB\n" : "%.1f%s\n"), b, u[i]
    }'
}

# Newline-sentinel list of the journal's backup files, newest first.
_ret_backups() { ls -1t "$JOURNAL_DIR"/findings.db.backup-* 2>/dev/null; }

# --- retention_report (READ-ONLY) -------------------------------------------
# Per-artifact byte breakdown plus a total, one "<bytes>\t<human>\t<label>" row
# each, with the grand total last. check-data-footprint folds this into a finding's
# detail. Sizes only — it never reads the journal's CONTENTS (that is journal.sh's
# job); stat'ing findings.db's size is not "touching" the database.
retention_report() {
    local db wal shm runlog ledger runlog2 backups bbytes bcount mon offsets total=0
    db="$(_ret_bytes "$JOURNAL_DIR/findings.db")"
    wal="$(_ret_bytes "$JOURNAL_DIR/findings.db-wal")"
    shm="$(_ret_bytes "$JOURNAL_DIR/findings.db-shm")"
    runlog="$(_ret_bytes "$JOURNAL_DIR/run.log")"
    ledger="$(_ret_bytes "$JOURNAL_DIR/run-ledger.tsv")"
    mon="$(_ret_dir_bytes "$JOURNAL_DIR/monitor-state")"
    offsets=$(( $(_ret_bytes "$JOURNAL_DIR/log-offsets.txt") \
              + $(_ret_bytes "$JOURNAL_DIR/monitor-offsets.txt") \
              + $(_ret_bytes "$JOURNAL_DIR/network-baseline.txt") ))
    bbytes=0; bcount=0
    local f
    while IFS= read -r f; do [[ -n "$f" ]] || continue; bbytes=$(( bbytes + $(_ret_bytes "$f") )); bcount=$(( bcount + 1 )); done < <(_ret_backups)

    _ret_row() { printf '%s\t%s\t%s\n' "$1" "$(_ret_human "$1")" "$2"; total=$(( total + $1 )); }
    _ret_row "$db"      "findings.db (active journal)"
    _ret_row "$(( wal + shm ))" "findings.db WAL/SHM sidecars"
    _ret_row "$runlog"  "run.log (headless run log)"
    _ret_row "$ledger"  "run-ledger.tsv (cost ledger — reported, not auto-pruned)"
    _ret_row "$bbytes"  "findings.db backups ($bcount file(s))"
    _ret_row "$mon"     "monitor-state/ (attended-watch snapshots)"
    _ret_row "$offsets" "offsets + network baseline (bounded)"
    printf '%s\t%s\t%s\n' "$total" "$(_ret_human "$total")" "TOTAL (journal/ collected data)"
}

# Just the total footprint in whole MB — the cheap number check-data-footprint
# compares against WATCHMAN_DATA_FOOTPRINT_WARN_MB and records as a metric.
retention_total_mb() {
    local total=0 f
    for f in findings.db findings.db-wal findings.db-shm run.log run-ledger.tsv \
             log-offsets.txt monitor-offsets.txt network-baseline.txt; do
        total=$(( total + $(_ret_bytes "$JOURNAL_DIR/$f") ))
    done
    total=$(( total + $(_ret_dir_bytes "$JOURNAL_DIR/monitor-state") ))
    while IFS= read -r f; do [[ -n "$f" ]] && total=$(( total + $(_ret_bytes "$f") )); done < <(_ret_backups)
    echo $(( total / 1024 / 1024 ))
}

# --- retention_file_candidates (READ-ONLY) ----------------------------------
# What the file-side prune WOULD remove right now, given the configured limits.
# One "<count>\t<bytes>\t<human>\t<label>" row per class; classes with nothing to
# prune are omitted. Pure enumeration — deletes nothing. Tunables (watchman.conf):
#   WATCHMAN_RETAIN_RUNLOG_MB     rotate run.log when larger than this   (default 10)
#   WATCHMAN_RETAIN_BACKUPS       keep this many newest db backups       (default 5)
#   WATCHMAN_RETAIN_MONITOR_DAYS  prune monitor-state files older than   (default 30)
retention_file_candidates() {
    local runlog_mb="${WATCHMAN_RETAIN_RUNLOG_MB:-10}"
    local keep="${WATCHMAN_RETAIN_BACKUPS:-5}"
    local mon_days="${WATCHMAN_RETAIN_MONITOR_DAYS:-30}"
    local out="" rl rlb f bytes count

    rl="$JOURNAL_DIR/run.log"; rlb="$(_ret_bytes "$rl")"
    if (( rlb > runlog_mb * 1024 * 1024 )); then
        out+="1	$rlb	$(_ret_human "$rlb")	run.log over ${runlog_mb}MB → rotate (keep recent tail)"$'\n'
    fi

    bytes=0; count=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        count=$(( count + 1 ))
        (( count > keep )) && bytes=$(( bytes + $(_ret_bytes "$f") ))
    done < <(_ret_backups)
    if (( count > keep )); then
        out+="$(( count - keep ))	$bytes	$(_ret_human "$bytes")	old findings.db backups beyond newest $keep → delete"$'\n'
    fi

    if [[ -d "$JOURNAL_DIR/monitor-state" ]]; then
        bytes=0; count=0
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            count=$(( count + 1 )); bytes=$(( bytes + $(_ret_bytes "$f") ))
        done < <(find "$JOURNAL_DIR/monitor-state" -type f -mtime "+$mon_days" 2>/dev/null)
        if (( count > 0 )); then
            out+="$count	$bytes	$(_ret_human "$bytes")	monitor-state snapshots older than ${mon_days}d → delete"$'\n'
        fi
    fi

    [[ -n "$out" ]] && printf '%s' "$out"
    return 0
}

# --- retention_prune_files (MUTATOR — WM_APPLY only) ------------------------
# Apply the file-side prune the candidates describe. DESTRUCTIVE: it overwrites
# run.log with its tail and deletes old backups / stale monitor-state files. It is
# in _WM_MUTATORS, so the read-only dispatcher refuses it without WM_APPLY=1 — the
# loop can never reach it; only `watchman fix` (operator-confirmed, review tier) can.
# It NEVER touches findings.db, the cost ledger, offsets, or the network baseline.
retention_prune_files() {
    local runlog_mb="${WATCHMAN_RETAIN_RUNLOG_MB:-10}"
    local keep="${WATCHMAN_RETAIN_BACKUPS:-5}"
    local mon_days="${WATCHMAN_RETAIN_MONITOR_DAYS:-30}"
    local keep_lines="${WATCHMAN_RETAIN_RUNLOG_LINES:-2000}"

    echo "retention: PRUNE deletes claude-watchman's own collected files (run.log tail-rotated," >&2
    echo "retention: old findings.db backups removed, stale monitor-state cleared). findings.db," >&2
    echo "retention: the cost ledger, offsets and the network baseline are NOT touched." >&2

    # run.log → keep the most recent keep_lines lines if it is over the cap.
    local rl="$JOURNAL_DIR/run.log" rlb
    rlb="$(_ret_bytes "$rl")"
    if (( rlb > runlog_mb * 1024 * 1024 )); then
        local tmp="$rl.rotate.$$"
        if tail -n "$keep_lines" "$rl" >"$tmp" 2>/dev/null; then
            mv "$tmp" "$rl" && echo "retention: rotated run.log to its last $keep_lines lines." >&2
        else
            rm -f "$tmp"; echo "retention: could not rotate run.log (left untouched)." >&2
        fi
    fi

    # findings.db backups → delete everything past the newest $keep.
    local n=0 f removed=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        n=$(( n + 1 ))
        if (( n > keep )); then rm -f "$f" && removed=$(( removed + 1 )); fi
    done < <(_ret_backups)
    (( removed > 0 )) && echo "retention: removed $removed old findings.db backup(s) (kept newest $keep)." >&2

    # monitor-state → delete snapshot files older than the window.
    if [[ -d "$JOURNAL_DIR/monitor-state" ]]; then
        local mremoved=0
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            rm -f "$f" && mremoved=$(( mremoved + 1 ))
        done < <(find "$JOURNAL_DIR/monitor-state" -type f -mtime "+$mon_days" 2>/dev/null)
        (( mremoved > 0 )) && echo "retention: removed $mremoved stale monitor-state snapshot(s) (older than ${mon_days}d)." >&2
    fi

    echo "retention: file prune complete." >&2
}
