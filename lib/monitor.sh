# lib/monitor.sh — deterministic, read-only delta helpers for the in-session
# `/watchman monitor` verb. Each helper emits ONLY what is new since the previous
# pass, so a `/loop`-driven monitor never re-announces content it already showed.
#
# > **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.sh. This rule has no exceptions and no mode that overrides it.
#
# Both functions are READ-ONLY: they read logs/stdin and write ONLY their own gitignored
# scratch state (journal/monitor-offsets.txt and journal/monitor-state/<key>) — the same
# advisory-state category as the loop's log offsets, NOT a Prime-Directive database write.
# Neither mutates the system, so neither belongs in lib/wm's _WM_MUTATORS.

# Where the per-file read offsets live (gitignored local state; keyed separately from the
# loop's journal/log-offsets.txt so monitor and the audit never fight over the same cursor).
monitor_offset_file() { echo "${WATCHMAN_ROOT:-.}/journal/monitor-offsets.txt"; }
# Where command-snapshot baselines live (one file per watch key).
monitor_state_dir()   { echo "${WATCHMAN_ROOT:-.}/journal/monitor-state"; }

# monitor_file_delta <path…> — emit only the NEW bytes of each given file since the last
# pass, then advance the stored offset. Mirrors webstats_cat_logs_incremental:
#   * Same file (inode unchanged) and grown → read [offset, end] only.
#   * Rotated (inode changed) or truncated (size < offset) → read from 0 and reset.
# Offsets persist as TSV: <path> <inode> <size>. Heavy reads run at the role's I/O
# priority when lib/io-courtesy.sh is sourced.
monitor_file_delta() {
    local ofile tmp f inode size start
    local -A OFF_INODE=() OFF_SIZE=()
    _mc() { if declare -F io_run >/dev/null 2>&1; then io_run "$@"; else "$@"; fi; }
    ofile="$(monitor_offset_file)"
    if [[ -r "$ofile" ]]; then
        local k i s
        while IFS=$'\t' read -r k i s; do
            [[ -n "$k" ]] && { OFF_INODE["$k"]="$i"; OFF_SIZE["$k"]="$s"; }
        done < "$ofile"
    fi
    # Carry forward offsets for files not named this pass, so an unrelated watch keeps its cursor.
    tmp="$(mktemp)"
    local -A SEEN=()
    for f in "$@"; do
        [[ -f "$f" ]] || continue
        SEEN["$f"]=1
        inode="$(stat -c%i "$f" 2>/dev/null)"; size="$(stat -c%s "$f" 2>/dev/null)"
        [[ -n "$inode" && -n "$size" ]] || continue
        start=0
        if [[ "${OFF_INODE[$f]:-}" == "$inode" && -n "${OFF_SIZE[$f]:-}" && "$size" -ge "${OFF_SIZE[$f]}" ]]; then
            start="${OFF_SIZE[$f]}"
        fi
        (( size > start )) && _mc tail -c "+$(( start + 1 ))" -- "$f" 2>/dev/null
        printf '%s\t%s\t%s\n' "$f" "$inode" "$size" >> "$tmp"
    done
    # Preserve cursors for any previously-tracked file not watched this pass.
    local pk
    for pk in "${!OFF_INODE[@]}"; do
        [[ -n "${SEEN[$pk]:-}" ]] && continue
        printf '%s\t%s\t%s\n' "$pk" "${OFF_INODE[$pk]}" "${OFF_SIZE[$pk]:-0}" >> "$tmp"
    done
    mv -f "$tmp" "$ofile" 2>/dev/null || rm -f "$tmp"
}

# monitor_diff <key> — read a fresh snapshot on STDIN, print only the lines that are NEW
# relative to the previous snapshot stored for <key>, then save the snapshot as the new
# baseline. For snapshot-style watches (open connections, a `grep` result set) where there
# is no byte offset. <key> is sanitized to a safe filename. First pass (no baseline) emits
# the whole snapshot so the operator sees the starting state.
monitor_diff() {
    local key="${1:-}" dir state tmp
    [[ -n "$key" ]] || { echo "monitor_diff: a watch key is required" >&2; return 2; }
    key="${key//[^A-Za-z0-9._-]/_}"
    dir="$(monitor_state_dir)"; mkdir -p "$dir" 2>/dev/null || true
    state="$dir/$key"
    tmp="$(mktemp)"
    cat > "$tmp"
    if [[ -r "$state" ]]; then
        # Emit lines present in the new snapshot but absent from the prior one (order-preserving).
        awk 'NR==FNR{ old[$0]=1; next } !($0 in old)' "$state" "$tmp"
    else
        cat "$tmp"
    fi
    mv -f "$tmp" "$state" 2>/dev/null || rm -f "$tmp"
}
