#!/usr/bin/env bash
# lib/capacity.sh — when a filesystem is DANGEROUSLY full, name what is filling it.
#
# check-capacity's df pass establishes THAT a filesystem is critically low; this
# engine answers the operator's very next question — WHAT is eating the space — so
# the critical-band finding (and the email it triggers) ships with the largest
# files already listed instead of just "95% full". It is the disk-pressure analog
# of webstats' offender list: a heavy filesystem walk kept polite and bounded.
#
# > PRIME DIRECTIVE. This engine is READ-ONLY. It walks the filesystem reading
# > metadata ONLY (find -printf — no `du` fork-per-file, no -exec, no -delete, no
# > -fprint) and NEVER removes or moves a byte. Freeing space is the operator's
# > call under `watchman fix`; this only observes and reports.
#
# Heavy-read discipline (CLAUDE.md "do no performance harm"): the walk runs through
# io_run when lib/io-courtesy.sh is sourced (the caller sources it), so it is
# I/O- and CPU-priced for the host's role and bounded by a timeout. The caller is
# expected to gate the whole enrichment on io_should_defer_heavy first — only the
# cheap df finding must always run; this walk is deferrable.

# capacity_top_consumers <mountpoint>
# Echoes up to N lines "<human-size>\t<absolute-path>", largest first, for the
# files that dominate the given filesystem. Stays on that ONE filesystem (-xdev),
# so it never wanders into /proc, /sys, bind mounts, or another disk. Empty output
# means nothing crossed the size floor. Tunables (config/watchman.conf or env):
#   WATCHMAN_TOPFILES_COUNT  how many files to list      (default 20)
#   WATCHMAN_TOPFILES_MIN    find -size floor            (default +25M)
capacity_top_consumers() {
    local mp="${1:-/}"
    local n="${WATCHMAN_TOPFILES_COUNT:-20}"
    local floor="${WATCHMAN_TOPFILES_MIN:-+25M}"

    # find emits "<bytes>\t<path>"; sort numerically descending; keep the top N.
    # The find (the heavy part) is io_run-priced when io-courtesy is in scope; the
    # sort/head are negligible. head closing the pipe early is fine — command
    # substitution still captures what flowed through.
    # BSD/macOS find has no -printf; there `stat -f` with a literal tab in the
    # format emits the same "<bytes>\t<path>" lines (`-exec +` batches the forks).
    local raw
    local -a findcmd=(find "$mp" -xdev -type f -size "$floor" -printf '%s\t%p\n')
    [[ "$(uname -s 2>/dev/null)" == "Darwin" ]] && \
        findcmd=(find "$mp" -xdev -type f -size "$floor" -exec stat -f $'%z\t%N' {} +)
    # `|| true`: when head exits early, find/sort take SIGPIPE (rc 141), which under
    # the dispatcher's pipefail would kill this function exactly on the big-file
    # mounts where its output matters most. The command substitution still captures
    # everything head passed through; the guard only masks the pipe status.
    if command -v io_run >/dev/null 2>&1; then
        raw="$(io_run "${findcmd[@]}" 2>/dev/null | sort -rn | head -n "$n")" || true
    else
        raw="$("${findcmd[@]}" 2>/dev/null | sort -rn | head -n "$n")" || true
    fi
    [[ -n "$raw" ]] || return 0

    # Humanise the byte column to IEC units (du -h style) without a du fork per file.
    printf '%s\n' "$raw" | awk -F'\t' '
        function human(b,   u, i) {
            split("B KB MB GB TB PB", u, " "); i = 1
            while (b >= 1024 && i < 6) { b /= 1024; i++ }
            return sprintf("%.1f%s", b, u[i])
        }
        { printf "%s\t%s\n", human($1), $2 }'
}
