#!/usr/bin/env bash
# lib/io-courtesy.sh — be a good guest: never degrade the machine's real job.
#
# claude-watchman does some genuinely heavy reads (package integrity verification,
# full + rotated log scans, Lynis, journald walks). On a busy server that I/O can
# compete with the production workload. This extends the project's safety promise
# from "do nothing destructive" to "do nothing that takes the box down":
#
#   1. io_run            — run a heavy command at IDLE I/O + lowest CPU priority,
#                          under a timeout, so it yields to production and can't run
#                          away. Degrades gracefully if ionice/nice/timeout absent.
#   2. io_should_defer_heavy / io_pressure_high — true when the box is already under
#                          enough load/memory pressure that a heavy diagnostic should
#                          be SKIPPED this pass (and recorded as deferred) rather than
#                          piled on. A monitor that backs off when the machine is hot.
#
# Read-only and non-destructive by nature: it only ever LOWERS claude-watchman's own
# priority or declines to run — it never raises priority, kills, or throttles anything
# else. Config (config/watchman.conf): WATCHMAN_IONICE, WATCHMAN_IO_TIMEOUT,
# WATCHMAN_IO_GUARD, WATCHMAN_IO_GUARD_LOAD (per-core), WATCHMAN_IO_GUARD_MEM_PCT.

# Number of CPUs (>= 1).
io_cpus() {
    local n; n="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
    [[ "$n" =~ ^[0-9]+$ && "$n" -ge 1 ]] || n=1
    echo "$n"
}

# io_run <cmd...> — execute a heavy command politely: idle I/O class (ionice -c3),
# lowest CPU priority (nice -n19), and a wall-clock timeout. Any tool that is
# missing is simply omitted; an empty wrapper just runs the command directly.
io_run() {
    local pre=()
    if [[ "${WATCHMAN_IONICE:-yes}" == yes ]]; then
        command -v ionice >/dev/null 2>&1 && pre+=(ionice -c3)
        command -v nice   >/dev/null 2>&1 && pre+=(nice -n19)
    fi
    command -v timeout >/dev/null 2>&1 && pre+=(timeout "${WATCHMAN_IO_TIMEOUT:-300}")
    if (( ${#pre[@]} )); then "${pre[@]}" "$@"; else "$@"; fi
}

# io_pressure_high — return 0 (TRUE: defer) when the box is busy enough that we
# should not add heavy diagnostic I/O. Signals (snapshot, no sampling delay, no
# tool deps): per-core load average (Linux loadavg includes I/O-wait tasks, so it
# already reflects disk pressure) and available memory %. Guard off → never defers.
io_pressure_high() {
    [[ "${WATCHMAN_IO_GUARD:-yes}" == yes ]] || return 1
    local load1 cpus per memav memtot mempct
    load1="$(awk '{print $1}' /proc/loadavg 2>/dev/null)"
    cpus="$(io_cpus)"
    if [[ -n "$load1" ]]; then
        per="$(awk -v l="$load1" -v c="$cpus" 'BEGIN{printf "%.3f", (c>0 ? l/c : l)}')"
        awk -v p="$per" -v t="${WATCHMAN_IO_GUARD_LOAD:-1.5}" 'BEGIN{exit !(p+0 > t+0)}' && return 0
    fi
    memav="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
    memtot="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
    if [[ -n "$memav" && -n "$memtot" && "$memtot" -gt 0 ]]; then
        mempct=$(( memav * 100 / memtot ))
        (( mempct < ${WATCHMAN_IO_GUARD_MEM_PCT:-10} )) && return 0
    fi
    return 1
}

# Convenience name the skills call before a heavy diagnostic.
io_should_defer_heavy() { io_pressure_high; }

# io_pressure_reason — one-line human explanation for the deferral finding.
io_pressure_reason() {
    local load1 cpus per memav memtot mempct
    load1="$(awk '{print $1}' /proc/loadavg 2>/dev/null)"; cpus="$(io_cpus)"
    per="$(awk -v l="${load1:-0}" -v c="$cpus" 'BEGIN{printf "%.2f", (c>0 ? l/c : l)}')"
    memav="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
    memtot="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
    mempct="n/a"; [[ -n "$memav" && -n "$memtot" && "$memtot" -gt 0 ]] && mempct="$(( memav*100/memtot ))%"
    echo "load ${load1:-?} over ${cpus} core(s) = ${per}/core (limit ${WATCHMAN_IO_GUARD_LOAD:-1.5}/core); mem free ${mempct} (limit ${WATCHMAN_IO_GUARD_MEM_PCT:-10}%)"
}
