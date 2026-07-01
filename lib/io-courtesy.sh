#!/usr/bin/env bash
# lib/io-courtesy.sh — be a good guest, but know your role and your own footprint.
#
# claude-watchman does some genuinely heavy reads (package integrity verification,
# full + rotated log scans, Lynis, journald walks). This module keeps that I/O from
# degrading the machine's real job — AND adapts to the case where claude-watchman is
# the most important thing on the box, AND measures what it itself costs.
#
#   1. io_run            — run a heavy command at a priority chosen by the declared
#                          ROLE (guest/peer/priority), under a timeout.
#   2. io_should_defer_heavy / io_pressure_high — true when the box is under enough
#                          real pressure to SKIP a heavy step this pass. Uses the
#                          kernel's PRESSURE STALL INFORMATION (/proc/pressure/io) —
#                          the accurate, I/O-specific signal — falling back to
#                          per-core loadavg + free memory where PSI is unavailable.
#                          The defer thresholds scale by role.
#   3. io_measure        — run a command politely AND record what watchman spent on
#                          it (wall seconds; filesystem I/O when GNU time is present),
#                          so the monitor can analyze and bound its OWN footprint.
#
# ROLE (config WATCHMAN_PRIORITY): how hard claude-watchman yields.
#   guest    (default) — idle I/O, lowest CPU, defer at the configured thresholds.
#   peer               — low-but-normal priority, defer only under REAL pressure (2x).
#   priority           — claude-watchman is critical (dedicated monitor): normal
#                        priority, defer only under EXTREME pressure (4x) so it keeps
#                        running when you most need it.
#
# Config: WATCHMAN_PRIORITY, WATCHMAN_IONICE, WATCHMAN_IO_TIMEOUT, WATCHMAN_IO_GUARD,
# WATCHMAN_IO_GUARD_PSI (PSI %), WATCHMAN_IO_GUARD_LOAD (per-core, fallback),
# WATCHMAN_IO_GUARD_MEM_PCT, WATCHMAN_CHECK_TIME_BUDGET. Read-only and non-destructive:
# it only ever lowers its own priority or declines to run.

io_cpus() {
    local n; n="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
    [[ "$n" =~ ^[0-9]+$ && "$n" -ge 1 ]] || n=1
    echo "$n"
}

_io_role() { echo "${WATCHMAN_PRIORITY:-guest}"; }

# Defer-threshold multiplier by role (higher role tolerates more before backing off).
_io_role_mult() { case "$(_io_role)" in priority) echo 4 ;; peer) echo 2 ;; *) echo 1 ;; esac; }

# io_run <cmd...> — run a heavy command at the role's I/O + CPU priority, under a
# timeout. Missing tools are omitted; an empty wrapper runs the command directly.
io_run() {
    local pre=()
    # ionice is Linux-only; skip gracefully on Darwin.
    if [[ "${WATCHMAN_IONICE:-yes}" == yes ]] && command -v ionice >/dev/null 2>&1 \
       && [[ "$(uname -s 2>/dev/null)" != Darwin ]]; then
        case "$(_io_role)" in
            priority) pre+=(ionice -c2 -n0) ;;   # best-effort, normal — do not deprioritize
            peer)     pre+=(ionice -c2 -n6) ;;   # best-effort, low
            *)        pre+=(ionice -c3)     ;;   # idle (guest)
        esac
    fi
    # CPU priority has its own INDEPENDENT toggle: turning off I/O deprioritization
    # (WATCHMAN_IONICE=no) must not silently turn off CPU deprioritization too.
    if [[ "${WATCHMAN_NICE:-yes}" == yes ]] && command -v nice >/dev/null 2>&1; then
        case "$(_io_role)" in
            priority) : ;;                       # normal CPU priority
            peer)     pre+=(nice -n10) ;;
            *)        pre+=(nice -n19) ;;
        esac
    fi
    command -v timeout >/dev/null 2>&1 && pre+=(timeout "${WATCHMAN_IO_TIMEOUT:-300}")
    if (( ${#pre[@]} )); then "${pre[@]}" "$@"; else "$@"; fi
}

# Read 'some avg10=' from a /proc/pressure/<res> file. Echoes the number or nothing.
_io_psi_some_avg10() {
    [[ -r "$1" ]] || return 1
    awk '/^some/{for(i=1;i<=NF;i++) if($i ~ /^avg10=/){sub(/avg10=/,"",$i); print $i; exit}}' "$1" 2>/dev/null
}

# io_pressure_high — TRUE (0) when we should DEFER a heavy step. Prefers PSI (the
# accurate I/O-specific signal); falls back to per-core loadavg + free memory.
io_pressure_high() {
    [[ "${WATCHMAN_IO_GUARD:-yes}" == yes ]] || return 1
    local mult psi mpsi thr
    mult="$(_io_role_mult)"
    thr="$(awk -v b="${WATCHMAN_IO_GUARD_PSI:-20}" -v m="$mult" 'BEGIN{printf "%.4f", b*m}')"

    # Darwin has no /proc — skip PSI entirely and use the load/memory fallback.
    if [[ "$(uname -s 2>/dev/null)" != Darwin ]]; then
        if [[ -r /proc/pressure/io ]]; then
            psi="$(_io_psi_some_avg10 /proc/pressure/io)"
            if [[ -n "$psi" ]]; then
                awk -v p="$psi" -v t="$thr" 'BEGIN{exit !(p+0 > t+0)}' && return 0
                mpsi="$(_io_psi_some_avg10 /proc/pressure/memory)"
                [[ -n "$mpsi" ]] && awk -v p="$mpsi" -v t="$thr" 'BEGIN{exit !(p+0 > t+0)}' && return 0
                return 1   # PSI present and below threshold → not under pressure
            fi
        fi
    fi

    # Fallback: per-core load average (Darwin: sysctl; Linux: /proc/loadavg).
    local load1 cpus per loadthr
    if [[ "$(uname -s 2>/dev/null)" == Darwin ]]; then
        load1="$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}')"
    else
        load1="$(awk '{print $1}' /proc/loadavg 2>/dev/null)"
    fi
    cpus="$(io_cpus)"
    if [[ -n "$load1" ]]; then
        per="$(awk -v l="$load1" -v c="$cpus" 'BEGIN{printf "%.3f",(c>0?l/c:l)}')"
        loadthr="$(awk -v b="${WATCHMAN_IO_GUARD_LOAD:-1.5}" -v m="$mult" 'BEGIN{printf "%.3f", b*m}')"
        awk -v p="$per" -v t="$loadthr" 'BEGIN{exit !(p+0 > t+0)}' && return 0
    fi

    # Memory pressure (Darwin: vm_stat + hw.memsize; Linux: /proc/meminfo).
    local memav memtot mempct
    if [[ "$(uname -s 2>/dev/null)" == Darwin ]]; then
        local pages_free page_size=4096
        pages_free="$(vm_stat 2>/dev/null | awk '/^Pages free:/{gsub(/\./,"",$3); print $3}')"
        memtot="$(sysctl -n hw.memsize 2>/dev/null)"
        if [[ -n "$pages_free" && -n "$memtot" && "$memtot" -gt 0 ]]; then
            memav=$(( pages_free * page_size ))
            mempct=$(( memav * 100 / memtot ))
            (( mempct < ${WATCHMAN_IO_GUARD_MEM_PCT:-10} )) && return 0
        fi
    else
        memav="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
        memtot="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
        if [[ -n "$memav" && -n "$memtot" && "$memtot" -gt 0 ]]; then
            mempct=$(( memav * 100 / memtot ))
            (( mempct < ${WATCHMAN_IO_GUARD_MEM_PCT:-10} )) && return 0
        fi
    fi
    return 1
}

io_should_defer_heavy() { io_pressure_high; }

# io_pressure_reason — one-line human explanation (names the actual signal used).
io_pressure_reason() {
    local mult psi role; role="$(_io_role)"; mult="$(_io_role_mult)"
    # Darwin has no /proc — always uses load-average fallback.
    if [[ "$(uname -s 2>/dev/null)" != Darwin ]]; then
        psi="$(_io_psi_some_avg10 /proc/pressure/io 2>/dev/null)"
        if [[ -n "$psi" ]]; then
            echo "role=$role; I/O pressure (PSI some/avg10) ${psi}% (limit $(awk -v b="${WATCHMAN_IO_GUARD_PSI:-20}" -v m="$mult" 'BEGIN{printf "%g", b*m}')%)"
            return
        fi
    fi
    local load1 cpus per
    if [[ "$(uname -s 2>/dev/null)" == Darwin ]]; then
        load1="$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}')"
    else
        load1="$(awk '{print $1}' /proc/loadavg 2>/dev/null)"
    fi
    cpus="$(io_cpus)"
    per="$(awk -v l="${load1:-0}" -v c="$cpus" 'BEGIN{printf "%.2f",(c>0?l/c:l)}')"
    local note="no PSI on this kernel"
    [[ "$(uname -s 2>/dev/null)" == Darwin ]] && note="no PSI on Darwin"
    echo "role=$role; load ${load1:-?}/${cpus} core = ${per}/core (limit $(awk -v b="${WATCHMAN_IO_GUARD_LOAD:-1.5}" -v m="$mult" 'BEGIN{printf "%.2f",b*m}')/core), $note"
}

# io_measure <cmd...> — run politely (via io_run) AND record watchman's own cost.
# Sets WATCHMAN_LAST_SECS (wall seconds) and WATCHMAN_LAST_IO (filesystem in/out,
# 512B blocks — only when GNU time is available). Stdout of the command passes through.
io_measure() {
    local gtime="" tmp start end rc=0
    command -v /usr/bin/time >/dev/null 2>&1 && gtime=/usr/bin/time
    [[ -z "$gtime" ]] && command -v gtime >/dev/null 2>&1 && gtime=gtime
    WATCHMAN_LAST_SECS=0; WATCHMAN_LAST_IO=""
    start="$(date +%s)"
    if [[ -n "$gtime" ]]; then
        tmp="$(mktemp)"
        io_run "$gtime" -v -o "$tmp" "$@" || rc=$?
        WATCHMAN_LAST_IO="$(awk -F': ' '
            /File system inputs/{i=$2} /File system outputs/{o=$2}
            END{ if(i!=""||o!="") printf "%d in / %d out (512B blk)", i+0, o+0 }' "$tmp" 2>/dev/null)"
        rm -f "$tmp"
    else
        io_run "$@" || rc=$?
    fi
    end="$(date +%s)"
    WATCHMAN_LAST_SECS=$(( end - start ))
    return $rc
}

# io_footprint_over_budget — TRUE if the last io_measure'd check exceeded the budget.
io_footprint_over_budget() {
    awk -v s="${WATCHMAN_LAST_SECS:-0}" -v b="${WATCHMAN_CHECK_TIME_BUDGET:-120}" 'BEGIN{exit !(s+0 > b+0)}'
}

# io_footprint_summary — human one-liner for the self_footprint finding.
io_footprint_summary() {
    local s="${WATCHMAN_LAST_SECS:-0}"
    if [[ -n "${WATCHMAN_LAST_IO:-}" ]]; then echo "${s}s, ${WATCHMAN_LAST_IO}"; else echo "${s}s"; fi
}
