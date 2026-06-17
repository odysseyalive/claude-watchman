#!/usr/bin/env bash
# lib/webstats.sh — privacy-respecting web-traffic statistics from server logs.
#
# The reusable parsing engine behind `/watchman stats`. It reads the web access
# logs (discovered via lib/distro.sh's webserver_log_paths, including rotated and
# .gz files), computes traffic aggregates, and prints a human-readable report.
#
# PRIVACY MODEL (the point of the feature — a GDPR-friendly alternative to
# third-party analytics):
#   * The client IP is used ONLY transiently, in memory, as an awk array key, to
#     CORRELATE visits — so one visitor reloading a page does not skew page views
#     or visitor counts. It is NEVER written to disk, never hashed-and-stored,
#     never printed. The report contains ONLY anonymous aggregates.
#   * No cookies, no third parties, no JavaScript beacon — the data comes from the
#     logs your server already keeps for security. Nothing leaves the host.
#   * A SECURITY use (e.g. a DDoS/abuse rate finding) legitimately needs the real
#     offending IP to propose a firewall rule — that is a DIFFERENT path on a
#     different legal basis (defending the system) and is NOT this report.
#
# > PRIME DIRECTIVE. webstats is READ-ONLY: it reads logs and prints a report. It
# > writes nothing, changes no config, and never touches the firewall. Acting on a
# > finding (e.g. blocking an IP) is the operator-run fixer's job under the risk
# > tiers — never here.

# Echo the access-log FILES (current + rotated + .gz), newest-style first, across
# every discovered web-server log directory. Excludes error logs.
webstats_access_logs() {
    local dir f
    while IFS= read -r dir; do
        [[ -d "$dir" ]] || continue
        # access logs only — nginx access.log*, apache access.log / *access*.
        for f in "$dir"/access.log "$dir"/access_log "$dir"/*access*.log \
                 "$dir"/access.log.* "$dir"/access_log.* "$dir"/*access*.log.* ; do
            [[ -e "$f" ]] || continue
            case "$f" in *error*) continue ;; esac
            printf '%s\n' "$f"
        done
    done < <(webserver_log_paths 2>/dev/null) | awk '!seen[$0]++'
}

# Stream the (possibly .gz) access logs to stdout — the FULL set (current + rotated
# + .gz). Used by `/watchman stats`, which wants a complete picture. When
# lib/io-courtesy.sh is sourced, the (heavy) reads run at the role's I/O priority so
# a large scan never competes with a busy server's real workload.
webstats_cat_logs() {
    local f
    _wc() { if declare -F io_run >/dev/null 2>&1; then io_run "$@"; else "$@"; fi; }
    while IFS= read -r f; do
        [[ -e "$f" ]] || continue
        case "$f" in
            *.gz) _wc zcat -- "$f" 2>/dev/null ;;
            *)    _wc cat  -- "$f" 2>/dev/null ;;
        esac
    done < <(webstats_access_logs)
}

# The LIVE (currently-growing) access logs only — no rotated `.N` / `.gz` (the glob
# requires a trailing `.log`, so access.log.1 / access.log.gz are excluded).
webstats_current_logs() {
    local dir f
    while IFS= read -r dir; do
        [[ -d "$dir" ]] || continue
        for f in "$dir"/access.log "$dir"/access_log "$dir"/*access*.log; do
            [[ -f "$f" ]] || continue
            case "$f" in *error*) continue ;; esac
            printf '%s\n' "$f"
        done
    done < <(webserver_log_paths 2>/dev/null) | awk '!seen[$0]++'
}

# Where the per-log read offsets are remembered (gitignored local state).
webstats_offset_file() { echo "${WATCHMAN_ROOT:-.}/journal/log-offsets.txt"; }

# webstats_cat_logs_incremental — emit only the NEW bytes of each LIVE access log
# since the last pass, then advance the stored offset. This bounds the loop's read
# to traffic-since-last-pass instead of the whole log every time.
#
#   * Same file (inode unchanged) and grown → read [offset, end] only.
#   * Rotated (inode changed) or truncated (size < offset) → read the current file
#     from 0 this pass, and reset. Rotated `.N`/`.gz` history is NOT re-read (the
#     loop already saw it while it was live). One small caveat: the handful of lines
#     written between the last pass and a rotation can be missed by the incremental
#     path — `/watchman stats` (full read) is always complete, so use it for an
#     authoritative report.
#
# Offsets persist in journal/log-offsets.txt as TSV: <path> <inode> <size>.
webstats_cat_logs_incremental() {
    local ofile tmp f inode size start
    local -A OFF_INODE=() OFF_SIZE=()
    _wc() { if declare -F io_run >/dev/null 2>&1; then io_run "$@"; else "$@"; fi; }
    ofile="$(webstats_offset_file)"
    if [[ -r "$ofile" ]]; then
        local k i s
        while IFS=$'\t' read -r k i s; do
            [[ -n "$k" ]] && { OFF_INODE["$k"]="$i"; OFF_SIZE["$k"]="$s"; }
        done < "$ofile"
    fi
    tmp="$(mktemp)"
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        inode="$(stat -c%i "$f" 2>/dev/null)"; size="$(stat -c%s "$f" 2>/dev/null)"
        [[ -n "$inode" && -n "$size" ]] || continue
        start=0
        if [[ "${OFF_INODE[$f]:-}" == "$inode" && -n "${OFF_SIZE[$f]:-}" && "$size" -ge "${OFF_SIZE[$f]}" ]]; then
            start="${OFF_SIZE[$f]}"
        fi
        (( size > start )) && _wc tail -c "+$(( start + 1 ))" -- "$f" 2>/dev/null
        printf '%s\t%s\t%s\n' "$f" "$inode" "$size" >> "$tmp"
    done < <(webstats_current_logs)
    # Atomically replace the offset state (last-writer-wins; offsets are advisory).
    mv -f "$tmp" "$ofile" 2>/dev/null || rm -f "$tmp"
}

# Compute the aggregates with awk. Emits TSV records consumed by webstats_report:
#   T  total_requests  pageviews  bot_requests  bytes  unique_visitors  mindate  maxdate
#   P  pageviews  unique_visitors  path
#   R  count  referrer
#   S  count  status
#   D  sortkey  count  human_day
_webstats_awk() {
    awk '
    function asset(p,   q){ q=p; sub(/\?.*/,"",q);
        return (q ~ /\.(css|js|mjs|png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|otf|map|mp4|webm|mp3|pdf|zip|gz|woff|txt|xml|json)$/) }
    function isbot(u){ return (tolower(u) ~ /bot|crawl|spider|slurp|bingpreview|facebookexternalhit|mediapartners|curl|wget|python-requests|go-http|libwww|httpclient|monitor|uptime|pingdom|headless|phantom|scan|nikto|sqlmap|masscan|zgrab/) }
    function mnum(m){ return (index("JanFebMarAprMayJunJulAugSepOctNovDec", m)-1)/3 + 1 }
    {
        # Portable combined/common-log parse by splitting on the quote char.
        n = split($0, q, "\"")
        if (n < 3) next
        split(q[1], h, " ")
        ip = h[1]
        dtl = h[4]; gsub(/\[/, "", dtl); split(dtl, dd, ":"); day = dd[1]    # DD/Mon/YYYY
        if (day == "") next
        split(q[2], rq, " "); method = rq[1]; path = rq[2]
        split(q[3], sb, " "); status = sb[1]; bytes = sb[2] + 0
        ref = (n >= 4 ? q[4] : "")
        ua  = (n >= 6 ? q[6] : "")
        sub(/\?.*/, "", path)                                                # drop query string

        # sortable day key YYYYMMDD from DD/Mon/YYYY
        split(day, p2, "/"); dom = p2[1]; mon = p2[2]; yr = p2[3]
        sortkey = sprintf("%04d%02d%02d", yr+0, mnum(mon), dom+0)
        if (mindate == "" || sortkey < mindate) { mindate = sortkey; minday = day }
        if (sortkey > maxdate) { maxdate = sortkey; maxday = day }

        total++
        bytes_tot += bytes
        daycount[sortkey]++; dayhuman[sortkey] = day
        if (status != "") st[status]++
        bot = isbot(ua)
        if (bot) { bots++ }

        # visitors: distinct IP overall and per day (IP is a transient key only)
        if (!bot) { if (!seen_ip[ip]++) visitors++; seen_day_ip[sortkey SUBSEP ip]++ }

        # page views = human GET of a non-asset, 2xx/3xx
        if (!bot && method == "GET" && status ~ /^[23]/ && !asset(path)) {
            pv++
            pvpath[path]++
            if (!seen_path_ip[path SUBSEP ip]++) upath[path]++
        }
        # referrers (external only)
        if (!bot && ref != "" && ref != "-" && ref !~ /^https?:\/\/[^\/]*localhost/) refc[ref]++
    }
    END {
        printf "T\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", total, pv, bots, bytes_tot, visitors, minday, maxday
        for (p in pvpath)  printf "P\t%d\t%d\t%s\n", pvpath[p], upath[p], p
        for (r in refc)    printf "R\t%d\t%s\n", refc[r], r
        for (s in st)      printf "S\t%d\t%s\n", st[s], s
        for (k in daycount) printf "D\t%s\t%d\t%s\n", k, daycount[k], dayhuman[k]
    }'
}

# Print the full report. Optional $1 = a single log file/dir to analyze instead of
# the discovered set (e.g. one site's access log).
webstats_report() {
    local src="${1:-}"
    local raw
    if [[ -n "$src" && -e "$src" ]]; then
        raw="$( { [[ "$src" == *.gz ]] && zcat -- "$src" || cat -- "$src"; } 2>/dev/null | _webstats_awk )"
    else
        raw="$(webstats_cat_logs | _webstats_awk)"
    fi

    if [[ -z "$raw" || -z "$(printf '%s\n' "$raw" | awk -F'\t' '$1=="T"{print $2}')" ]]; then
        echo "watchman stats: no parseable access-log data found."
        echo "  Looked in: $(webserver_log_paths 2>/dev/null | paste -sd' ' -)"
        echo "  (No web server, empty logs, or a non-standard log format.)"
        return 0
    fi

    local total pv bots bytes_tot visitors minday maxday
    IFS=$'\t' read -r _ total pv bots bytes_tot visitors minday maxday \
        < <(printf '%s\n' "$raw" | awk -F'\t' '$1=="T"')

    local human_bytes; human_bytes="$(awk -v b="$bytes_tot" 'BEGIN{
        u="B KB MB GB TB"; split(u,a," "); i=1; while(b>=1024 && i<5){b/=1024;i++} printf "%.1f %s", b, a[i]}')"
    local bot_pct=0; (( total > 0 )) && bot_pct=$(( bots * 100 / total ))

    echo "claude-watchman — web traffic stats (privacy-respecting; from server logs)"
    echo "Range: ${minday:-?} → ${maxday:-?}    (IPs correlated in memory only, never stored or shown)"
    echo
    printf "  Page views (human):   %d\n" "$pv"
    printf "  Unique visitors:      %d\n" "$visitors"
    printf "  Total requests:       %d  (bots/crawlers: %d, %d%%)\n" "$total" "$bots" "$bot_pct"
    printf "  Bandwidth:            %s\n" "$human_bytes"
    echo
    echo "  Top pages (by unique visitors — dedup'd, so reloads don't skew):"
    printf '%s\n' "$raw" | awk -F'\t' '$1=="P"{printf "    %6d uniq  %6d views  %s\n",$3,$2,$4}' \
        | sort -rn | head -15
    echo
    echo "  Top external referrers:"
    local refs; refs="$(printf '%s\n' "$raw" | awk -F'\t' '$1=="R"{printf "    %6d  %s\n",$2,$3}' | sort -rn | head -10)"
    [[ -n "$refs" ]] && printf '%s\n' "$refs" || echo "    (none — direct traffic only)"
    echo
    echo "  Status codes:"
    printf '%s\n' "$raw" | awk -F'\t' '$1=="S"{printf "    %6d  %s\n",$2,$3}' | sort -rn
    echo
    echo "  Daily trend (requests/day):"
    printf '%s\n' "$raw" | awk -F'\t' '$1=="D"{print $2"\t"$3"\t"$4}' | sort \
        | awk -F'\t' '{printf "    %s  %6d\n",$3,$2}'
}

# --- SECURITY PATH: request-rate offenders (DDoS/abuse) ----------------------
# DIFFERENT legal basis from the analytics above: defending the system. This one
# deliberately KEEPS the real source IP, because you cannot firewall-block a hash
# — the offending IP has to be named in the proposed rule. inspect-logs consumes
# this to journal a `security` finding; the operator-run fixer applies the block
# under the risk tiers (review). Detection only — NEVER blocks here.
#
# Emits one TSV line per source whose PEAK requests-in-a-single-minute reaches the
# threshold:  <ip>\t<peak_per_min>\t<total_in_logs>\t<user_agent_sample>
# $1 = per-minute threshold (default: $WATCHMAN_RATE_PER_MIN, else 300).
webstats_rate_offenders() {
    local th="${1:-${WATCHMAN_RATE_PER_MIN:-300}}"
    # This runs every loop pass, so read INCREMENTALLY by default — only the new log
    # lines since last pass — to keep the footprint proportional to recent traffic.
    # Set WATCHMAN_LOG_INCREMENTAL=no to scan the full logs each time instead.
    local src=webstats_cat_logs
    [[ "${WATCHMAN_LOG_INCREMENTAL:-yes}" == yes ]] && declare -F webstats_cat_logs_incremental >/dev/null \
        && src=webstats_cat_logs_incremental
    "$src" | awk -v THMIN="$th" '
    function mnum(m){ return (index("JanFebMarAprMayJunJulAugSepOctNovDec", m)-1)/3 + 1 }
    {
        n = split($0, q, "\""); if (n < 1) next
        split(q[1], h, " "); ip = h[1]
        dtl = h[4]; gsub(/\[/, "", dtl); split(dtl, dd, ":")   # dd[1]=DD/Mon/YYYY dd[2]=HH dd[3]=MM
        if (ip == "" || dd[1] == "") next
        split(dd[1], p, "/")
        minute = sprintf("%04d%02d%02d%02d%02d", p[3]+0, mnum(p[2]), p[1]+0, dd[2]+0, dd[3]+0)
        c = ++cnt[ip SUBSEP minute]
        tot[ip]++
        if (n >= 6) ua[ip] = q[6]
        if (c > peak[ip]) peak[ip] = c
    }
    END { for (i in peak) if (peak[i] >= THMIN+0) printf "%s\t%d\t%d\t%s\n", i, peak[i], tot[i], ua[i] }
    ' | sort -t"$(printf '\t')" -k2 -rn
}
