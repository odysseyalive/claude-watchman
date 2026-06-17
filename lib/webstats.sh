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

# Stream the (possibly .gz) access logs to stdout.
webstats_cat_logs() {
    local f
    while IFS= read -r f; do
        [[ -e "$f" ]] || continue
        case "$f" in
            *.gz) zcat -- "$f" 2>/dev/null ;;
            *)    cat  -- "$f" 2>/dev/null ;;
        esac
    done < <(webstats_access_logs)
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
    function mnum(m){ return index("JanFebMarAprMayJunJulAugSepOctNovDec", m)/3 + 1 - 1 }
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
