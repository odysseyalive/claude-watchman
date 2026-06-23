# lib/webstats.ps1 — privacy-respecting web-traffic statistics from server logs (Windows port).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# The reusable parsing engine behind `/watchman stats`. It reads the web access logs (discovered via
# lib/distro.ps1's webserver_log_paths), computes traffic aggregates, and prints a human-readable
# report. On Windows the primary log format is IIS W3C (space-separated fields; a header line
# beginning '#Fields:' names the columns; the client IP is the c-ip column). The classic
# nginx/apache combined-log format is also handled when those servers run on Windows.
#
# PRIVACY MODEL (the point of the feature — a GDPR-friendly alternative to third-party analytics):
#   * The client IP is used ONLY transiently, in memory, as a hashtable key, to CORRELATE visits —
#     so one visitor reloading a page does not skew page views or visitor counts. It is NEVER
#     written to disk, never hashed-and-stored, never printed. The report is ONLY anonymous aggregates.
#   * No cookies, no third parties, no JavaScript beacon — the data comes from the logs the server
#     already keeps for security. Nothing leaves the host.
#   * A SECURITY use (a DDoS/abuse rate finding) legitimately needs the real offending IP to propose
#     a firewall rule — that is a DIFFERENT path (defending the system) and is NOT this report.
#
# This file is READ-ONLY: it reads logs and prints a report (or emits TSV finding-candidates). It
# writes nothing, changes no config, and never touches the firewall. Acting on a finding (e.g.
# blocking an IP) is the operator-run fixer's job under the risk tiers — never here.

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# Run a (heavy) read through io_run when lib/io-courtesy.ps1 is loaded, so a large log scan never
# competes with a busy server's real workload; otherwise run it directly. Mirrors the bash _wc helper.
function _ws_io {
    param([Parameter(ValueFromRemainingArguments = $true)][object[]]$cmd)
    if (Get-Command io_run -ErrorAction SilentlyContinue) {
        return (io_run @cmd)
    }
    $exe = $cmd[0]
    $rest = if ($cmd.Count -gt 1) { $cmd[1..($cmd.Count - 1)] } else { @() }
    return (& $exe @rest)
}

# --- Log file discovery -----------------------------------------------------
# Echo the access-log FILES (current + rotated/.gz) across every discovered web-server log dir.
# On IIS the access logs are the W3SVC*/u_ex*.log (and .gz) trees; nginx/apache use access*.log.
# Excludes error logs and the IIS HTTPERR trail.
function webstats_access_logs {
    $dirs = @()
    if (Get-Command webserver_log_paths -ErrorAction SilentlyContinue) {
        try { $dirs = @(webserver_log_paths) } catch { $dirs = @() }
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($dir in $dirs) {
        if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { continue }
        $files = @()
        try {
            # IIS W3C logs (W3SVC<n>\u_ex*.log) plus classic access*.log, current + rotated + .gz.
            $files = Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)(u_ex.*|.*access.*)\.(log|gz)(\.\d+)?$' -or $_.Name -match '(?i)access_log' }
        } catch { $files = @() }
        foreach ($f in $files) {
            $p = $f.FullName
            if ($p -match '(?i)(error|httperr)') { continue }
            if ($seen.Add($p)) { $p }
        }
    }
}

# The LIVE (currently-growing) access logs only — no rotated/.gz. IIS rolls daily by filename, so
# the live file is the newest u_ex*.log per W3SVC dir; nginx/apache use the bare access*.log.
function webstats_current_logs {
    $dirs = @()
    if (Get-Command webserver_log_paths -ErrorAction SilentlyContinue) {
        try { $dirs = @(webserver_log_paths) } catch { $dirs = @() }
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($dir in $dirs) {
        if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { continue }
        try {
            # nginx/apache live files
            $plain = Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)^access(_log)?\.log$' -and $_.Name -notmatch '(?i)error' }
            foreach ($f in $plain) { if ($seen.Add($f.FullName)) { $f.FullName } }
            # IIS: newest u_ex*.log per site directory is the live one.
            $sites = Get-ChildItem -LiteralPath $dir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)^W3SVC' }
            foreach ($s in $sites) {
                $newest = Get-ChildItem -LiteralPath $s.FullName -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '(?i)^u_ex.*\.log$' } |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($newest -and $seen.Add($newest.FullName)) { $newest.FullName }
            }
            # IIS logs sometimes sit directly under the dir (no per-site subdir).
            $direct = Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)^u_ex.*\.log$' } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($direct -and $seen.Add($direct.FullName)) { $direct.FullName }
        } catch {}
    }
}

# Stream the (possibly .gz) access logs as raw text lines — the FULL set. Used by `/watchman stats`,
# which wants a complete picture.
function webstats_cat_logs {
    foreach ($f in (webstats_access_logs)) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        try {
            if ($f -match '(?i)\.gz$') { _ws_io '_ws_read_gz' $f } else { _ws_io 'Get-Content' '-LiteralPath' $f }
        } catch {}
    }
}

# Decompress and stream a .gz log to text (used by _ws_io as a named "command").
function _ws_read_gz {
    param([string]$path)
    try {
        $fs = [System.IO.File]::OpenRead($path)
        $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
        $sr = New-Object System.IO.StreamReader($gz)
        while ($null -ne ($line = $sr.ReadLine())) { $line }
    } catch {} finally {
        if ($sr) { $sr.Dispose() }
        if ($gz) { $gz.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
}

# Where the per-log read offsets are remembered (gitignored local state).
function webstats_offset_file {
    $root = if ($env:WATCHMAN_ROOT) { $env:WATCHMAN_ROOT } else { Split-Path -Parent $PSScriptRoot }
    return (Join-Path $root 'journal/log-offsets.txt')
}

# webstats_cat_logs_incremental — emit only the NEW bytes of each LIVE access log since the last
# pass, then advance the stored offset, so the loop's read is bounded to traffic-since-last-pass.
#   * Same file (identity unchanged) and grown  -> read [offset, end] only.
#   * Rotated (identity changed) or truncated (size < offset) -> read from 0, and reset.
# Offsets persist in journal/log-offsets.txt as TSV: <path>\t<identity>\t<size>. On Windows there is
# no inode, so we fingerprint identity as "<CreationTimeUtc ticks>:<size at last pass via record>" —
# the CreationTime changes when IIS starts a new file, which is the rotation signal we need.
function webstats_cat_logs_incremental {
    $ofile = webstats_offset_file
    $offId = @{}; $offSize = @{}
    if (Test-Path -LiteralPath $ofile) {
        try {
            foreach ($ln in (Get-Content -LiteralPath $ofile -ErrorAction SilentlyContinue)) {
                $parts = $ln -split "`t"
                if ($parts.Count -ge 3 -and $parts[0]) { $offId[$parts[0]] = $parts[1]; $offSize[$parts[0]] = $parts[2] }
            }
        } catch {}
    }
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($f in (webstats_current_logs)) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $fi = $null
        try { $fi = Get-Item -LiteralPath $f -ErrorAction Stop } catch { continue }
        $ident = ''
        try { $ident = [string]$fi.CreationTimeUtc.Ticks } catch { $ident = '' }
        $size = [int64]$fi.Length
        $start = 0L
        if ($offId.ContainsKey($f) -and $offId[$f] -eq $ident -and $offSize.ContainsKey($f)) {
            $prev = 0L; [int64]::TryParse([string]$offSize[$f], [ref]$prev) | Out-Null
            if ($size -ge $prev) { $start = $prev }
        }
        if ($size -gt $start) {
            try {
                $fs = [System.IO.File]::Open($f, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                [void]$fs.Seek($start, [System.IO.SeekOrigin]::Begin)
                $sr = New-Object System.IO.StreamReader($fs)
                while ($null -ne ($line = $sr.ReadLine())) { $line }
            } catch {} finally {
                if ($sr) { $sr.Dispose() }
                if ($fs) { $fs.Dispose() }
            }
        }
        $records.Add(("{0}`t{1}`t{2}" -f $f, $ident, $size))
    }
    # Atomically replace the offset state (last-writer-wins; offsets are advisory).
    try {
        $tmp = "$ofile.tmp.$PID"
        Set-Content -LiteralPath $tmp -Value $records -Encoding utf8 -ErrorAction Stop
        Move-Item -LiteralPath $tmp -Destination $ofile -Force -ErrorAction Stop
    } catch {
        try { if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } } catch {}
    }
}

# --- Parsing ----------------------------------------------------------------
# Detect, line-by-line, which format a record is and yield a normalized parsed object:
#   @{ ip; sortkey; day; method; path; status; bytes; ref; ua; bot }
# Handles BOTH the IIS W3C format (space-separated, header-named columns) and the nginx/apache
# combined log format. W3C #Fields: header lines are tracked to map column positions.

$script:_WS_BOT_RX = '(?i)bot|crawl|spider|slurp|bingpreview|facebookexternalhit|mediapartners|curl|wget|python-requests|go-http|libwww|httpclient|monitor|uptime|pingdom|headless|phantom|scan|nikto|sqlmap|masscan|zgrab'
$script:_WS_ASSET_RX = '(?i)\.(css|js|mjs|png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|otf|map|mp4|webm|mp3|pdf|zip|gz|woff|txt|xml|json)$'
$script:_WS_MONTHS = @{ Jan = 1; Feb = 2; Mar = 3; Apr = 4; May = 5; Jun = 6; Jul = 7; Aug = 8; Sep = 9; Oct = 10; Nov = 11; Dec = 12 }

function _ws_isbot([string]$ua) { return ($ua -match $script:_WS_BOT_RX) }
function _ws_isasset([string]$p) { $q = $p -replace '\?.*', ''; return ($q -match $script:_WS_ASSET_RX) }

# Parse a stream of log lines into normalized hashtables. $LineStream is an array/enumerable of lines.
function _ws_parse_stream {
    param([object[]]$LineStream)
    $fields = $null   # current W3C column index map, set by a '#Fields:' header
    foreach ($line in $LineStream) {
        if ($null -eq $line) { continue }
        $line = [string]$line
        if ($line.Length -eq 0) { continue }

        # IIS W3C directive lines: '#Fields: date time s-ip cs-method ... c-ip ...'
        if ($line[0] -eq '#') {
            if ($line -match '(?i)^#Fields:\s*(.+)$') {
                $cols = ($Matches[1].Trim() -split '\s+')
                $fields = @{}
                for ($i = 0; $i -lt $cols.Count; $i++) { $fields[$cols[$i]] = $i }
            }
            continue
        }

        if ($fields -and ($line -notmatch '"')) {
            # --- IIS W3C record (space-separated, no quotes) ---
            $t = $line -split '\s+'
            function _g([string]$col) { if ($fields.ContainsKey($col) -and $fields[$col] -lt $t.Count) { return $t[$fields[$col]] } else { return '' } }
            $ip = _g 'c-ip'
            $d = _g 'date'        # YYYY-MM-DD
            if (-not $d) { continue }
            $method = _g 'cs-method'
            $path = _g 'cs-uri-stem'
            $status = _g 'sc-status'
            $bytesRaw = _g 'sc-bytes'
            $ref = _g 'cs(Referer)'
            $ua = _g 'cs(User-Agent)'
            $sortkey = ($d -replace '-', '')
            $human = $d
            # W3C 'time' is UTC HH:MM:SS — keep HHMM for per-minute rate bucketing.
            $tm = _g 'time'
            $minute = if ($tm -match '^(\d{2}):(\d{2})') { "$($Matches[1])$($Matches[2])" } else { '0000' }
            $bytes = 0; [int]::TryParse(($bytesRaw -replace '[^\d]', ''), [ref]$bytes) | Out-Null
            $ua = ($ua -replace '\+', ' ')
            $ref = ($ref -replace '\+', ' ')
            if ($path) { $path = $path -replace '\?.*', '' }
        } else {
            # --- nginx/apache combined/common log (quote-delimited) ---
            $q = $line -split '"'
            if ($q.Count -lt 3) { continue }
            $h = $q[0] -split '\s+'
            $ip = $h[0]
            $dtl = if ($h.Count -ge 4) { $h[3] } else { '' }
            $dtl = $dtl -replace '\[', ''
            $dd = $dtl -split ':'
            $day = $dd[0]            # DD/Mon/YYYY
            if (-not $day) { continue }
            $rq = $q[1] -split '\s+'
            $method = $rq[0]; $path = if ($rq.Count -ge 2) { $rq[1] } else { '' }
            $sb = ($q[2].Trim()) -split '\s+'
            $status = $sb[0]; $bytes = 0; if ($sb.Count -ge 2) { [int]::TryParse(($sb[1] -replace '[^\d]', ''), [ref]$bytes) | Out-Null }
            $ref = if ($q.Count -ge 4) { $q[3] } else { '' }
            $ua = if ($q.Count -ge 6) { $q[5] } else { '' }
            if ($path) { $path = $path -replace '\?.*', '' }
            # sortable YYYYMMDD from DD/Mon/YYYY
            $p2 = $day -split '/'
            $dom = 0; $yr = 0; [int]::TryParse($p2[0], [ref]$dom) | Out-Null
            $mon = if ($p2.Count -ge 2 -and $script:_WS_MONTHS.ContainsKey($p2[1])) { $script:_WS_MONTHS[$p2[1]] } else { 0 }
            if ($p2.Count -ge 3) { [int]::TryParse($p2[2], [ref]$yr) | Out-Null }
            $sortkey = '{0:D4}{1:D2}{2:D2}' -f $yr, $mon, $dom
            $human = $day
            # combined-log time is DD/Mon/YYYY:HH:MM:SS — dd[1]=HH, dd[2]=MM.
            $hh = if ($dd.Count -ge 2 -and $dd[1] -match '^\d{2}$') { $dd[1] } else { '00' }
            $mm = if ($dd.Count -ge 3 -and $dd[2] -match '^\d{2}$') { $dd[2] } else { '00' }
            $minute = "$hh$mm"
        }

        [pscustomobject]@{
            ip = $ip; sortkey = $sortkey; day = $human; minute = $minute; method = $method; path = $path
            status = [string]$status; bytes = [int]$bytes; ref = $ref; ua = $ua; bot = (_ws_isbot $ua)
        }
    }
}

# Aggregate a stream of log lines into a result object the report renders. Mirrors the awk pass:
# the IP is a transient in-memory correlation key only, never stored or printed.
function _ws_aggregate {
    param([object[]]$LineStream)
    $total = 0; $pv = 0; $bots = 0; $bytesTot = [int64]0; $visitors = 0
    $mindate = ''; $maxdate = ''; $minday = ''; $maxday = ''
    $st = @{}; $daycount = @{}; $dayhuman = @{}; $pvpath = @{}; $upath = @{}; $refc = @{}
    $seenIp = @{}; $seenPathIp = @{}

    foreach ($r in (_ws_parse_stream $LineStream)) {
        if (-not $r.sortkey) { continue }
        if (-not $mindate -or $r.sortkey -lt $mindate) { $mindate = $r.sortkey; $minday = $r.day }
        if ($r.sortkey -gt $maxdate) { $maxdate = $r.sortkey; $maxday = $r.day }
        $total++
        $bytesTot += $r.bytes
        if ($daycount.ContainsKey($r.sortkey)) { $daycount[$r.sortkey]++ } else { $daycount[$r.sortkey] = 1 }
        $dayhuman[$r.sortkey] = $r.day
        if ($r.status) { if ($st.ContainsKey($r.status)) { $st[$r.status]++ } else { $st[$r.status] = 1 } }
        if ($r.bot) { $bots++ }

        if (-not $r.bot) {
            if (-not $seenIp.ContainsKey($r.ip)) { $seenIp[$r.ip] = 1; $visitors++ }
        }
        if (-not $r.bot -and $r.method -eq 'GET' -and $r.status -match '^[23]' -and -not (_ws_isasset $r.path)) {
            $pv++
            if ($pvpath.ContainsKey($r.path)) { $pvpath[$r.path]++ } else { $pvpath[$r.path] = 1 }
            $k = "$($r.path)`u{241F}$($r.ip)"
            if (-not $seenPathIp.ContainsKey($k)) { $seenPathIp[$k] = 1; if ($upath.ContainsKey($r.path)) { $upath[$r.path]++ } else { $upath[$r.path] = 1 } }
        }
        if (-not $r.bot -and $r.ref -and $r.ref -ne '-' -and $r.ref -notmatch '(?i)^https?://[^/]*localhost') {
            if ($refc.ContainsKey($r.ref)) { $refc[$r.ref]++ } else { $refc[$r.ref] = 1 }
        }
    }

    return [pscustomobject]@{
        total = $total; pv = $pv; bots = $bots; bytes = $bytesTot; visitors = $visitors
        minday = $minday; maxday = $maxday
        st = $st; daycount = $daycount; dayhuman = $dayhuman; pvpath = $pvpath; upath = $upath; refc = $refc
    }
}

function _ws_human_bytes([double]$b) {
    $u = @('B', 'KB', 'MB', 'GB', 'TB'); $i = 0
    while ($b -ge 1024 -and $i -lt 4) { $b /= 1024; $i++ }
    return ('{0:N1} {1}' -f $b, $u[$i])
}

# Print the full report. Optional $src = a single log file to analyze instead of the discovered set.
function webstats_report {
    param([string]$src = '')
    $lines = $null
    if ($src -and (Test-Path -LiteralPath $src)) {
        if ($src -match '(?i)\.gz$') { $lines = @(_ws_read_gz $src) } else { $lines = @(Get-Content -LiteralPath $src -ErrorAction SilentlyContinue) }
    } else {
        $lines = @(webstats_cat_logs)
    }
    $agg = _ws_aggregate $lines

    if (-not $agg -or $agg.total -le 0) {
        $where = ''
        if (Get-Command webserver_log_paths -ErrorAction SilentlyContinue) { try { $where = (@(webserver_log_paths) -join ' ') } catch {} }
        'watchman stats: no parseable access-log data found.'
        "  Looked in: $where"
        '  (No web server, empty logs, or a non-standard log format.)'
        return
    }

    $humanBytes = _ws_human_bytes ([double]$agg.bytes)
    $botPct = if ($agg.total -gt 0) { [int]($agg.bots * 100 / $agg.total) } else { 0 }

    'claude-watchman — web traffic stats (privacy-respecting; from server logs)'
    "Range: $($agg.minday -as [string]) -> $($agg.maxday -as [string])    (IPs correlated in memory only, never stored or shown)"
    ''
    '  Page views (human):   {0}' -f $agg.pv
    '  Unique visitors:      {0}' -f $agg.visitors
    '  Total requests:       {0}  (bots/crawlers: {1}, {2}%)' -f $agg.total, $agg.bots, $botPct
    '  Bandwidth:            {0}' -f $humanBytes
    ''
    "  Top pages (by unique visitors — dedup'd, so reloads don't skew):"
    $agg.pvpath.Keys |
        Sort-Object { $agg.upath[$_] } -Descending |
        Select-Object -First 15 |
        ForEach-Object { '    {0,6} uniq  {1,6} views  {2}' -f $agg.upath[$_], $agg.pvpath[$_], $_ }
    ''
    '  Top external referrers:'
    $refLines = $agg.refc.Keys | Sort-Object { $agg.refc[$_] } -Descending | Select-Object -First 10 |
        ForEach-Object { '    {0,6}  {1}' -f $agg.refc[$_], $_ }
    if ($refLines) { $refLines } else { '    (none — direct traffic only)' }
    ''
    '  Status codes:'
    $agg.st.Keys | Sort-Object { $agg.st[$_] } -Descending | ForEach-Object { '    {0,6}  {1}' -f $agg.st[$_], $_ }
    ''
    '  Daily trend (requests/day):'
    $agg.daycount.Keys | Sort-Object | ForEach-Object { '    {0}  {1,6}' -f $agg.dayhuman[$_], $agg.daycount[$_] }
}

# --- SECURITY PATH: request-rate offenders (DDoS/abuse) ----------------------
# DIFFERENT legal basis from the analytics above: defending the system. This one deliberately KEEPS
# the real source IP, because you cannot firewall-block a hash — the offending IP has to be named in
# the proposed rule. inspect-logs consumes this to journal a `security` finding; the operator-run
# fixer applies the block under the risk tiers (review). Detection only — NEVER blocks here.
#
# Emits one TSV line per source whose PEAK requests-in-a-single-minute reaches the threshold:
#   <ip>\t<peak_per_min>\t<total_in_logs>\t<user_agent_sample>
# $1 = per-minute threshold (default: $WATCHMAN_RATE_PER_MIN, else 300).
function webstats_rate_offenders {
    param([int]$threshold = 0)
    if (-not $threshold) {
        $threshold = if ($env:WATCHMAN_RATE_PER_MIN) { [int]$env:WATCHMAN_RATE_PER_MIN } else { 300 }
    }
    # This runs every loop pass, so read INCREMENTALLY by default — only the new log lines since the
    # last pass. Set WATCHMAN_LOG_INCREMENTAL=no to scan the full logs each time instead.
    $incremental = (($env:WATCHMAN_LOG_INCREMENTAL -eq $null) -or ($env:WATCHMAN_LOG_INCREMENTAL -eq 'yes'))
    if ($incremental -and (Get-Command webstats_cat_logs_incremental -ErrorAction SilentlyContinue)) {
        $lines = @(webstats_cat_logs_incremental)
    } else {
        $lines = @(webstats_cat_logs)
    }

    $cnt = @{}; $tot = @{}; $ua = @{}; $peak = @{}
    foreach ($r in (_ws_parse_stream $lines)) {
        $ip = $r.ip
        if (-not $ip -or -not $r.sortkey) { continue }
        # minute bucket: sortkey (YYYYMMDD) + the time field. W3C carries a 'time' column (HH:MM:SS);
        # the combined-log path lost sub-day time in normalization, so use sortkey for combined and
        # the full timestamp where available. We recover minute granularity from the raw record below.
        $minuteKey = "$($ip)`u{241F}$($r.sortkey)$($r.minute)"
        if ($cnt.ContainsKey($minuteKey)) { $cnt[$minuteKey]++ } else { $cnt[$minuteKey] = 1 }
        if ($tot.ContainsKey($ip)) { $tot[$ip]++ } else { $tot[$ip] = 1 }
        if ($r.ua) { $ua[$ip] = $r.ua }
        $c = $cnt[$minuteKey]
        if (-not $peak.ContainsKey($ip) -or $c -gt $peak[$ip]) { $peak[$ip] = $c }
    }

    $out = foreach ($ip in $peak.Keys) {
        if ($peak[$ip] -ge $threshold) {
            $uaSample = if ($ua.ContainsKey($ip)) { $ua[$ip] } else { '' }
            [pscustomobject]@{ ip = $ip; peak = $peak[$ip]; total = $tot[$ip]; ua = $uaSample }
        }
    }
    $out | Sort-Object peak -Descending | ForEach-Object { "{0}`t{1}`t{2}`t{3}" -f $_.ip, $_.peak, $_.total, $_.ua }
}
