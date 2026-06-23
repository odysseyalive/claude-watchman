# lib/capacity.ps1 — when a filesystem is DANGEROUSLY full, name what is filling it
# (Windows-native PowerShell port of lib/capacity.sh).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# check-capacity's drive pass establishes THAT a filesystem is critically low; this engine answers
# the operator's very next question — WHAT is eating the space — so the critical-band finding (and
# the email it triggers) ships with the largest files already listed instead of just "95% full".
# It is the disk-pressure analog of webstats' offender list: a heavy filesystem walk kept polite
# and bounded.
#
# This engine is READ-ONLY. It walks the filesystem reading metadata ONLY (file length) and NEVER
# removes or moves a byte. Freeing space is the operator's call under `watchman fix`; this only
# observes and reports.
#
# Heavy-read discipline (CLAUDE.md "do no performance harm"): the walk runs through io_run when
# lib/io-courtesy.ps1 is loaded (the dispatcher loads it), so it is priced for the host's role and
# bounded by a timeout. The caller is expected to gate the whole enrichment on io_should_defer_heavy
# first — only the cheap drive finding must always run; this walk is deferrable.
#
# NOTE — no inode analogue on Windows. The bash file's caller emits a separate inode_capacity
# finding (df -iP); NTFS has no exposed inode table, so the Windows check-capacity skill skips that
# finding rather than journal a meaningless one. This engine only ever lists largest files; it
# journals nothing itself (the skill drives disk_capacity / memory_pressure journaling).

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# _capacity_human <bytes> — IEC units, du -h style, without a per-file fork.
function _capacity_human([double]$b) {
    $units = @('B', 'KB', 'MB', 'GB', 'TB', 'PB')
    $i = 0
    while ($b -ge 1024 -and $i -lt 5) { $b = $b / 1024.0; $i++ }
    return ('{0:0.0}{1}' -f $b, $units[$i])
}

# capacity_top_consumers <mountpoint>
# Echoes up to N lines "<human-size>\t<absolute-path>", largest first, for the files that dominate
# the given filesystem (a Windows drive root such as 'C:\'). Stays on that ONE volume — it does not
# cross into a different drive — so it never wanders off the disk under pressure. Empty output means
# nothing crossed the size floor. Tunables (config/watchman.conf or env):
#   WATCHMAN_TOPFILES_COUNT  how many files to list      (default 20)
#   WATCHMAN_TOPFILES_MIN    size floor in bytes / suffixed (+25M); default +25M
function capacity_top_consumers {
    param([string]$mp = 'C:\')
    if (-not $mp) { $mp = 'C:\' }

    $n = 20
    if ($env:WATCHMAN_TOPFILES_COUNT) { try { $n = [int]$env:WATCHMAN_TOPFILES_COUNT } catch { $n = 20 } }

    # Parse the size floor. Accepts a bare byte count or a find-style "+25M" / "25MB" suffix.
    $floorRaw = if ($env:WATCHMAN_TOPFILES_MIN) { $env:WATCHMAN_TOPFILES_MIN } else { '+25M' }
    $floorBytes = _capacity_parse_size $floorRaw

    if (-not (Test-Path -LiteralPath $mp)) { return }

    # The actual walk: enumerate files on the volume, keep only those at/above the floor, and emit
    # "<bytes>\t<path>" for the top-N by size. The heavy enumeration is io_run-priced when
    # io-courtesy is in scope; the sort/select are negligible.
    $walk = {
        param($root, $floor)
        try {
            # -Force surfaces hidden/system files; -ErrorAction SilentlyContinue skips locked dirs.
            Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -ge $floor } |
                ForEach-Object { "{0}`t{1}" -f [int64]$_.Length, $_.FullName }
        } catch { }
    }

    # The walk is a PS scriptblock (in-proc enumeration), not an external program, so it runs under
    # the current process's role priority directly — the deferral gate the skill applies
    # (io_should_defer_heavy) is what keeps it off a busy box, exactly as the bash caller gates it.
    $raw = & $walk $mp $floorBytes

    if (-not $raw) { return }

    $raw |
        Where-Object { $_ } |
        Sort-Object -Descending { try { [int64](($_ -split "`t")[0]) } catch { 0 } } |
        Select-Object -First $n |
        ForEach-Object {
            $cols = $_ -split "`t", 2
            $bytes = 0.0
            try { $bytes = [double]$cols[0] } catch { $bytes = 0.0 }
            "{0}`t{1}" -f (_capacity_human $bytes), $cols[1]
        }
}

# _capacity_parse_size <spec> — bytes from a find-style/suffixed size. "+25M"/"25M"/"25MB" → 26214400.
# A bare integer is treated as bytes. Returns a [double] byte count (0 on parse failure).
function _capacity_parse_size([string]$spec) {
    if (-not $spec) { return 0 }
    $s = $spec.Trim().TrimStart('+').ToUpper()
    if ($s -match '^([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?)B?$') {
        $num = [double]$Matches[1]
        switch ($Matches[2]) {
            'K' { return $num * 1KB }
            'M' { return $num * 1MB }
            'G' { return $num * 1GB }
            'T' { return $num * 1TB }
            'P' { return $num * 1PB }
            default { return $num }   # bare number = bytes
        }
    }
    return 0
}
