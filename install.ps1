#!/usr/bin/env pwsh
# install.ps1 — claude-watchman Windows installer/updater (PowerShell port of install.sh).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > This installer only WRITES product code + create-if-absent config; it never deletes operator
# > data. install == update: re-running manifest-fetches the latest product (NO git) and never
# > touches the gitignored machine state (.env, config, findings.db, .claude).
#
# Run from an elevated (Administrator) PowerShell. First install (one-liner):
#   iwr -useb https://raw.githubusercontent.com/odysseyalive/claude-watchman/main/install.ps1 | iex
# Re-run with -Update from an installed dir to pull the latest product.

[CmdletBinding()]
param(
    [switch]$Update,
    [switch]$Yes,
    [string]$Profile = '',
    [string]$Ref = 'main'
)
$ErrorActionPreference = 'Stop'

$WATCHMAN_REF = if ($env:WATCHMAN_REF) { $env:WATCHMAN_REF } else { $Ref }
$WATCHMAN_RAW = "https://raw.githubusercontent.com/odysseyalive/claude-watchman/$WATCHMAN_REF"

function say  { param($m) Write-Host "==> $m" -ForegroundColor Cyan }
function warn { param($m) Write-Host "[warn] $m" -ForegroundColor Yellow }
function die  { param($m) Write-Host "[fail] $m" -ForegroundColor Red; exit 1 }
function _have([string]$n) { return [bool](Get-Command $n -ErrorAction SilentlyContinue) }

# Resolve our own location. Empty when piped (iwr | iex) — then install into the current dir.
$ROOT = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

function _is_admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { return $false }
}
if (-not (_is_admin)) {
    warn 'Not running elevated. claude-watchman reads system state and the Security event log, which need Administrator. Re-run from an elevated PowerShell for full coverage.'
}

# --- Manifest-driven fetch (NO git) -----------------------------------------
# Fetches every path in manifest.txt from WATCHMAN_RAW into $dest ATOMICALLY: all files land in a
# temp tree first and move into place only after ALL succeed. `keep` files fetched only if absent;
# the `hook` flag (chmod +x on Linux) is a no-op on Windows.
function Invoke-WatchmanFetch([string]$dest) {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wm-fetch-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    say "fetching claude-watchman ($WATCHMAN_REF) -> $dest"
    try {
        $manifest = Join-Path $tmp 'manifest.txt'
        Invoke-WebRequest -UseBasicParsing -Uri "$WATCHMAN_RAW/manifest.txt" -OutFile $manifest
        $lines = Get-Content -LiteralPath $manifest | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^#' }
        # Phase 1 — fetch into the temp tree.
        foreach ($line in $lines) {
            $flag = ''; $path = $line
            if ($line -match '^(keep|hook)\s+(.+)$') { $flag = $Matches[1]; $path = $Matches[2] }
            if ($flag -eq 'keep' -and (Test-Path -LiteralPath (Join-Path $dest $path))) { continue }
            $tp = Join-Path $tmp $path
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $tp) | Out-Null
            Invoke-WebRequest -UseBasicParsing -Uri "$WATCHMAN_RAW/$path" -OutFile $tp
        }
        # Phase 2 — move into place; keep manifest.txt on disk for `update --check`.
        Copy-Item -LiteralPath $manifest -Destination (Join-Path $dest 'manifest.txt') -Force
        foreach ($line in $lines) {
            $path = $line
            if ($line -match '^(keep|hook)\s+(.+)$') { $path = $Matches[2] }
            $tp = Join-Path $tmp $path
            if (-not (Test-Path -LiteralPath $tp)) { continue }   # keep-skipped
            $dp = Join-Path $dest $path
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dp) | Out-Null
            Move-Item -LiteralPath $tp -Destination $dp -Force
        }
    } finally {
        if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    }
}

# Fetch when running detached (no lib yet) OR on -Update. A dev checkout with lib present and no
# -Update skips the fetch and uses local files.
if ((-not (Test-Path (Join-Path $ROOT 'lib/distro.ps1'))) -or $Update) {
    Invoke-WatchmanFetch $ROOT
}

$env:WATCHMAN_ROOT = $ROOT
. (Join-Path $ROOT 'lib/wm.mutators.ps1')
. (Join-Path $ROOT 'lib/wm.common.ps1')
. (Join-Path $ROOT 'lib/journal.ps1')
. (Join-Path $ROOT 'lib/distro.ps1')
. (Join-Path $ROOT 'lib/profile.ps1')

$assumeYes = $Yes -or $Update

# --- Evidence-based profile guess (read-only, no AI, no network) ------------
function _profile_guess {
    $score = 0; $reasons = @()
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ($os.ProductType -ne 1) { $score += 3; $reasons += 'Windows Server SKU' }
    } catch {}
    try {
        $pub = Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') -and $_.LocalPort -in @(22, 25, 80, 443, 3306, 5432, 3389) }
        if ($pub) { $score += 2; $reasons += "public listeners: $(($pub.LocalPort | Sort-Object -Unique) -join ',')" }
    } catch {}
    try { if (Get-CimInstance Win32_Battery -ErrorAction Stop) { $score -= 2; $reasons += 'battery present (laptop)' } } catch {}
    $guess = if ($score -gt 0) { 'server' } else { 'workstation' }
    return @{ guess = $guess; reasons = ($reasons -join '; ') }
}

$fam = watchman_family
say "family: $fam"
if (-not $Profile) {
    $g = _profile_guess
    $Profile = $g.guess
    say "profile: $Profile  ($($g.reasons))"
} else {
    say "profile: $Profile (operator-specified)"
}

# --- Dependencies -----------------------------------------------------------
# sqlite3 is required (the journal). jq is NOT needed (PowerShell has ConvertFrom-Json).
if (-not (_have 'sqlite3') -and -not (Test-Path (Join-Path $ROOT 'bin/sqlite3.exe'))) {
    if (_have 'winget') {
        say 'installing sqlite3 via winget…'
        try { winget install --id SQLite.SQLite --accept-source-agreements --accept-package-agreements -e } catch { warn "winget sqlite install failed: $($_.Exception.Message)" }
    }
    if (-not (_have 'sqlite3') -and -not (Test-Path (Join-Path $ROOT 'bin/sqlite3.exe'))) {
        warn 'sqlite3 not found. Install it (winget install SQLite.SQLite) or place sqlite3.exe at bin\sqlite3.exe — the journal needs it.'
    }
}
if (-not (_have 'claude')) { warn 'the Claude Code CLI (claude) is not on PATH — install it before running the session verbs.' }
if (-not (_have 'cscli'))  { say 'CrowdSec (cscli) not detected — optional; inspect-logs uses it when present.' }

# --- config / .env / .gitignore / journal -----------------------------------
$confExample = Join-Path $ROOT 'config/watchman.conf.example'
$conf = Join-Path $ROOT 'config/watchman.conf'
if ((Test-Path $confExample) -and -not (Test-Path $conf)) {
    (Get-Content -Raw $confExample) -replace '(?m)^\s*WATCHMAN_PROFILE\s*=.*$', "WATCHMAN_PROFILE=$Profile" |
        Set-Content -LiteralPath $conf
    say "wrote config/watchman.conf (profile=$Profile)"
}

$envExample = Join-Path $ROOT '.env.example'
$envFile = Join-Path $ROOT '.env'
if ((Test-Path $envExample) -and -not (Test-Path $envFile)) {
    Copy-Item -LiteralPath $envExample -Destination $envFile
    # Restrict the secrets file to the current user (the Windows analogue of chmod 600).
    try {
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        icacls $envFile /inheritance:r /grant:r "${me}:F" *> $null
    } catch { warn ".env created but ACL hardening failed: $($_.Exception.Message). Restrict it by hand." }
    say 'wrote .env from template — fill in SMTP_* and REPORT_EMAIL to enable reports.'
}

# .gitignore canonical block (the authoritative copy lives in CLAUDE.md). Appended once.
$gi = Join-Path $ROOT '.gitignore'
$marker = '# claude-watchman — never commit these'
$giBlock = @'
# claude-watchman — never commit these
# (install (re)generates this block; the canonical copy lives in CLAUDE.md.
#  Order matters: the .env.example negation must follow the .env* glob.)
CLAUDE.md
.claude/
.env*
!.env.example
config/watchman.conf
journal/findings.db
journal/findings.db-wal
journal/findings.db-shm
journal/network-baseline.txt
journal/log-offsets.txt
journal/monitor-offsets.txt
journal/monitor-state/
journal/run-ledger.tsv
journal/run.log
journal/.write.lock

# preflight staging + scratch
.watchman-sudoers.staged
.pf.allow
.pf.dirs
.pf.sudoers
.pf.fix.allow
.pf.fix.dirs
journal/findings.db.backup-*

# editor / OS cruft
*.swp
*~
.DS_Store
'@
if (-not (Test-Path $gi) -or -not (Select-String -LiteralPath $gi -SimpleMatch $marker -Quiet)) {
    Add-Content -LiteralPath $gi -Value "`n$giBlock"
    say 'appended .gitignore block'
}

say 'initializing journal…'
journal_init

say 'running preflight (Claude permission profiles + in-session commands)…'
. (Join-Path $ROOT 'lib/preflight.ps1')
preflight_run

# --- PATH shim --------------------------------------------------------------
# Add the repo root to the USER PATH so `watchman <verb>` resolves watchman.cmd. (The Windows
# analogue of the /usr/local/bin symlink — no admin needed for the user PATH.)
try {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$ROOT*") {
        [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ";$ROOT"), 'User')
        say "added $ROOT to your user PATH — open a new shell, then run: watchman selfcheck"
    } else {
        say 'repo already on PATH — run: watchman selfcheck'
    }
} catch { warn "could not update PATH automatically: $($_.Exception.Message). Add $ROOT to PATH manually." }

say 'claude-watchman installed. Next: open a NEW elevated PowerShell and run  watchman selfcheck'
