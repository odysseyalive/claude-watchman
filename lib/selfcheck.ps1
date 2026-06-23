# lib/selfcheck.ps1 — prove the plumbing works on THIS host, with NO Claude in the
# loop (Windows PowerShell port of lib/selfcheck.sh). This isolates "does the tool
# work on this box" (resolvers, journal, deps, permissions, mail, auth, real observe
# commands) from "does headless Claude execute the skills correctly" — which only
# `/watchman audit` (live) can prove.
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# selfcheck is READ-ONLY with ONE narrow, non-destructive exception: it re-asserts the loop's
# permission safety-contracts in .claude/settings.json (defaultMode=dontAsk + the destructive deny
# base) via preflight's base-settings writer — because selfcheck is on the path to a loop start and
# a drifted base silently weakens the seatbelt. That repair only TIGHTENS protection and preserves
# operator tuning; it never loosens, deletes, or overwrites data. Otherwise selfcheck writes nothing
# except a throwaway scratch DB under a temp dir (removed before return).
#
# Return: $true = healthy (warnings allowed); $false = a CRITICAL plumbing fault (missing sqlite3,
# broken journal code, syntax-broken lib) that would stop the tool from functioning at all.
#
# Every Windows cmdlet is guarded so this file parses and smoke-runs on a non-Windows host (it will
# print WARN/FAIL for the missing Windows bits — expected when statically testing the port).

$script:SC_LIB_DIR = $PSScriptRoot
$script:WATCHMAN_ROOT = if ($env:WATCHMAN_ROOT) { $env:WATCHMAN_ROOT } else { Split-Path -Parent $PSScriptRoot }

$script:_SC_FAIL = 0
$script:_SC_WARN = 0

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function _sc_ok([string]$m)   { Write-Host "  [ ok ] $m" -ForegroundColor Green }
function _sc_warn([string]$m) { Write-Host "  [warn] $m" -ForegroundColor Yellow; $script:_SC_WARN++ }
function _sc_fail([string]$m) { Write-Host "  [FAIL] $m" -ForegroundColor Red;    $script:_SC_FAIL++ }
function _sc_na([string]$m)   { Write-Host "  [ -- ] $m" -ForegroundColor DarkGray }
function _sc_hdr([string]$m)  { Write-Host ""; Write-Host $m -ForegroundColor White }

# True if this session is elevated (Administrator). Guarded so it does not throw off-Windows.
function _sc_is_admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { return $false }
}

function selfcheck_run {
    Write-Host "claude-watchman selfcheck — direct plumbing test (no Claude)"
    Write-Host "root: $($script:WATCHMAN_ROOT)"

    # --- lib integrity (PowerShell AST parse) ------------------------------
    _sc_hdr "1. Library integrity (PowerShell parse)"
    foreach ($f in @('journal', 'distro', 'profile', 'smtp', 'preflight', 'selfcheck')) {
        $p = Join-Path $script:WATCHMAN_ROOT "lib/$f.ps1"
        if (Test-Path -LiteralPath $p) {
            $errs = $null; $toks = $null
            try {
                [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$toks, [ref]$errs) | Out-Null
                if ($errs -and $errs.Count -gt 0) { _sc_fail "lib/$f.ps1 has a syntax error" } else { _sc_ok "lib/$f.ps1" }
            } catch { _sc_fail "lib/$f.ps1 could not be parsed" }
        } else { _sc_fail "lib/$f.ps1 missing" }
    }
    if (Test-Path -LiteralPath (Join-Path $script:WATCHMAN_ROOT 'journal/schema.sql')) { _sc_ok 'journal/schema.sql present' } else { _sc_fail 'journal/schema.sql missing' }

    # Dot-source the resolvers (now that they parse) so we can call them directly.
    foreach ($lib in @('wm.mutators.ps1', 'wm.common.ps1', 'journal.ps1', 'distro.ps1', 'profile.ps1')) {
        $lp = Join-Path $script:SC_LIB_DIR $lib
        if (Test-Path -LiteralPath $lp) { try { . $lp } catch {} }
    }
    if (Test-Path -LiteralPath (Join-Path $script:SC_LIB_DIR 'smtp.ps1')) { try { . (Join-Path $script:SC_LIB_DIR 'smtp.ps1') } catch {} }

    # --- environment + resolvers -------------------------------------------
    _sc_hdr "2. Detection & resolvers"
    $fam = if (Get-Command watchman_family -ErrorAction SilentlyContinue) { watchman_family } else { 'unknown' }
    $prof = if (Get-Command watchman_profile -ErrorAction SilentlyContinue) { watchman_profile } else { 'unknown' }
    if ($fam -eq 'unknown') { _sc_fail 'distro family unknown (need windows on this port)' }
    elseif ($fam -ne 'windows') { _sc_warn "family=$fam (expected windows on the PowerShell port)" }
    else { _sc_ok "family=$fam" }
    _sc_ok "profile=$prof"
    if (Get-Command watchman_firewall_backend -ErrorAction SilentlyContinue) { _sc_ok "firewall backend  = $(watchman_firewall_backend)" }
    if ((Get-Command mac_layer -ErrorAction SilentlyContinue) -and (Get-Command mac_state -ErrorAction SilentlyContinue)) { _sc_ok "MAC layer/state   = $(mac_layer)/$(mac_state)" }
    if (Get-Command autoupdate_mechanism -ErrorAction SilentlyContinue) { _sc_ok "auto-update mech   = $(autoupdate_mechanism)" }
    if (Get-Command integrity_verifier -ErrorAction SilentlyContinue) { _sc_ok "integrity verifier = $(integrity_verifier)" }
    if (Get-Command log_path_auth -ErrorAction SilentlyContinue) { _sc_ok "auth log path      = $(log_path_auth)" }
    if (Get-Command webserver_detect -ErrorAction SilentlyContinue) {
        $wsNames = @(webserver_detect | ForEach-Object { ($_ -split "`t")[0] }) | Where-Object { $_ }
        $wsStr = if ($wsNames.Count) { ($wsNames -join ' ') } else { 'none detected' }
        _sc_ok "web servers found  = $wsStr"
    }
    if (Get-Command webserver_log_paths -ErrorAction SilentlyContinue) {
        $logDirs = @(webserver_log_paths) -join ' '
        _sc_ok "web log dirs       = $logDirs"
    }

    # --- dependencies (degradation map) ------------------------------------
    _sc_hdr "3. Dependencies"
    $miss = [System.Collections.Generic.List[string]]::new()
    # sqlite3 is REQUIRED — PATH or a bundled bin/sqlite3.exe.
    $bundledSqlite = Join-Path $script:WATCHMAN_ROOT 'bin/sqlite3.exe'
    if ((_have 'sqlite3') -or (Test-Path -LiteralPath $bundledSqlite)) {
        if (_have 'sqlite3') { _sc_ok 'sqlite3 present (required)' } else { _sc_ok 'sqlite3 present (bundled bin/sqlite3.exe, required)' }
    } else {
        _sc_fail 'sqlite3 MISSING — required (add to PATH or bundle bin/sqlite3.exe)'
        if (Get-Command pkg_for_cmd -ErrorAction SilentlyContinue) { $miss.Add((pkg_for_cmd 'sqlite3')) } else { $miss.Add('SQLite.SQLite') }
    }
    # Get-WinEvent is the journald analogue for observe checks.
    if (_have 'Get-WinEvent') { _sc_ok 'Get-WinEvent present (event-log observe)' } else { _sc_warn 'Get-WinEvent missing — some observe checks degrade' }
    # Disk capacity.
    if ((_have 'Get-Volume') -or (_have 'Get-PSDrive')) { _sc_ok 'disk enumeration present (Get-Volume/Get-PSDrive)' } else { _sc_warn 'disk enumeration missing — disk capacity check degrades' }
    # Connection enumeration.
    if (_have 'Get-NetTCPConnection') { _sc_ok 'Get-NetTCPConnection present (connection enumeration)' } else { _sc_warn 'Get-NetTCPConnection missing — outbound connection tracking degrades' }
    # Memory.
    if (_have 'Get-CimInstance') { _sc_ok 'Get-CimInstance present (memory/OS facts)' } else { _sc_warn 'Get-CimInstance missing — memory check degrades' }
    # lynis has no Windows port — audit-system uses windows_hardening_scan instead.
    _sc_na 'lynis n/a on Windows — audit-system runs the native windows_hardening_scan'
    # msmtp is replaced by the MailKit transport in smtp.ps1; report on configured SMTP later.
    if (_have 'msmtp') { _sc_ok 'msmtp present (send-report fallback)' } else { _sc_na 'msmtp absent — Windows send-report uses the native MailKit transport (smtp.ps1)' }
    # CrowdSec cscli is optional and exists on Windows.
    if (_have 'cscli') { _sc_ok 'cscli present (crowdsec)' } else { _sc_warn 'cscli missing — inspect-logs falls back to log scan'; $miss.Add('CrowdSec.CrowdSec') }

    if ($miss.Count -gt 0) {
        $ic = if (Get-Command pkg_install_cmd -ErrorAction SilentlyContinue) { pkg_install_cmd } else { 'winget install --id' }
        $uniq = ($miss | Select-Object -Unique) -join ' '
        Write-Host ""
        Write-Host "  [ ->  ] install the missing packages:" -ForegroundColor Yellow
        Write-Host "        $ic $uniq"
    }

    # --- journal: real DB status + scratch roundtrip -----------------------
    _sc_hdr "4. Journal"
    $realDb = Join-Path $script:WATCHMAN_ROOT 'journal/findings.db'
    $sqliteBin = $null
    if (_have 'sqlite3') { $sqliteBin = (Get-Command 'sqlite3').Source }
    elseif (Test-Path -LiteralPath $bundledSqlite) { $sqliteBin = $bundledSqlite }
    if (Test-Path -LiteralPath $realDb) {
        $n = $null
        if ($sqliteBin) { try { $n = ('SELECT COUNT(*) FROM findings;' | & $sqliteBin $realDb) } catch {} }
        if ($n) { _sc_ok "real findings.db opens ($n findings)" } else { _sc_warn 'findings.db present but unreadable — inspect it' }
    } else {
        _sc_warn 'findings.db not yet initialized (created by install.ps1 / first audit)'
    }

    # Prove journal.ps1 works end-to-end without touching the real DB, in a temp dir.
    if ($sqliteBin) {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wm-selfcheck-" + [guid]::NewGuid().ToString('N'))
        $rc = 0
        try {
            New-Item -ItemType Directory -Force -Path $tmp | Out-Null
            # Run the roundtrip in a child pwsh so the env-var overrides + dot-source don't leak.
            $schema = Join-Path $script:WATCHMAN_ROOT 'journal/schema.sql'
            $jlib = Join-Path $script:SC_LIB_DIR 'journal.ps1'
            $rtScript = @"
`$ErrorActionPreference = 'Stop'
`$env:JOURNAL_DIR = '$tmp'
`$env:JOURNAL_DB = '$tmp/findings.db'
`$env:JOURNAL_SCHEMA = '$schema'
`$env:WATCHMAN_SQLITE = '$sqliteBin'
. '$jlib'
journal_init | Out-Null
`$fp = journal_upsert '$fam' '$prof' config info safe selfcheck_probe '' 'selfcheck probe' 'n/a' 'n/a'
if (-not `$fp) { exit 12 }
journal_set_status `$fp fixed 'selfcheck' | Out-Null
journal_upsert '$fam' '$prof' config info safe selfcheck_probe '' 'selfcheck probe' 'n/a' 'n/a' | Out-Null
`$status = ('SELECT status FROM findings WHERE fingerprint=''' + `$fp + ''';' | & '$sqliteBin' '$tmp/findings.db')
if (`$status -ne 'regressed') { exit 15 }
`$count = ('SELECT COUNT(*) FROM findings;' | & '$sqliteBin' '$tmp/findings.db')
if (`$count -ne '1') { exit 16 }
exit 0
"@
            $pwsh = (Get-Process -Id $PID).Path
            if (-not $pwsh) { $pwsh = 'pwsh' }
            & $pwsh -NoProfile -Command $rtScript
            $rc = $LASTEXITCODE
        } catch { $rc = 99 } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        }
        if ($rc -eq 0) { _sc_ok 'journal.ps1 roundtrip OK (init->upsert->regress->dedup, scratch DB)' }
        else { _sc_fail "journal.ps1 roundtrip FAILED (code $rc) — the journal engine is broken on this host" }
    } else {
        _sc_fail 'cannot test journal roundtrip — sqlite3 missing'
    }

    # Prove the wm dispatcher works (the single allowlisted execution path for every skill) and that
    # its read-only guard refuses a mutator without WM_APPLY (the seatbelt that keeps the loop from
    # mutating). The refusal happens BEFORE the function runs, so this touches nothing.
    $wmPs = Join-Path $script:WATCHMAN_ROOT 'lib/wm.ps1'
    if (Test-Path -LiteralPath $wmPs) {
        $pwshExe = (Get-Process -Id $PID).Path
        if (-not $pwshExe) { $pwshExe = 'pwsh' }
        $wmfam = $null
        try { $wmfam = (& $pwshExe -NoProfile -File $wmPs watchman_family 2>$null) } catch {}
        if ($wmfam -and ($wmfam -eq $fam)) { _sc_ok "wm.ps1 dispatcher OK (pwsh -NoProfile -File lib/wm.ps1 watchman_family -> $wmfam)" }
        else { _sc_fail "wm.ps1 dispatcher FAILED (returned '$wmfam', expected '$fam') — skills cannot execute" }
        $grc = 0
        try { & $pwshExe -NoProfile -File $wmPs firewall_allow '1/tcp' *> $null; $grc = $LASTEXITCODE } catch { $grc = -1 }
        if ($grc -eq 3) { _sc_ok 'wm.ps1 read-only guard OK (refuses mutators without WM_APPLY)' }
        else { _sc_fail "wm.ps1 read-only guard BROKEN (mutator exit $grc, expected refusal 3) — the loop's seatbelt is compromised" }
    } else {
        _sc_fail 'lib/wm.ps1 dispatcher missing — skills have no way to call library functions'
    }

    # --- permission artifacts ----------------------------------------------
    _sc_hdr "5. Permission artifacts"
    $cdir = if ($env:WATCHMAN_CLAUDE_DIR) { $env:WATCHMAN_CLAUDE_DIR } else { Join-Path $script:WATCHMAN_ROOT '.claude' }
    $settings = Join-Path $cdir 'settings.json'
    if (Test-Path -LiteralPath $settings) {
        $modeBefore = 'unset'
        try { $cur = Get-Content -Raw -LiteralPath $settings | ConvertFrom-Json; if ($cur.permissions.defaultMode) { $modeBefore = $cur.permissions.defaultMode } } catch {}
        # On the path to a loop start: don't merely WARN on drift — repair it via preflight's
        # single source of truth (idempotent; restores dontAsk + re-asserts the destructive deny base
        # without clobbering operator tuning). Graceful if it can't be written.
        if (-not (Get-Command preflight_write_base_settings -ErrorAction SilentlyContinue)) {
            $pflib = Join-Path $script:SC_LIB_DIR 'preflight.ps1'
            if (Test-Path -LiteralPath $pflib) { try { . $pflib } catch {} }
        }
        if (Get-Command preflight_write_base_settings -ErrorAction SilentlyContinue) { try { preflight_write_base_settings $cdir | Out-Null } catch {} }
        $modeAfter = 'unset'
        try { $cur2 = Get-Content -Raw -LiteralPath $settings | ConvertFrom-Json; if ($cur2.permissions.defaultMode) { $modeAfter = $cur2.permissions.defaultMode } } catch {}
        if ($modeAfter -ne 'dontAsk') { _sc_warn "settings.json defaultMode=$modeAfter — the loop needs dontAsk and auto-repair failed; run 'watchman preflight' as Administrator or fix by hand (use 'watchman dev' for edit sessions)" }
        elseif ($modeBefore -eq 'dontAsk') { _sc_ok 'settings.json defaultMode=dontAsk (deny base re-asserted)' }
        else { _sc_ok "settings.json defaultMode repaired ($modeBefore -> dontAsk) + deny base re-asserted" }
    } else { _sc_warn 'settings.json absent — run install.ps1 / watchman preflight' }
    $localSettings = Join-Path $cdir 'settings.local.json'
    if (Test-Path -LiteralPath $localSettings) {
        $na = 0
        try { $lj = Get-Content -Raw -LiteralPath $localSettings | ConvertFrom-Json; $na = @($lj.permissions.allow).Count } catch {}
        if ($na -gt 0) { _sc_ok "settings.local.json has $na allow rules" } else { _sc_warn 'settings.local.json has no allow rules — run watchman preflight' }
    } else { _sc_warn 'settings.local.json absent — run install.ps1 / watchman preflight' }
    if (_sc_is_admin) { _sc_ok 'running elevated (Administrator) — reads logs/event-log directly' }
    else { _sc_warn 'not elevated — claude-watchman is designed to run as Administrator so it can read all logs/events' }

    # --- mail + Claude CLI -------------------------------------------------
    _sc_hdr "6. Mail & Claude Code"
    if (-not $env:SMTP_ENV_FILE) { $env:SMTP_ENV_FILE = Join-Path $script:WATCHMAN_ROOT '.env' }
    if ((Get-Command smtp_is_configured -ErrorAction SilentlyContinue) -and (smtp_is_configured)) { _sc_ok 'SMTP configured (reports will send)' }
    else { _sc_warn 'SMTP unconfigured — send-report degrades (logs & skips)' }
    if (_have 'claude') { _sc_ok "claude CLI on PATH — audit/loop/fix run on this user's Claude Code login ('claude' + /login if needed)" }
    else { _sc_warn 'claude CLI not on PATH — audit/loop/fix cannot run (selfcheck still works)' }

    # --- live read-only observe smoke --------------------------------------
    _sc_hdr "7. Observe smoke (real read-only commands)"
    if (_have 'Get-Volume') {
        try {
            $sysLetter = if ($env:SystemDrive) { $env:SystemDrive.TrimEnd(':') } else { 'C' }
            $vol = Get-Volume -DriveLetter $sysLetter -ErrorAction Stop
            if ($vol.Size -gt 0) {
                $usedPct = [math]::Round(100.0 * ($vol.Size - $vol.SizeRemaining) / $vol.Size, 0)
                _sc_ok "Get-Volume: $usedPct% used on $($sysLetter):"
            } else { _sc_ok "Get-Volume: $($sysLetter): readable" }
        } catch { _sc_warn "Get-Volume failed — $($_.Exception.Message)" }
    } elseif (_have 'Get-PSDrive') {
        try { Get-PSDrive -PSProvider FileSystem -ErrorAction Stop | Out-Null; _sc_ok 'Get-PSDrive readable' } catch { _sc_warn 'Get-PSDrive failed' }
    } else { _sc_warn 'no disk-enumeration cmdlet present' }
    if (_have 'Get-CimInstance') {
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $freeMb = [math]::Round($os.FreePhysicalMemory / 1024, 0)
            _sc_ok "Win32_OperatingSystem: $freeMb MiB free physical memory"
        } catch { _sc_warn "memory smoke check failed — $($_.Exception.Message)" }
    } else { _sc_warn 'Get-CimInstance missing — memory smoke check skipped' }
    if (_have 'Get-WinEvent') {
        try { Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction Stop | Out-Null; _sc_ok 'Get-WinEvent readable (System log)' }
        catch { _sc_warn 'Get-WinEvent not readable — run elevated (the intended model)' }
    }

    # --- verdict -----------------------------------------------------------
    _sc_hdr "Verdict"
    Write-Host "  failures: $($script:_SC_FAIL)   warnings: $($script:_SC_WARN)"
    Write-Host ""
    Write-Host "  NOTE: selfcheck does NOT exercise the live 'claude -p' -> SKILL.md path or"
    Write-Host "        the dontAsk allowlist matching of compound commands. Run a supervised"
    Write-Host "        '/watchman audit' once and read the output to validate that path."
    if ($script:_SC_FAIL -gt 0) {
        Write-Host ""
        Write-Host "  FAIL — critical plumbing fault; fix the [FAIL] items before deploying." -ForegroundColor Red
        return $false
    } elseif ($script:_SC_WARN -gt 0) {
        Write-Host ""
        Write-Host "  PASS with warnings — plumbing works; review [warn] items for full coverage." -ForegroundColor Yellow
        return $true
    }
    Write-Host ""
    Write-Host "  PASS — plumbing healthy on this host." -ForegroundColor Green
    return $true
}
