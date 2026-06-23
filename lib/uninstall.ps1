# lib/uninstall.ps1 — `watchman uninstall` (zero-token PowerShell; no Claude, no git).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# The destructive inverse of install.ps1: it removes the Task Scheduler trigger, unlinks the PATH
# shim (watchman.cmd), then removes the artifacts install created — in tiers, each behind its own
# confirmation. It is OPERATOR-RUN with explicit intent, so unlike the loop it CAN stop-warn-ask, and
# it does, for every removal. Uninstalling IS destructive (it deletes files irreversibly), so this
# script obeys the directive to the letter: it STOPS before each class of removal, WARNS in plain
# language what would be lost, and ASKS for explicit per-tier consent (default NO; a non-interactive
# session with no -Yes refuses rather than assume yes). It NEVER removes packages (other software may
# depend on them — it only names them), and it NEVER does a blind recursive delete of the install
# directory: claude-watchman may be a guest inside a host repo, so it deletes only the files IT owns
# (the manifest product + its own generated artifacts) and hands the final directory delete back.
#
# Every cmdlet is guarded so this file parses and smoke-runs on a non-Windows host.

$script:UN_LIB_DIR = $PSScriptRoot
$script:WATCHMAN_ROOT = if ($env:WATCHMAN_ROOT) { $env:WATCHMAN_ROOT } else { Split-Path -Parent $PSScriptRoot }

# The Windows PATH shim install.ps1 drops on a PATH dir (overridable for forks/tests). Guarded so a
# null %LOCALAPPDATA% (e.g. on a non-Windows host where this file is statically smoke-tested) can't
# throw at load — fall back to a benign relative path that simply won't exist.
$script:UN_SHIM = if ($env:WATCHMAN_SHIM) { $env:WATCHMAN_SHIM }
    elseif ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\watchman.cmd' }
    else { 'watchman.cmd' }

$script:_un_assume_yes = $false

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function _un_say([string]$m)  { Write-Host "==> $m" -ForegroundColor Cyan }
function _un_warn([string]$m) { [Console]::Error.WriteLine("[warn] $m") }
function _un_del([string]$m)  { Write-Host "  [removed] $m" -ForegroundColor Red }
function _un_keep([string]$m) { Write-Host "  [kept] $m" -ForegroundColor DarkGray }

# Mirror install.ps1's confirm: default NO, and a non-interactive session with no -Yes REFUSES (fail
# safe) rather than silently deleting.
function _un_confirm([string]$prompt) {
    if ($script:_un_assume_yes) { return $true }
    $interactive = $true
    try { $interactive = -not [System.Console]::IsInputRedirected } catch { $interactive = $false }
    if (-not $interactive) { _un_warn "non-interactive session — refusing (answer 'no'): $prompt"; return $false }
    $reply = Read-Host "    $prompt [y/N]"
    return ($reply -match '^[Yy]$')
}

# Remove a single path (file, dir, or symlink) and report it, relative to the install root. No-op if
# absent. The actual delete is the one destructive act — it is reached only after _un_confirm gated it.
function _un_rm([string]$p, [string]$root) {
    if ((Test-Path -LiteralPath $p) -or (Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue)) {
        try {
            Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop
            $rel = $p
            if ($p.StartsWith($root)) { $rel = $p.Substring($root.Length).TrimStart('\', '/') }
            _un_del $rel
        } catch { _un_warn "could not remove ${p}: $($_.Exception.Message)" }
    }
}

# Remove every path matching the given glob(s) under the install root.
function _un_rm_glob([string]$root, [Parameter(ValueFromRemainingArguments = $true)][string[]]$patterns) {
    foreach ($pat in $patterns) {
        $matches = @()
        try { $matches = @(Get-ChildItem -Path (Join-Path $root $pat) -Force -ErrorAction SilentlyContinue) } catch {}
        foreach ($g in $matches) { _un_rm $g.FullName $root }
    }
}

function uninstall_run {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$args)
    $root = $script:WATCHMAN_ROOT
    foreach ($a in @($args)) {
        if ([string]::IsNullOrWhiteSpace($a)) { continue }
        switch ($a) {
            '-Yes' { $script:_un_assume_yes = $true }
            '--yes' { $script:_un_assume_yes = $true }
            '-y' { $script:_un_assume_yes = $true }
            default { [Console]::Error.WriteLine("uninstall: unknown arg '$a' (only -Yes is accepted)"); return $false }
        }
    }

    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        _un_warn "WATCHMAN_ROOT ($root) does not exist — nothing to uninstall."
        return $true
    }

    _un_say "claude-watchman uninstall — install root: $root"
    [Console]::Error.WriteLine(@"

This removes claude-watchman in tiers, asking before each one (default is No). It will:
  * NOT remove packages — sqlite3, msmtp, lynis (and crowdsec, if installed) are left in
    place; other software may use them. Remove them yourself if you want.
  * NOT delete the install directory wholesale — it removes only the files watchman owns,
    then tells you the directory is yours to delete if you want it gone.
"@)

    # --- Tier 0: the Task Scheduler trigger (the headless cadence) ---------
    # Tear down the recurring headless loop FIRST so nothing fires mid-uninstall. schedule_remove
    # itself stop-warn-asks (it is a gated mutator), so we just delegate to it when present.
    _un_say "0. Scheduled Task (headless cadence)"
    if (Get-Command schedule_remove -ErrorAction SilentlyContinue) {
        try { schedule_remove | Out-Null } catch { _un_warn "schedule_remove failed: $($_.Exception.Message)" }
    } else {
        $schedLib = Join-Path $script:UN_LIB_DIR 'schedule.ps1'
        if (Test-Path -LiteralPath $schedLib) {
            try { . $schedLib; if (Get-Command schedule_remove -ErrorAction SilentlyContinue) { schedule_remove | Out-Null } } catch { _un_warn "schedule_remove unavailable: $($_.Exception.Message)" }
        } else {
            _un_keep 'no schedule library present — nothing to unregister'
        }
    }

    # --- Tier 1: the PATH shim --------------------------------------------
    # Only touch the shim if it resolves to THIS install — never remove an unrelated file.
    _un_say "1. PATH shim ($($script:UN_SHIM))"
    $shim = $script:UN_SHIM
    if (Test-Path -LiteralPath $shim) {
        $ownsShim = $false
        try {
            $content = Get-Content -Raw -LiteralPath $shim -ErrorAction Stop
            # install.ps1 writes a shim that references this root's bin/watchman.ps1.
            if ($content -match [regex]::Escape($root)) { $ownsShim = $true }
        } catch {}
        if ($ownsShim) {
            if (_un_confirm "Remove the PATH shim $shim (points at this install)?") { _un_rm $shim $root } else { _un_keep $shim }
        } else {
            _un_warn "$shim does not reference this install — leaving it untouched."
        }
    } else {
        _un_keep "$shim (absent)"
    }

    # --- Tier 2: regenerable local artifacts -------------------------------
    # The Claude permission profiles + deployed command, and preflight scratch — all regenerated by
    # `watchman preflight`, so losing it is cheap.
    _un_say "2. Generated local artifacts (.claude/, preflight scratch, journal backups)"
    if (_un_confirm "Remove the regenerable artifacts (regenerated by 'watchman preflight')?") {
        _un_rm (Join-Path $root '.claude') $root
        _un_rm_glob $root '.pf.allow' '.pf.dirs' '.pf.sudoers' '.pf.fix.allow' '.pf.fix.dirs' `
                    '.watchman-sudoers.staged' 'journal/findings.db.backup-*'
    } else {
        _un_keep 'generated artifacts'
    }

    # --- Tier 3: operator DATA and SECRETS (loud) --------------------------
    # The irreversible tier: .env holds your SMTP password; findings.db is the entire journal
    # history; the baselines/offsets are accumulated state.
    _un_say "3. Operator data & secrets (.env, config, journal database, baselines)"
    _un_warn "DESTRUCTIVE & IRREVERSIBLE: this deletes your SMTP credentials (.env), your"
    _un_warn "machine config, and the ENTIRE finding history in journal/findings.db. There"
    _un_warn "is no backup and no undo. Skip this tier to keep your data if you may reinstall."
    if (_un_confirm "Permanently delete .env, config, and the journal database?") {
        _un_rm (Join-Path $root '.env') $root
        _un_rm (Join-Path $root 'config/watchman.conf') $root
        _un_rm_glob $root 'journal/findings.db' 'journal/findings.db-wal' 'journal/findings.db-shm' `
                    'journal/network-baseline.txt' 'journal/log-offsets.txt' `
                    'journal/monitor-offsets.txt' 'journal/monitor-state' 'journal/.write.lock'
    } else {
        _un_keep 'operator data & secrets'
    }

    # --- Tier 4: the product code ------------------------------------------
    # Remove exactly the files the manifest shipped (read the manifest in full first, since it lists
    # files we are about to delete), plus manifest.txt itself. .gitignore is intentionally NOT touched.
    _un_say "4. Product code (skills/, lib/, commands/, bin/, install.ps1, …)"
    if (_un_confirm "Remove the claude-watchman product files from $root?") {
        $product = [System.Collections.Generic.List[string]]::new()
        $manifest = Join-Path $root 'manifest.txt'
        if (Test-Path -LiteralPath $manifest) {
            foreach ($line in (Get-Content -LiteralPath $manifest)) {
                if (-not $line) { continue }
                if ($line -match '^\s*#') { continue }
                $entry = ($line -replace '^(hook|keep) ', '').Trim()
                if ($entry) { $product.Add($entry) }
            }
        } else {
            _un_warn "manifest.txt missing — falling back to the known product directories."
            @('bin/watchman', 'bin/watchman.ps1', 'install.ps1', 'install.sh', 'journal/schema.sql', '.env.example',
              'config/watchman.conf.example', 'commands/watchman/SKILL.md', 'skills/MANIFEST.md') | ForEach-Object { $product.Add($_) }
        }
        foreach ($p in $product) { _un_rm (Join-Path $root $p) $root }
        _un_rm $manifest $root
        # Prune empty dirs ONLY within watchman's own subtrees (never $root, never host dirs).
        foreach ($d in @('skills', 'lib', 'commands', 'config', 'journal', 'bin')) {
            $sub = Join-Path $root $d
            if (Test-Path -LiteralPath $sub) {
                try {
                    Get-ChildItem -Path $sub -Recurse -Directory -Force -ErrorAction SilentlyContinue |
                        Sort-Object { $_.FullName.Length } -Descending |
                        ForEach-Object { if (-not (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } }
                } catch {}
            }
        }
    } else {
        _un_keep 'product code'
    }

    # --- Wrap up ------------------------------------------------------------
    _un_say "Uninstall steps complete."
    [Console]::Error.WriteLine(@"

Left in place on purpose:
  * Packages (sqlite3, msmtp, lynis, and crowdsec if present). Remove with your package
    manager (winget) if nothing else needs them.
"@)
    $gi = Join-Path $root '.gitignore'
    if (Test-Path -LiteralPath $gi) {
        $gt = ''
        try { $gt = Get-Content -Raw -LiteralPath $gi } catch {}
        if ($gt -match 'claude-watchman — never commit these') {
            _un_warn ".gitignore still carries the claude-watchman block — remove that block by hand if you want it gone."
        }
    }
    if (Test-Path -LiteralPath (Join-Path $root 'CLAUDE.md')) {
        _un_warn "CLAUDE.md (development standing-context, gitignored) is still here — delete it by hand if unwanted."
    }

    $remaining = $null
    try { $remaining = Get-ChildItem -Path $root -Force -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}
    if ($remaining) {
        [Console]::Error.WriteLine(@"

The install directory still holds files (kept data, the host repo, or your own content).
claude-watchman never deletes the directory wholesale. If this was a dedicated watchman
directory and you want it gone entirely, you can remove it yourself:
    Remove-Item -Recurse -Force '$root'
"@)
    } else {
        _un_say "Install directory $root is now empty — Remove-Item '$root' to remove it."
    }
    return $true
}
