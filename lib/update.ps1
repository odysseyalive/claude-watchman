# lib/update.ps1 — the update mechanism (zero-token PowerShell; no Claude, no git for the user path).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
#   * update_run        — `watchman update`: re-run install.ps1 -Update, which manifest-fetches the
#                         latest product into this directory and regenerates the local artifacts.
#                         Install and update are the SAME command — there is no separate update path.
#   * update_check_run  — `watchman update --check`: a MAINTAINER release-readiness check, run in the
#                         git repo before committing a feature, that asserts the update story still
#                         holds (pull-safety, manifest completeness, orchestration wiring, Prime
#                         Directive, Windows dispatcher hygiene, schema sync).
#   * update_sync_run   — `watchman update --sync`: regenerate manifest.txt from the tracked product
#                         (maintainer-only).
#
# Update is pull-safe by construction: the manifest lists only the portable product, so a re-fetch
# overwrites product files and NEVER touches the machine artifacts (.env, config, journal, .claude) —
# they aren't in the manifest. install.ps1 -Update is non-destructive: it fetches atomically and the
# schema migration it triggers (journal_init) auto-applies only ADDITIVE migrations.
#
# Every cmdlet/external-call is guarded so this file parses and smoke-runs on a non-Windows host.

$script:UP_LIB_DIR = $PSScriptRoot
$script:WATCHMAN_ROOT = if ($env:WATCHMAN_ROOT) { $env:WATCHMAN_ROOT } else { Split-Path -Parent $PSScriptRoot }

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# Run git in the repo root and return its trimmed stdout lines (empty array on any failure).
function _up_git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$gargs)
    if (-not (_have 'git')) { return @() }
    try {
        $out = & git -C $script:WATCHMAN_ROOT @gargs 2>$null
        return @($out)
    } catch { return @() }
}

function _up_in_git_repo {
    if (-not (_have 'git')) { return $false }
    try {
        & git -C $script:WATCHMAN_ROOT rev-parse --is-inside-work-tree 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

# --- watchman update --------------------------------------------------------
# Re-runs install.ps1 in -Update mode. install.ps1 re-fetches the product from the manifest and runs
# its idempotent setup (config/journal left intact, preflight regenerated, additive journal migration).
function update_run {
    $installer = Join-Path $script:WATCHMAN_ROOT 'install.ps1'
    if (-not (Test-Path -LiteralPath $installer)) {
        [Console]::Error.WriteLine("update: $installer not found.")
        [Console]::Error.WriteLine('        Re-run the install one-liner from this directory to (re)install:')
        [Console]::Error.WriteLine('        iwr -useb https://raw.githubusercontent.com/odysseyalive/claude-watchman/main/install.ps1 | iex')
        return $false
    }
    Write-Host 'watchman update: fetching the latest product (manifest, no git) and regenerating…'
    $pwshExe = (Get-Process -Id $PID).Path
    if (-not $pwshExe) { $pwshExe = 'pwsh' }
    & $pwshExe -NoProfile -File $installer -Update
    return ($LASTEXITCODE -eq 0)
}

# --- watchman update --sync (regenerate manifest.txt) -----------------------
# Maintainer helper: rewrite manifest.txt to list exactly the tracked product, so a file you just
# added/removed under skills/ commands/ lib/ ships (or stops shipping) without a hand-edit.
function update_sync_run {
    if (-not (_up_in_git_repo)) {
        [Console]::Error.WriteLine('update --sync is a maintainer tool — run it inside the claude-watchman git repo.')
        return $false
    }
    $m = Join-Path $script:WATCHMAN_ROOT 'manifest.txt'

    # Preserve the leading comment/blank header (machine-format documentation).
    $header = ''
    if (Test-Path -LiteralPath $m) {
        $lines = Get-Content -LiteralPath $m
        $hdr = [System.Collections.Generic.List[string]]::new()
        foreach ($ln in $lines) {
            if ($ln -match '^\s*#' -or $ln -match '^\s*$') { $hdr.Add($ln) } else { break }
        }
        $header = ($hdr -join "`n").TrimEnd()
    }
    if (-not $header) { $header = '# manifest.txt — shipped file list. Regenerate with: watchman update --sync' }

    # The product = tracked files minus .gitignore (install-managed) and the manifest itself.
    $new = @(_up_git ls-files) | Where-Object { $_ -and ($_ -notmatch '^(\.gitignore|manifest\.txt)$') } | Sort-Object -Unique
    $old = @()
    if (Test-Path -LiteralPath $m) {
        $old = @(Get-Content -LiteralPath $m) |
            Where-Object { $_ -and ($_ -notmatch '^\s*#') -and ($_ -notmatch '^\s*$') } |
            ForEach-Object { $_ -replace '^(keep|hook) ', '' } | Sort-Object -Unique
    }

    # Rewrite (atomic via temp + move): header, blank line, then each path with its flag.
    $body = [System.Collections.Generic.List[string]]::new()
    $body.Add($header)
    $body.Add('')
    foreach ($p in $new) {
        if (-not $p) { continue }
        if ($p -eq 'bin/watchman') { $body.Add("hook $p") } else { $body.Add($p) }
    }
    $tmp = "$m.tmp"
    ($body -join "`n") + "`n" | Set-Content -LiteralPath $tmp -NoNewline
    Move-Item -LiteralPath $tmp -Destination $m -Force

    $added = @($new | Where-Object { $old -notcontains $_ })
    $removed = @($old | Where-Object { $new -notcontains $_ })
    if ($added.Count -eq 0 -and $removed.Count -eq 0) {
        Write-Host "update --sync: manifest.txt already in sync ($($new.Count) files)."
    } else {
        Write-Host "update --sync: regenerated manifest.txt ($($new.Count) files)."
        if ($added.Count)   { Write-Host '  + now shipped:';        $added   | ForEach-Object { Write-Host "      $_" } }
        if ($removed.Count) { Write-Host '  - no longer shipped:';  $removed | ForEach-Object { Write-Host "      $_" } }
        Write-Host "Re-stage manifest.txt, run 'watchman update --check', then commit."
    }
    return $true
}

# --- watchman update --check (maintainer release-readiness) -----------------
function update_check_run {
    if (-not (_up_in_git_repo)) {
        Write-Host 'update --check is a maintainer tool — run it inside the claude-watchman git repo.'
        Write-Host '(On an installed tree there is no git pull to make unsafe; update is a manifest re-fetch.)'
        return $true
    }
    $fail = $false
    function _uc_ok([string]$m)   { Write-Host "  [ ok ] $m" -ForegroundColor Green }
    function _uc_fail([string]$m) { Write-Host "  [FAIL] $m" -ForegroundColor Red; $script:_uc_fail_flag = $true }
    $script:_uc_fail_flag = $false

    Write-Host 'claude-watchman release-readiness check (does the update story still hold?)'

    # 1. Pull-safety: every machine-specific artifact is gitignored.
    Write-Host ''; Write-Host '1. Machine artifacts gitignored'
    $artifacts = @(
        '.env', 'config/watchman.conf', 'journal/findings.db', 'journal/findings.db-wal',
        'journal/findings.db-shm', 'journal/network-baseline.txt', 'journal/log-offsets.txt',
        'journal/monitor-offsets.txt', 'journal/monitor-state',
        'journal/run-ledger.tsv', 'journal/run.log', 'journal/.write.lock', '.claude', 'CLAUDE.md'
    )
    foreach ($p in $artifacts) {
        # git check-ignore -q: exit 0 means ignored.
        $ignored = $false
        if (_have 'git') {
            try { & git -C $script:WATCHMAN_ROOT check-ignore -q -- $p 2>$null; $ignored = ($LASTEXITCODE -eq 0) } catch { $ignored = $false }
        }
        if ($ignored) { _uc_ok "ignored: $p" } else { _uc_fail "NOT gitignored: $p — it could be committed or clobbered" }
    }

    # 2. No machine artifact is tracked.
    Write-Host ''; Write-Host '2. No machine artifact tracked'
    $tracked = @(_up_git ls-files)
    $bad = @($tracked | Where-Object {
        $_ -match '(^|/)(findings\.db|network-baseline\.txt|settings(\.local|\.fix|\.dev)?\.json|watchman\.conf)$' -or $_ -match '(^|/)\.env$'
    })
    if ($bad.Count -eq 0) { _uc_ok 'no machine artifact is tracked' } else { _uc_fail ("machine artifacts are tracked:`n" + ($bad -join "`n")) }

    # 3. Manifest in lockstep with the product (no drift on feature submission).
    Write-Host ''; Write-Host '3. Manifest completeness (manifest.txt <-> tracked product)'
    $manifestPath = Join-Path $script:WATCHMAN_ROOT 'manifest.txt'
    if (Test-Path -LiteralPath $manifestPath) {
        $expected = @($tracked | Where-Object { $_ -and ($_ -notmatch '^(\.gitignore|manifest\.txt)$') } | Sort-Object -Unique)
        $manifested = @(Get-Content -LiteralPath $manifestPath) |
            Where-Object { $_ -and ($_ -notmatch '^\s*#') -and ($_ -notmatch '^\s*$') } |
            ForEach-Object { $_ -replace '^(keep|hook) ', '' } | Sort-Object -Unique
        $missing = @($expected | Where-Object { $manifested -notcontains $_ })
        $extra = @($manifested | Where-Object { $expected -notcontains $_ })
        if ($missing.Count -eq 0 -and $extra.Count -eq 0) {
            _uc_ok 'manifest.txt lists exactly the tracked product'
        } else {
            if ($missing.Count) { _uc_fail ("in product but NOT in manifest.txt (won't ship to users):`n" + ($missing -join "`n")) }
            if ($extra.Count)   { _uc_fail ("in manifest.txt but not a tracked file (broken fetch):`n" + ($extra -join "`n")) }
            Write-Host "         fix: run 'watchman update --sync' to regenerate manifest.txt"
        }
    } else {
        _uc_fail 'manifest.txt is missing — the fetch list is gone'
    }

    # 4. Every product SKILL.md AND every lib/*.ps1 carries the Prime Directive block.
    Write-Host ''; Write-Host '4. Prime Directive present in every skill and PowerShell lib'
    $missingPd = $false
    $skillFiles = @()
    foreach ($d in @('skills', 'commands')) {
        $dp = Join-Path $script:WATCHMAN_ROOT $d
        if (Test-Path -LiteralPath $dp) { $skillFiles += @(Get-ChildItem -Path $dp -Recurse -Filter 'SKILL.md' -File -ErrorAction SilentlyContinue) }
    }
    foreach ($s in ($skillFiles | Sort-Object FullName)) {
        $txt = ''
        try { $txt = Get-Content -Raw -LiteralPath $s.FullName } catch {}
        if ($txt -notmatch 'PRIME DIRECTIVE \(outranks everything below\)') { _uc_fail "missing Prime Directive block: $($s.FullName)"; $missingPd = $true }
    }
    # lib/*.ps1 — the comment form is '# > PRIME DIRECTIVE ...'.
    $libDir = Join-Path $script:WATCHMAN_ROOT 'lib'
    if (Test-Path -LiteralPath $libDir) {
        foreach ($l in (Get-ChildItem -Path $libDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $txt = ''
            try { $txt = Get-Content -Raw -LiteralPath $l.FullName } catch {}
            if ($txt -notmatch '#\s*>\s*PRIME DIRECTIVE') { _uc_fail "missing Prime Directive block: lib/$($l.Name)"; $missingPd = $true }
        }
    }
    if (-not $missingPd) { _uc_ok 'all skills and PowerShell libs carry the Prime Directive block' }

    # 5. Windows dispatcher hygiene: no deployed/committed lib/*.ps1 carries the POSIX dispatcher
    #    invocation, and every pwsh dispatcher invocation carries '-NoProfile -File'. The forbidden
    #    literal is assembled from pieces so THIS guard's own source never self-matches.
    Write-Host ''; Write-Host '5. Windows dispatcher hygiene (no POSIX dispatcher leak; pwsh calls carry -NoProfile -File)'
    $bashWm = 'bash' + ' ' + 'lib/wm'
    $dispBad = $false
    if (Test-Path -LiteralPath $libDir) {
        foreach ($l in (Get-ChildItem -Path $libDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $lines = @()
            try { $lines = Get-Content -LiteralPath $l.FullName } catch {}
            foreach ($line in $lines) {
                $trimmed = $line.TrimStart()
                # Skip comment lines (prose, e.g. "# the committed skills say `bash lib/wm`") — only
                # EXECUTABLE code can leak the dispatcher.
                if ($trimmed.StartsWith('#')) { continue }
                # Skip the preflight rewrite line: it NAMES the POSIX literal as the source token of a
                # string replacement (-replace 'bash lib/wm' -> pwsh form), which is the fix, not a leak.
                $isRewrite = ($line -match '-replace' -or $line -match '\[regex\]::Escape')
                # The POSIX bash dispatcher can never run on Windows — flag any executable invocation.
                if ($line.Contains($bashWm) -and -not $isRewrite) {
                    _uc_fail "lib/$($l.Name): carries the POSIX '$bashWm' dispatcher — Windows libs must call the pwsh dispatcher"
                    $dispBad = $true
                }
                # A line that actually INVOKES a wm dispatcher (mentions pwsh AND a wm*.ps1 file) must
                # carry '-NoProfile -File'. Comment/path-only references (Join-Path, prose) are ignored.
                if ($line -match '\bpwsh\b' -and $line -match 'wm(-apply)?\.ps1' -and $line -notmatch '-NoProfile\s+-File') {
                    _uc_fail "lib/$($l.Name): a pwsh dispatcher call does not carry '-NoProfile -File': $($trimmed)"
                    $dispBad = $true
                }
            }
        }
    }
    if (-not $dispBad) { _uc_ok 'no POSIX dispatcher leak; all pwsh dispatcher calls carry -NoProfile -File' }

    # 6. Every observe/analyze skill is wired into the /watchman orchestration.
    Write-Host ''; Write-Host '6. Orchestration wiring (observe/analyze skills in /watchman audit)'
    $cmd = Join-Path $script:WATCHMAN_ROOT 'commands/watchman/SKILL.md'
    if (Test-Path -LiteralPath $cmd) {
        $cmdTxt = ''
        try { $cmdTxt = Get-Content -Raw -LiteralPath $cmd } catch {}
        $unwired = $false
        foreach ($stage in @('grammar', 'logic')) {
            $stageDir = Join-Path $script:WATCHMAN_ROOT "skills/$stage"
            if (-not (Test-Path -LiteralPath $stageDir)) { continue }
            foreach ($d in (Get-ChildItem -Path $stageDir -Directory -ErrorAction SilentlyContinue)) {
                if (-not (Test-Path -LiteralPath (Join-Path $d.FullName 'SKILL.md'))) { continue }
                $rel = "skills/$stage/$($d.Name)"
                if ($cmdTxt -notlike "*$rel*") { _uc_fail "not wired into commands/watchman/SKILL.md: $rel"; $unwired = $true }
            }
        }
        if (-not $unwired) { _uc_ok 'all observe/analyze skills wired into /watchman audit' }
    } else {
        _uc_fail 'commands/watchman/SKILL.md is missing — the in-session command source is gone'
    }

    # 7. Journal schema version in sync (journal.ps1 <-> schema.sql).
    Write-Host ''; Write-Host '7. Journal schema version sync'
    $jv = ''; $sv = ''
    $jlib = Join-Path $script:WATCHMAN_ROOT 'lib/journal.ps1'
    if (Test-Path -LiteralPath $jlib) {
        $jt = Get-Content -Raw -LiteralPath $jlib
        $mm = [regex]::Match($jt, 'JOURNAL_SCHEMA_VERSION\s*=\s*(\d+)')
        if ($mm.Success) { $jv = $mm.Groups[1].Value }
    }
    $schema = Join-Path $script:WATCHMAN_ROOT 'journal/schema.sql'
    if (Test-Path -LiteralPath $schema) {
        $st = Get-Content -Raw -LiteralPath $schema
        $ms = [regex]::Match($st, '(?i)user_version[^0-9]*([0-9]+)')
        if ($ms.Success) { $sv = $ms.Groups[1].Value }
    }
    if ($jv -and $jv -eq $sv) { _uc_ok "schema version in sync (v$jv)" }
    else { _uc_fail "schema version mismatch — lib/journal.ps1=v$(if($jv){$jv}else{'?'}) vs journal/schema.sql=v$(if($sv){$sv}else{'?'})" }

    Write-Host ''
    if (-not $script:_uc_fail_flag) {
        Write-Host 'release-readiness: PASS — the update story holds; safe to commit.'
        return $true
    } else {
        [Console]::Error.WriteLine('release-readiness: FAIL — fix the above before committing this feature.')
        return $false
    }
}
