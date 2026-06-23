# lib/preflight.ps1 — ONE manifest, ONE generated allowlist (Windows PowerShell port).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# Collates the SAME per-skill manifest.json files preflight.sh uses, but emits Windows-native
# permission profiles in the PowerShell(...) namespace (Claude Code's Windows tool), with the
# two-script seatbelt (knot 1) and a Windows additionalDirectories encoding. It ALSO deploys a
# rewritten Windows skill tree (knot 2): the committed skills say `bash lib/wm`, which can't run
# on Windows, so each deployed copy has its dispatcher invocation mechanically rewritten to the
# pwsh form. The committed source is untouched (Linux stays byte-identical).
#
# Three profiles, one shared deny base, exactly as preflight.sh — only the namespace + paths change.

$script:PF_LIB_DIR = $PSScriptRoot
$script:WATCHMAN_ROOT = if ($env:WATCHMAN_ROOT) { $env:WATCHMAN_ROOT } else { Split-Path -Parent $PSScriptRoot }
$script:WATCHMAN_CLAUDE_DIR = if ($env:WATCHMAN_CLAUDE_DIR) { $env:WATCHMAN_CLAUDE_DIR } else { Join-Path $script:WATCHMAN_ROOT '.claude' }

# distro/profile resolvers, so read tokens (webserver_log_paths, log_path_auth, …) resolve for
# THIS host exactly as the in-session skills will see them.
. (Join-Path $script:PF_LIB_DIR 'wm.mutators.ps1')
. (Join-Path $script:PF_LIB_DIR 'wm.common.ps1')
. (Join-Path $script:PF_LIB_DIR 'journal.ps1')
. (Join-Path $script:PF_LIB_DIR 'distro.ps1')
. (Join-Path $script:PF_LIB_DIR 'profile.ps1')
if (Test-Path (Join-Path $script:PF_LIB_DIR 'sectools.ps1')) { . (Join-Path $script:PF_LIB_DIR 'sectools.ps1') }

# A drive path forward-slashed (avoids JSON backslash-escaping); used for Read() globs + dirs.
function _pf_winpath([string]$p) { return ($p -replace '\\', '/') }

# Known Linux literal read-paths in the shared manifests → their Windows homes. Anything not
# mapped (and not produced by a resolver token) is skipped rather than guessed.
$script:PF_LINUX_READ_MAP = @{
    '/home' = 'C:/Users'
    '/root' = 'C:/Users'
    '/etc'  = 'C:/ProgramData'
    '/var/log' = 'C:/Windows/System32/winevt/Logs'
}
# Linux-only command families in the shared manifests that have NO Windows binary — their
# observation runs inside the wm dispatcher on Windows (covered by the framework base rule), so
# they need no PowerShell() rule. Anything else in commands[] gets a PowerShell(<cmd> *) grant.
$script:PF_LINUX_ONLY_CMDS = @(
    'lynis', 'journalctl', 'ss', 'systemctl', 'stat', 'last', 'lsattr', 'getent',
    'debsums', 'aa-status', 'getenforce', 'sestatus', 'ufw', 'firewall-cmd', 'nft', 'aide', 'debsecan', 'arch-audit',
    'df', 'free', 'exim', 'crontab', 'whmapi1', 'check_cpanel_rpms'   # cPanel/Linux-only; cPanel self-gates on Windows
)

# --- Framework base ---------------------------------------------------------
# The load-bearing rule: PowerShell(pwsh -NoProfile -File lib/wm.ps1:*) lets every read/journal
# skill run through the dispatcher. wm-apply.ps1 is DELIBERATELY NOT named here, so under dontAsk
# the loop auto-denies any mutation — the Windows seatbelt (knot 1). Plus sqlite3 + Skill(<name>).
function _pf_framework_allow {
    $rules = [System.Collections.Generic.List[string]]::new()
    $rules.Add('PowerShell(pwsh -NoProfile -File lib/wm.ps1:*)')
    $rules.Add('PowerShell(sqlite3 *)')
    $src = Join-Path $script:WATCHMAN_ROOT 'commands'
    if (Test-Path $src) {
        Get-ChildItem -Path $src -Directory | Sort-Object Name | ForEach-Object {
            if (Test-Path (Join-Path $_.FullName 'SKILL.md')) { $rules.Add("Skill($($_.Name))") }
        }
    }
    return $rules
}

# --- resolver_op expansion (Windows arm) ------------------------------------
# Belt-and-suspenders: the Windows skills route observation through wm resolvers (covered by the
# framework base), but if a skill ever calls a cmdlet RAW, grant it here. Read-only cmdlets only.
function _pf_expand_resolver_op([string]$op) {
    switch ($op) {
        'pkg_query'       { @('winget list *', 'Get-Package *') }
        'service_status'  { @('Get-Service *') }
        'journal_read'    { @('Get-WinEvent *', 'Get-EventLog *') }
        'net_connections' { @('Get-NetTCPConnection *') }
        'firewall_list'   { @('Get-NetFirewallProfile *', 'Get-NetFirewallRule *') }
        'integrity_verify' { @('sfc *', 'dism *') }
        'mac_status'      { @('Get-MpComputerStatus *') }
        'sectool_status'  { @('Get-MpComputerStatus *', 'Get-NetFirewallProfile *', 'cscli *') }
        default           { @() }
    }
}

# --- fix_op expansion (FIX profile only; safe-tier ops are filtered by the caller) ----------
# Each line: "<allow-rule>`t<additional-dir-or-->". Mutating fns run through the APPLY dispatcher:
# PowerShell(pwsh -NoProfile -File lib/wm-apply.ps1 <fn>:*). config_edit on Windows is file-based
# (C:/ProgramData) PLUS the registry_set mutator (registry config can't be reached by Edit()).
function _pf_expand_fix_op([string]$op) {
    switch ($op) {
        'firewall_allow'  { @("PowerShell(pwsh -NoProfile -File lib/wm-apply.ps1 firewall_allow:*)`t-") }
        'firewall_deny'   { @("PowerShell(pwsh -NoProfile -File lib/wm-apply.ps1 firewall_deny:*)`t-") }
        'service_enable'  { @("PowerShell(pwsh -NoProfile -File lib/wm-apply.ps1 service_enable:*)`t-") }
        'service_restart' { @("PowerShell(pwsh -NoProfile -File lib/wm-apply.ps1 service_restart:*)`t-") }
        'config_edit'     { @(
                "Edit(C:/ProgramData/**)`tC:/ProgramData",
                "Write(C:/ProgramData/**)`tC:/ProgramData",
                "PowerShell(pwsh -NoProfile -File lib/wm-apply.ps1 registry_set:*)`t-"
            ) }
        default           { @() }
    }
}

# --- reads resolution -------------------------------------------------------
# A read entry is either a resolver token (a distro.ps1 function emitting ≥1 path) or a literal
# path. Tokens are resolved by CALLING the function; the journald/winevent sentinels are skipped
# (covered by the journal_read resolver_op, not a file Read). Linux literal paths are mapped to
# their Windows home; unmappable ones are skipped.
function _pf_resolve_read([string]$entry) {
    $out = [System.Collections.Generic.List[string]]::new()
    if ($entry -notmatch '^[A-Za-z]:[\\/]' -and $entry -notmatch '^/' -and (Get-Command $entry -ErrorAction SilentlyContinue)) {
        try {
            foreach ($line in (& $entry)) {
                $s = [string]$line
                if (-not $s) { continue }
                if ($s -like 'journald:*' -or $s -like 'winevent:*') { continue }
                $out.Add((_pf_winpath $s))
            }
        } catch {}
        return $out
    }
    if ($entry -like 'journald:*' -or $entry -like 'winevent:*') { return $out }
    if ($script:PF_LINUX_READ_MAP.ContainsKey($entry)) { $out.Add($script:PF_LINUX_READ_MAP[$entry]); return $out }
    if ($entry -match '^[A-Za-z]:[\\/]') { $out.Add((_pf_winpath $entry)) }
    return $out
}

function _pf_manifests {
    $skills = Join-Path $script:WATCHMAN_ROOT 'skills'
    if (-not (Test-Path $skills)) { return @() }
    Get-ChildItem -Path $skills -Recurse -Filter 'manifest.json' -File |
        Where-Object { ($_.FullName -replace '\\', '/') -match '/skills/[^/]+/[^/]+/manifest.json$' } |
        Sort-Object FullName
}

# --- Collation --------------------------------------------------------------
function preflight_collate {
    $allow = [System.Collections.Generic.List[string]]::new()
    $adddirs = [System.Collections.Generic.List[string]]::new()
    (_pf_framework_allow) | ForEach-Object { $allow.Add($_) }

    foreach ($m in (_pf_manifests)) {
        $j = $null
        try { $j = Get-Content -Raw -LiteralPath $m.FullName | ConvertFrom-Json } catch { continue }

        # reads → Read globs + additionalDirectories (Windows encoding, no slash-doubling).
        foreach ($r in @($j.reads)) {
            if (-not $r) { continue }
            foreach ($path in (_pf_resolve_read ([string]$r))) {
                if (-not $path) { continue }
                # If it's a file, grant its dir; if a dir (or unknown), grant it directly.
                $dir = if (Test-Path -LiteralPath $path -PathType Container) { $path }
                       elseif (Test-Path -LiteralPath $path) { _pf_winpath (Split-Path -Parent $path) }
                       else { $path }
                $allow.Add("Read($dir/**)")
                $adddirs.Add($dir)
            }
        }

        # direct commands → PowerShell(<cmd> *), skipping Linux-only families (handled inside wm).
        foreach ($c in @($j.commands)) {
            if (-not $c.family) { continue }
            # Skip Linux-only families and any absolute POSIX path (a Linux binary) — on Windows
            # that observation runs inside the wm dispatcher, covered by the framework base rule.
            if ($c.family -like '/*') { continue }
            $famLeaf = (Split-Path -Leaf $c.family)
            if (($script:PF_LINUX_ONLY_CMDS -contains $c.family) -or ($script:PF_LINUX_ONLY_CMDS -contains $famLeaf)) { continue }
            $args = if ($c.args -and $c.args -ne 'null') { $c.args } else { '*' }
            $allow.Add("PowerShell($($c.family) $args)")
        }

        # resolver_ops → concrete per-family (Windows) cmdlet rules.
        foreach ($op in @($j.resolver_ops)) {
            if (-not $op) { continue }
            foreach ($r in (_pf_expand_resolver_op ([string]$op))) { $allow.Add("PowerShell($r)") }
        }
    }

    ($allow | Where-Object { $_ } | Sort-Object -Unique) | Set-Content -LiteralPath (Join-Path $script:WATCHMAN_ROOT '.pf.allow')
    ($adddirs | Where-Object { $_ } | Sort-Object -Unique) | Set-Content -LiteralPath (Join-Path $script:WATCHMAN_ROOT '.pf.dirs')
}

# --- FIX-profile collation (tier-aware: SAFE ops only) ----------------------
function _pf_collate_fix {
    $allow = [System.Collections.Generic.List[string]]::new()
    $dirs = [System.Collections.Generic.List[string]]::new()
    foreach ($m in (_pf_manifests)) {
        $j = $null
        try { $j = Get-Content -Raw -LiteralPath $m.FullName | ConvertFrom-Json } catch { continue }
        foreach ($f in @($j.fixes)) {
            if (-not $f.op) { continue }
            $tier = if ($f.risk_tier) { $f.risk_tier } else { 'manual' }
            if ($tier -ne 'safe') { continue }   # tier-aware: safe ops auto-granted; review prompts; manual never
            foreach ($entry in (_pf_expand_fix_op ([string]$f.op))) {
                $parts = $entry -split "`t", 2
                $allow.Add($parts[0])
                if ($parts.Count -gt 1 -and $parts[1] -and $parts[1] -ne '-') { $dirs.Add($parts[1]) }
            }
        }
    }
    ($allow | Where-Object { $_ } | Sort-Object -Unique) | Set-Content -LiteralPath (Join-Path $script:WATCHMAN_ROOT '.pf.fix.allow')
    ($dirs | Where-Object { $_ } | Sort-Object -Unique) | Set-Content -LiteralPath (Join-Path $script:WATCHMAN_ROOT '.pf.fix.dirs')
}

# --- Deny base (the backstop, shared by ALL profiles; Windows namespace) ----
# Alias-matching helps here: PowerShell(Remove-Item *) also catches del/rm/ri. Registry-hive
# files (SAM/SECURITY/SYSTEM) are the /etc/shadow analogue.
function _pf_deny_base {
    @(
        'Read(.env)'
        'Read(./.env)'
        'PowerShell(Remove-Item *)'
        'PowerShell(Remove-ItemProperty *)'
        'PowerShell(rmdir *)'
        'PowerShell(del *)'
        'PowerShell(Clear-Disk *)'
        'PowerShell(Format-Volume *)'
        'PowerShell(Stop-Service *)'
        'PowerShell(Disable-WindowsOptionalFeature *)'
        'PowerShell(Remove-NetFirewallRule *)'
        'PowerShell(Stop-Computer *)'
        'PowerShell(Restart-Computer *)'
        'PowerShell(Disable-LocalUser *)'
        'PowerShell(Remove-LocalUser *)'
        'PowerShell(Reset-ComputerMachinePassword *)'
        'Edit(C:/Windows/System32/config/**)'
        'Write(C:/Windows/System32/config/**)'
    )
}

# --- Base policy (dontAsk + deny base; never clobber operator tuning) --------
function preflight_write_base_settings([string]$claude_dir) {
    New-Item -ItemType Directory -Force -Path $claude_dir | Out-Null
    $target = Join-Path $claude_dir 'settings.json'
    $deny = @(_pf_deny_base)
    if (Test-Path -LiteralPath $target) {
        $cur = $null
        try { $cur = Get-Content -Raw -LiteralPath $target | ConvertFrom-Json } catch {}
        $obj = if ($cur) { $cur } else { [pscustomobject]@{} }
        if (-not $obj.permissions) { $obj | Add-Member -NotePropertyName permissions -NotePropertyValue ([pscustomobject]@{}) -Force }
        # Re-assert BOTH contracts non-destructively: defaultMode=dontAsk, and union the deny base.
        $obj.permissions | Add-Member -NotePropertyName defaultMode -NotePropertyValue 'dontAsk' -Force
        $existing = @(); if ($obj.permissions.deny) { $existing = @($obj.permissions.deny) }
        $merged = @($existing) + @($deny | Where-Object { $existing -notcontains $_ })
        $obj.permissions | Add-Member -NotePropertyName deny -NotePropertyValue $merged -Force
        ($obj | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $target
        Write-Host "preflight: repaired base settings.json (dontAsk + deny base re-asserted)."
        return
    }
    $base = [pscustomobject]@{ permissions = [pscustomobject]@{ defaultMode = 'dontAsk'; deny = $deny } }
    ($base | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $target
    Write-Host "preflight: wrote base policy $target"
}

function _pf_read_lines([string]$file) {
    if (Test-Path -LiteralPath $file) { return @(Get-Content -LiteralPath $file | Where-Object { $_ }) }
    return @()
}

function preflight_write_local_settings([string]$claude_dir) {
    $target = Join-Path $claude_dir 'settings.local.json'
    $allow = _pf_read_lines (Join-Path $script:WATCHMAN_ROOT '.pf.allow')
    $dirs = _pf_read_lines (Join-Path $script:WATCHMAN_ROOT '.pf.dirs')
    $obj = [pscustomobject]@{ permissions = [pscustomobject]@{ allow = $allow; additionalDirectories = $dirs } }
    ($obj | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $target
    Write-Host "preflight: wrote agent allowlist $target ($($allow.Count) allow rules)"
}

function preflight_write_fix_settings([string]$claude_dir) {
    $target = Join-Path $claude_dir 'settings.fix.json'
    $allow = @(_pf_read_lines (Join-Path $script:WATCHMAN_ROOT '.pf.allow')) +
             @(_pf_read_lines (Join-Path $script:WATCHMAN_ROOT '.pf.fix.allow')) +
             @('WebSearch', 'WebFetch') | Where-Object { $_ } | Sort-Object -Unique
    $dirs = @(_pf_read_lines (Join-Path $script:WATCHMAN_ROOT '.pf.dirs')) +
            @(_pf_read_lines (Join-Path $script:WATCHMAN_ROOT '.pf.fix.dirs')) | Where-Object { $_ } | Sort-Object -Unique
    $obj = [pscustomobject]@{ permissions = [pscustomobject]@{
        defaultMode = 'default'; deny = @(_pf_deny_base); allow = $allow; additionalDirectories = $dirs } }
    ($obj | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $target
    Write-Host "preflight: wrote fix profile $target ($($allow.Count) allow rules, default mode)"
}

function preflight_write_dev_settings([string]$claude_dir) {
    $target = Join-Path $claude_dir 'settings.dev.json'
    $root = _pf_winpath $script:WATCHMAN_ROOT
    $allow = @(
        "Read($root/**)", "Edit($root/**)", "Write($root/**)",
        'PowerShell(pwsh -NoProfile -File lib/wm.ps1:*)',
        'PowerShell(git *)', 'PowerShell(sqlite3 *)', 'Skill(watchman)'
    )
    $obj = [pscustomobject]@{ permissions = [pscustomobject]@{
        defaultMode = 'acceptEdits'; deny = @(_pf_deny_base); allow = $allow; additionalDirectories = @($root) } }
    ($obj | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $target
    Write-Host "preflight: wrote dev profile $target (acceptEdits, repo-write)"
}

# --- The two-string dispatcher rewrite (knot 2) -----------------------------
# The committed skills say `bash lib/wm` / `WM_APPLY=1 bash lib/wm`, which can't run on Windows.
# Rewrite (longest match FIRST) to the pwsh dispatchers. This is the ENTIRE platform-coupled
# surface of a skill; everything else copies verbatim.
function _pf_rewrite_dispatch([string]$text) {
    $text = $text -replace [regex]::Escape('WM_APPLY=1 bash lib/wm'), 'pwsh -NoProfile -File lib/wm-apply.ps1'
    $text = $text -replace [regex]::Escape('bash lib/wm'), 'pwsh -NoProfile -File lib/wm.ps1'
    return $text
}
# The orchestrator names sub-skill PATHS (skills/grammar/…); point them at the deployed Windows
# mirror so it reads the rewritten copies, not the in-place bash ones.
function _pf_rewrite_skillpaths([string]$text) {
    foreach ($stage in @('grammar', 'logic', 'rhetoric')) {
        $text = $text -replace [regex]::Escape("skills/$stage/"), ".claude/wm-skills/$stage/"
    }
    return $text
}

# --- Deploy the rewritten Windows skill tree + in-session commands ----------
function preflight_deploy_commands {
    $claude = $script:WATCHMAN_CLAUDE_DIR
    # 1. Mirror grammar/logic/rhetoric skills with the dispatcher rewrite into .claude/wm-skills/.
    $skillsSrc = Join-Path $script:WATCHMAN_ROOT 'skills'
    $mirror = Join-Path $claude 'wm-skills'
    $nSkills = 0
    if (Test-Path $skillsSrc) {
        Get-ChildItem -Path $skillsSrc -Recurse -Filter 'SKILL.md' -File | ForEach-Object {
            $rel = ($_.FullName.Substring($skillsSrc.Length)).TrimStart('\', '/')
            $dst = Join-Path $mirror $rel
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
            $txt = _pf_rewrite_dispatch (Get-Content -Raw -LiteralPath $_.FullName)
            Set-Content -LiteralPath $dst -Value $txt
            $nSkills++
        }
    }
    # 2. Deploy each commands/<name>/SKILL.md as the /<name> slash command, rewriting BOTH the
    #    dispatcher invocations AND the sub-skill paths (so it reads the mirror above).
    $src = Join-Path $script:WATCHMAN_ROOT 'commands'
    $dst = Join-Path $claude 'skills'
    $n = 0
    if (Test-Path $src) {
        Get-ChildItem -Path $src -Directory | Sort-Object Name | ForEach-Object {
            $skill = Join-Path $_.FullName 'SKILL.md'
            if (-not (Test-Path $skill)) { return }
            New-Item -ItemType Directory -Force -Path (Join-Path $dst $_.Name) | Out-Null
            $txt = _pf_rewrite_skillpaths (_pf_rewrite_dispatch (Get-Content -Raw -LiteralPath $skill))
            Set-Content -LiteralPath (Join-Path (Join-Path $dst $_.Name) 'SKILL.md') -Value $txt
            $n++
        }
    }
    Write-Host "preflight: deployed $n command skill(s) + mirrored $nSkills rewritten skill file(s)"
}

# --- Public entry -----------------------------------------------------------
function preflight_run {
    preflight_collate
    _pf_collate_fix
    preflight_write_base_settings  $script:WATCHMAN_CLAUDE_DIR
    preflight_write_local_settings $script:WATCHMAN_CLAUDE_DIR
    preflight_write_fix_settings   $script:WATCHMAN_CLAUDE_DIR
    preflight_write_dev_settings   $script:WATCHMAN_CLAUDE_DIR
    preflight_deploy_commands
    foreach ($f in @('.pf.allow', '.pf.dirs', '.pf.fix.allow', '.pf.fix.dirs')) {
        $p = Join-Path $script:WATCHMAN_ROOT $f
        if (Test-Path $p) { Remove-Item -LiteralPath $p -Force }
    }
}

if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.Line -notmatch '^\s*\.\s') {
    if ($args.Count -ge 1 -and $args[0] -eq 'run') { preflight_run }
}
