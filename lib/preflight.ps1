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
        'Read(//**/wp-config.php)'
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
        # Claude Code normalizes Windows paths to POSIX form before matching, so the rule form
        # its docs specify is //c/... The C:/ pair above is kept until this is confirmed on a
        # real Windows host; a redundant deny is harmless.
        'Edit(//c/Windows/System32/config/**)'
        'Write(//c/Windows/System32/config/**)'
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
        if (_pf_replace_settings $target $obj) {
            Write-Host "preflight: base settings.json checked (dontAsk + deny base re-asserted)."
        }
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

# --- Never lose a settings file to regeneration (mirror of lib/preflight.sh) --
# Overwriting is destructive under the Prime Directive, so a settings file whose content
# would change is first copied to journal/pre-update-backup-<stamp>-preflight/.claude/.
$script:_PF_BACKUP_DIR = $null
function _pf_replace_settings([string]$target, $obj) {
    $json = $obj | ConvertTo-Json -Depth 12
    if (Test-Path -LiteralPath $target) {
        $old = Get-Content -Raw -LiteralPath $target
        if ($old.TrimEnd() -eq $json.TrimEnd()) { return $true }
        if (-not $script:_PF_BACKUP_DIR) {
            $script:_PF_BACKUP_DIR = Join-Path $script:WATCHMAN_ROOT ("journal/pre-update-backup-{0}-{1}-preflight" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID)
        }
        try {
            $bdir = Join-Path $script:_PF_BACKUP_DIR '.claude'
            New-Item -ItemType Directory -Force -Path $bdir | Out-Null
            Copy-Item -LiteralPath $target -Destination $bdir -Force -ErrorAction Stop
        } catch {
            Write-Warning "preflight: could not back up $target - left it unchanged."
            return $false
        }
    }
    $json | Set-Content -LiteralPath $target
    return $true
}

# Can this command change the system? A second check under _pf_rule_carryable: Edit/Write,
# state-changing cmdlet verbs, native tools that write, network fetches, and any interpreter
# handed a script.
function _pf_rule_mutates([string]$rule) {
    if ($rule -match '^(Edit|Write|NotebookEdit)\(') { return $true }
    if ($rule -notmatch '^(PowerShell|Bash)\((.*)\)$') { return $false }
    $cmd = $Matches[2].Trim()
    if ($cmd -match '^(?i)(Set|New|Remove|Stop|Start|Restart|Enable|Disable|Install|Uninstall|Add|Clear|Copy|Move|Rename|Register|Unregister|Update|Suspend|Resume|Reset|Grant|Revoke|Mount|Dismount|Initialize|Format|Out|Export|Import|Publish|Unpublish|Unblock|Lock|Unlock)-') { return $true }
    if ($cmd -match '^(?i)(Invoke-WebRequest|Invoke-RestMethod|Invoke-Expression|Invoke-Command|Invoke-Item|iwr|irm|iex|curl|wget|del|erase|rd|rmdir|rm|mv|move|cp|copy|ren|ni|md|mkdir|sc|netsh|winget|choco|scoop|msiexec|icacls|takeown|attrib|bcdedit|diskpart|schtasks|wmic|net|reg|taskkill|shutdown|setx|robocopy|xcopy|ssh|scp)(\s|$)') {
        if ($cmd -match '^(?i)reg\s+(query|export)\b' -or $cmd -match '^(?i)sc\s+(query|qc|queryex)\b' -or $cmd -match '^(?i)net\s+(view|user|localgroup|share|session|statistics)(\s|$)(?!.*\s/(add|delete|active))') { return $false }
        return $true
    }
    if ($cmd -match '^(?i)git\s+(-C\s+\S+\s+)?(commit|push|pull|fetch|reset|checkout|switch|restore|merge|rebase|clean|stash|add|rm|mv|tag|branch|init|clone|apply|am|cherry-pick|revert)\b') { return $true }
    if ($cmd -match '^(?i)git\s.*(--output|--no-index|--ext-diff|--textconv|--exec|--upload-pack|--receive-pack|\s-c\s|--config)') { return $true }
    if ($cmd -match '^(?i)ipconfig\s.*/(release|renew|flushdns|registerdns|setclassid)') { return $true }
    if ($cmd -match '^(?i)(pwsh|powershell|cmd|bash|sh|python[0-9.]*|py|perl|ruby|node|php)(\.exe)?\s+(-File\s+|/c\s+)?[^-/]') { return $true }
    if ($cmd -match '^(?i)(pwsh|powershell)(\.exe)?\s+.*-(File|Command)\s') { return $true }
    return $false
}

# Is this path narrow enough to carry? Not a whole system tree (a drive root, Windows, Users,
# ProgramData, Program Files: the Windows homes of the trees `update --check` refuses), not
# home- or env-relative, no '..', and no wildcard except a trailing /* or /** on a specific path.
function _pf_path_narrow([string]$p) {
    if (-not $p -or $p -match '^(~|\$|%)' -or $p.Contains('..')) { return $false }
    # Unnormalised paths (C://Users//**, C:/./Users) would slip past the tree match below.
    $body = $p -replace '^(//?)?([A-Za-z]:)?', ''
    if ($body -match '[\\/]{2}|[\\/]\.([\\/]|$)|^\.([\\/]|$)') { return $false }
    # Windows path quirks that alias another path: 8.3 short names (~), trailing dots or
    # spaces, stream/device syntax (: past the drive), and variable or wildcard characters.
    if ($body -match '[~$?:]|[. ]([\\/]|$)') { return $false }
    if ($p -match '^//' -and $p -notmatch '^//[A-Za-z]/') { return $false }
    $stem = $p -replace '[\\/]\*\*?$', ''
    if ($stem.Contains('*')) { return $false }
    $tree = '^(?i)(/{0,2}[A-Za-z]:|//[A-Za-z]|/)?[\\/]*((Windows|Users|ProgramData|Program Files( \(x86\))?|Windows[\\/]System32)[\\/]*)?$'
    if ($stem -match $tree) { return $false }
    # A junction or symlink anywhere along the path can point at a whole tree, so any reparse
    # point among the components that exist on this host makes the path not narrow.
    $walk = ($stem -replace '^//([A-Za-z])/', '$1:/')
    while ($walk -and $walk -notmatch '^[A-Za-z]:[\\/]?$') {
        $item = Get-Item -LiteralPath $walk -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint))) { return $false }
        $parent = Split-Path -Parent $walk
        if (-not $parent -or $parent -eq $walk) { break }
        $walk = $parent
    }
    return $true
}

# Which operator rules may be carried into the read-only loop allowlist? An ALLOWLIST, as in
# _pf_rule_carryable in preflight.sh: a narrow Read, a read-only cmdlet or query form with any
# arguments, or a file-content reader only as the exact approved command (a wildcard one would
# read past the Read deny base). Pipes, redirection, chaining, subexpressions and the backtick
# escape are held, as is every bare tool name, MCP tool, Edit/Write and unknown command.
# Named cmdlets only, not Get-*: Get-ItemProperty and Get-CimInstance can read stored secrets
# (an autologon password, a process command line). Interpreters, sqlite3, and anything that
# takes a scriptblock are on no list, so they are always held.
$script:_PF_RO_ANYARGS = '(?i)^(Get-(Service|Process|NetTCPConnection|NetUDPEndpoint|NetFirewallProfile|NetFirewallRule|HotFix|Volume|PSDrive|Disk|Date|Command|Module|ScheduledTask|LocalUser|LocalGroup|MpComputerStatus|BitLockerVolume|ComputerInfo|FileHash)|Test-Path|Resolve-Path|whoami|hostname|systeminfo|tasklist|netstat|ver)(\s|:|$)'
$script:_PF_RO_PREFIX  = '(?i)^(sc(\.exe)?\s+(query|qc|queryex)|auditpol\s+/get|bcdedit\s+/enum|manage-bde\s+-status|netsh\s+\S+(\s+\S+)?\s+show)(\s|:|$)'
# net user/localgroup/share take a positional argument that SETS state (net user bob newpass),
# so only the bare listing or a single name, optionally /domain, is accepted, as a whole command.
$script:_PF_RO_EXACT   = '(?i)^((Get-Content|Select-String|Get-ChildItem|Get-Item|Get-Acl|type|more|findstr|cat|jq|ipconfig|git(\s+-C\s+\S+)?\s+(status|log|diff|show|rev-parse|ls-files|describe))(\s|$)|net\s+(view|session|statistics|(user|localgroup|share)(\s+[^\s/=]+)?)(\s+/domain)?$)'
function _pf_rule_carryable([string]$rule) {
    if ($rule -match '^Read\((.*)\)$') { return (_pf_path_narrow $Matches[1]) }
    if ($rule -notmatch '^(PowerShell|Bash)\((.*)\)$') { return $false }
    $cmd = $Matches[2].Trim()
    if (-not $cmd -or $cmd.StartsWith('*')) { return $false }
    if ($cmd -match '[|>;&`(){}\r\n]|\$\(|\$\\\(|@\(') { return $false }
    # Arguments must be plain filesystem paths, not provider paths (HKLM:, Env:, Cert:,
    # Registry::, Microsoft.PowerShell.Core\Environment:: ...). An allowlist: the only
    # "<name>:" accepted is a single drive letter, and any "::" is refused.
    if ($cmd.Contains('::') -or $cmd -match '(?i)(^|[\s''"\\/])[A-Za-z][A-Za-z0-9_.\\-]+:') { return $false }
    if (_pf_rule_mutates "PowerShell($cmd)") { return $false }
    if ($cmd -match $script:_PF_RO_ANYARGS) { return $true }
    if ($cmd -match $script:_PF_RO_PREFIX) { return $true }
    if (-not $cmd.Contains('*') -and $cmd -match $script:_PF_RO_EXACT) { return $true }
    return $false
}

# Claude Code saves the operator's "always allow" approvals into settings.local.json, so it is
# not regenerated wholesale: the generated rules are recorded in .watchman-generated.json and
# anything else in the file is the operator's. With no record yet (an older install), only rules
# the current generator produces count as generated, since the Windows generator has always
# written the same rule forms. Only operator rules _pf_rule_carryable recognises as read-only are
# carried into this read-only loop profile, and only the rule lists: any other key (defaultMode,
# hooks, env ...) would outrank the base settings.json. deny and ask are carried because they only
# tighten. Everything held is listed and kept in the backup.
function preflight_write_local_settings([string]$claude_dir) {
    $target = Join-Path $claude_dir 'settings.local.json'
    $record = Join-Path $claude_dir '.watchman-generated.json'
    $allow = @(_pf_read_lines (Join-Path $script:WATCHMAN_ROOT '.pf.allow'))
    $dirs = @(_pf_read_lines (Join-Path $script:WATCHMAN_ROOT '.pf.dirs'))
    $kept = [System.Collections.Generic.List[string]]::new()
    $held = [System.Collections.Generic.List[string]]::new()
    $keptDirs = [System.Collections.Generic.List[string]]::new()
    $cur = $null
    if (Test-Path -LiteralPath $target) { try { $cur = Get-Content -Raw -LiteralPath $target | ConvertFrom-Json } catch { $cur = $null } }
    if ($cur -and $cur.permissions) {
        $prevAllow = @(); $prevDirs = @()
        if (Test-Path -LiteralPath $record) {
            try {
                $rec = Get-Content -Raw -LiteralPath $record | ConvertFrom-Json
                $prevAllow = @($rec.allow); $prevDirs = @($rec.additionalDirectories)
            } catch {}
        }
        foreach ($r in @($cur.permissions.allow)) {
            if (-not ($r -is [string]) -or -not $r) { continue }
            if ($allow -ccontains $r -or $prevAllow -ccontains $r -or $kept -ccontains $r) { continue }
            if (_pf_rule_carryable $r) { $kept.Add($r) } else { $held.Add($r) }
        }
        foreach ($d in @($cur.permissions.additionalDirectories)) {
            if (-not ($d -is [string]) -or -not $d) { continue }
            if ($dirs -ccontains $d -or $prevDirs -ccontains $d -or $keptDirs -ccontains $d) { continue }
            if (_pf_path_narrow $d) { $keptDirs.Add($d) } else { $held.Add("additionalDirectories: $d") }
        }
    }
    if ($cur) {
        foreach ($k in $cur.PSObject.Properties.Name) { if ($k -ne 'permissions') { $held.Add("setting: $k") } }
        if ($cur.permissions) {
            foreach ($k in $cur.permissions.PSObject.Properties.Name) {
                if (@('allow', 'additionalDirectories', 'deny', 'ask') -notcontains $k) { $held.Add("setting: permissions.$k") }
            }
        }
    }
    $perm = [ordered]@{
        allow = @(@($allow) + @($kept) | Select-Object -Unique)
        additionalDirectories = @(@($dirs) + @($keptDirs) | Select-Object -Unique)
    }
    foreach ($k in @('deny', 'ask')) {
        # Built outside an if-expression: PowerShell unwraps a one-item array returned from one.
        $v = @()
        if ($cur -and $cur.permissions) { $v = @($cur.permissions.$k | Where-Object { $_ -is [string] }) }
        if ($v.Count -gt 0) { $perm[$k] = $v }
    }
    $obj = [pscustomobject]@{ permissions = [pscustomobject]$perm }
    if (-not (_pf_replace_settings $target $obj)) { return }
    ([pscustomobject]@{ allow = @($allow); additionalDirectories = @($dirs) } | ConvertTo-Json -Depth 4) |
        Set-Content -LiteralPath $record
    Write-Host "preflight: wrote agent allowlist $target ($($allow.Count + $kept.Count) allow rules)"
    if (($kept.Count + $keptDirs.Count) -gt 0) {
        Write-Host "preflight: kept $($kept.Count + $keptDirs.Count) operator-approved rule(s)/dir(s) already in that file."
    }
    if ($held.Count -gt 0) {
        Write-Warning ("preflight: $($held.Count) operator-approved rule(s)/setting(s) are not recognisably read-only, " +
            "so they were NOT carried into the read-only loop allowlist (dontAsk would run them unattended):")
        $held | ForEach-Object { Write-Host "    $_" }
        Write-Host "  The previous file, with these rules, is saved in $($script:_PF_BACKUP_DIR)/.claude/"
        Write-Host "  In the loop they now auto-deny; for remediation work use 'watchman fix', which prompts for each."
    }
    if ($script:_PF_BACKUP_DIR) { Write-Host "preflight: previous settings saved to $($script:_PF_BACKUP_DIR)/.claude/" }
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
    if (-not (_pf_replace_settings $target $obj)) { return }
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
    if (-not (_pf_replace_settings $target $obj)) { return }
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
