# lib/distro.ps1 — the resolver for the HOW (Windows-native PowerShell port of lib/distro.sh).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# These PS libs run ONLY on Windows (the platform router picks bash on Linux/macOS), so each
# function implements just the Windows behavior — Windows is the one "family" here. The PUBLIC
# function names and their stdout/exit contracts match lib/distro.sh exactly, so the shared,
# install-rewritten skills stay family-blind and call them identically. Mutating ops (pkg_install,
# service_enable/restart, firewall_allow/deny, registry_set) only ever run via wm-apply.ps1.
#
# Every cmdlet call is guarded (Get-Command / try-catch) so the file also parses and smoke-runs on
# a non-Windows host with safe defaults — which is how the port is statically tested.

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# --- Family detection -------------------------------------------------------
function watchman_detect_family {
    if ($env:WATCHMAN_FAMILY) { return $env:WATCHMAN_FAMILY }
    $env:WATCHMAN_FAMILY = 'windows'
    return 'windows'
}
function watchman_family { return (watchman_detect_family) }

# True on Windows Server SKUs (ProductType 2=domain controller, 3=server), else workstation.
function _is_server_sku {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        return ($os.ProductType -ne 1)
    } catch { return $false }
}

# --- Package operations -----------------------------------------------------
# "Packages" on Windows = winget packages + Windows capabilities/features.
function pkg_is_installed {
    param([string]$p)
    if (_have 'Get-Package') {
        try { if (Get-Package -Name $p -ErrorAction SilentlyContinue) { return $true } } catch {}
    }
    if (_have 'winget') {
        try { $out = winget list --id $p --exact 2>$null; if ($LASTEXITCODE -eq 0 -and $out -match $p) { return $true } } catch {}
    }
    return $false
}

# MUTATING — installer/operator only; absent from the loop's allowlist.
function pkg_install {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$pkgs)
    if (-not (_have 'winget')) { [Console]::Error.WriteLine('pkg_install: winget not available'); return (Wm-Exit 2) }
    foreach ($p in $pkgs) { winget install --id $p --accept-source-agreements --accept-package-agreements -e }
}

# NON-mutating: the install command for the operator to run (not executed here).
function pkg_install_cmd { return 'winget install --id' }

# NON-mutating: map a generic command name to its Windows package id (mostly identity).
function pkg_for_cmd {
    param([string]$cmd)
    switch ($cmd) {
        'sqlite3' { return 'SQLite.SQLite' }
        'cscli'   { return 'CrowdSec.CrowdSec' }
        default   { return $cmd }
    }
}

# NON-mutating: the command that APPLIES pending updates (shown to the operator, never run).
function security_update_cmd { return 'winget upgrade --all  (and: Install-WindowsUpdate -AcceptAll from PSWindowsUpdate)' }

# Days since the update view was last refreshed; -1 when unknown. Read-only, no network.
function pkg_db_age_days {
    # Windows Update last successful search time (registry), the closest analogue to apt's stamp.
    try {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect'
        $v = (Get-ItemProperty -Path $k -Name 'LastSuccessTime' -ErrorAction Stop).LastSuccessTime
        $when = [datetime]::Parse($v)
        return [string][int]((Get-Date) - $when).TotalDays
    } catch { return '-1' }
}

function vuln_scanner {
    if (_have 'Get-WindowsUpdate') { return 'pswindowsupdate' }   # PSWindowsUpdate security category
    return 'none'
}
function vuln_scan {
    if (-not (_have 'Get-WindowsUpdate')) { return (Wm-Exit 2) }
    try { Get-WindowsUpdate -MicrosoftUpdate -Category 'Security Updates' -ErrorAction Stop |
            ForEach-Object { "$($_.KB) $($_.Title)" } } catch { return (Wm-Exit 2) }
}

function pkg_list_installed {
    if (_have 'Get-Package') { try { return (Get-Package -ErrorAction Stop | ForEach-Object { $_.Name }) } catch {} }
    if (_have 'winget') { try { return (winget list 2>$null | Select-Object -Skip 2) } catch {} }
    return (Wm-Exit 2)
}
function pkg_list_upgradable {
    if (_have 'Get-WindowsUpdate') { try { return (Get-WindowsUpdate -ErrorAction Stop | ForEach-Object { $_.KB }) } catch {} }
    if (_have 'winget') { try { return (winget upgrade 2>$null | Select-Object -Skip 2 | ForEach-Object { ($_ -split '\s{2,}')[0] }) } catch {} }
    return (Wm-Exit 2)
}

# --- Service operations -----------------------------------------------------
function service_status {
    param([string]$s)
    try {
        $svc = Get-Service -Name $s -ErrorAction Stop
        if ($svc.Status -eq 'Running') { return 'active' } else { return 'inactive' }
    } catch { return 'inactive' }
}
function service_enabled {
    param([string]$s)
    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction Stop
        if ($svc -and $svc.StartMode -in @('Auto', 'Automatic')) { return 'enabled' } else { return 'disabled' }
    } catch { return 'disabled' }
}
function service_enable {   # MUTATING
    param([string]$s)
    Set-Service -Name $s -StartupType Automatic
    Start-Service -Name $s
}
function service_restart {  # MUTATING
    param([string]$s)
    Restart-Service -Name $s -Force
}

# --- Firewall operations ----------------------------------------------------
# Windows Defender Firewall is the one backend. firewall_list is read-only; allow/deny are
# MUTATING and (Prime Directive + risk tiers) must be shown exactly and confirmed per-rule.
function watchman_firewall_backend {
    if ($env:WATCHMAN_FIREWALL) { return $env:WATCHMAN_FIREWALL }
    $b = if (_have 'Get-NetFirewallProfile') { 'defender' } else { 'none' }
    $env:WATCHMAN_FIREWALL = $b
    return $b
}
function firewall_list {
    if (-not (_have 'Get-NetFirewallProfile')) { [Console]::Error.WriteLine('firewall_list: no backend detected'); return (Wm-Exit 2) }
    try {
        Get-NetFirewallProfile | ForEach-Object { "{0}: enabled={1} inbound={2} outbound={3}" -f $_.Name, $_.Enabled, $_.DefaultInboundAction, $_.DefaultOutboundAction }
        Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
            Select-Object -First 200 | ForEach-Object { "allow-in: $($_.DisplayName)" }
    } catch { [Console]::Error.WriteLine("firewall_list: $($_.Exception.Message)"); return (Wm-Exit 2) }
}
# MUTATING — review-tier. spec = PORT/proto e.g. 443/tcp
function firewall_allow {
    param([string]$spec)
    $parts = $spec -split '/'
    $port = $parts[0]; $proto = if ($parts.Count -gt 1) { $parts[1].ToUpper() } else { 'TCP' }
    New-NetFirewallRule -DisplayName "watchman-allow-$port-$proto" -Direction Inbound -Action Allow -Protocol $proto -LocalPort $port -Profile Any | Out-Null
    "allowed $proto/$port"
}
function firewall_deny {    # MUTATING — review-tier
    param([string]$spec)
    $parts = $spec -split '/'
    $port = $parts[0]; $proto = if ($parts.Count -gt 1) { $parts[1].ToUpper() } else { 'TCP' }
    New-NetFirewallRule -DisplayName "watchman-deny-$port-$proto" -Direction Inbound -Action Block -Protocol $proto -LocalPort $port -Profile Any | Out-Null
    "blocked $proto/$port"
}

# --- Registry config edits (Windows config_edit; NEW mutator) --------------
# config_edit on Windows often targets the registry, which an Edit()/Write() permission rule
# cannot reach — so it is a gated mutator, applied only through wm-apply.ps1.
function registry_set {     # MUTATING
    param([string]$path, [string]$name, [string]$value, [string]$type = 'String')
    New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $path -Name $name -Value $value -Type $type
    "set $path\$name = $value"
}

# --- Log paths --------------------------------------------------------------
# The Windows auth trail lives in the Security event log, not a flat file. The sentinel tells
# callers (and the preflight) to read via Get-WinEvent rather than opening a file.
function log_path_auth { return 'winevent:Security' }

# Lynis has no Windows port; audit-system uses native checks (windows_hardening_scan). Returning
# empty makes the preflight grant no Read for this token on Windows.
function log_path_lynis { return '' }

# --- Web server discovery ---------------------------------------------------
# IIS is the primary Windows web server; nginx/apache also run on Windows. Output matches
# distro.sh: "<server>\t<config_root>" lines.
function webserver_detect {
    if ((Test-Path 'C:\inetpub') -or (_have 'Get-Website') -or ((service_status 'W3SVC') -eq 'active')) {
        "iis`tC:\Windows\System32\inetsrv\config"
    }
    foreach ($n in @('C:\nginx', "$env:ProgramFiles\nginx")) { if ($n -and (Test-Path $n)) { "nginx`t$n"; break } }
    foreach ($a in @("$env:ProgramFiles\Apache24\conf", 'C:\Apache24\conf')) { if ($a -and (Test-Path $a)) { "apache`t$a"; break } }
}
function webserver_config_roots {
    webserver_detect | ForEach-Object { ($_ -split "`t")[1] } | Where-Object { $_ } | Sort-Object -Unique
}
function webserver_log_paths {
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $results = [System.Collections.Generic.List[string]]::new()
    function _add([string]$d) { if ($d -and $seen.Add($d)) { $results.Add($d) } }

    foreach ($row in (webserver_detect)) {
        $server = ($row -split "`t")[0]
        switch ($server) {
            'iis'    { _add 'C:\inetpub\logs\LogFiles' }
            'nginx'  { $r = ($row -split "`t")[1]; if ($r) { _add (Join-Path $r 'logs') } }
            'apache' { $r = ($row -split "`t")[1]; if ($r) { _add (Join-Path (Split-Path -Parent $r) 'logs') } }
        }
    }
    foreach ($p in @('C:\inetpub\logs\LogFiles', 'C:\nginx\logs')) { if (Test-Path $p) { _add $p } }
    if ($results.Count -eq 0) { _add 'C:\inetpub\logs\LogFiles' }
    return $results
}
function log_path_webserver { return (webserver_log_paths | Select-Object -First 1) }

# --- "Mandatory Access Control" analogue ------------------------------------
# Windows has no AppArmor/SELinux. The closest "is the protection layer enforcing" signal is
# Microsoft Defender real-time protection. Echoes layer + state like distro.sh.
function mac_layer { return 'defender' }
function mac_state {
    if (-not (_have 'Get-MpComputerStatus')) { return 'absent' }
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        if ($s.RealTimeProtectionEnabled) { return 'enforcing' } else { return 'disabled' }
    } catch { return 'absent' }
}

# --- Auto-update mechanism --------------------------------------------------
function autoupdate_mechanism { return 'windowsupdate' }
function autoupdate_enabled {   # 0=enabled, 1=not, 2=n/a
    # NoAutoUpdate=0 (or absent) means automatic updates are on.
    try {
        $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        if (Test-Path $k) {
            $v = (Get-ItemProperty -Path $k -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue).NoAutoUpdate
            if ($v -eq 1) { return (Wm-Exit 1) }
        }
        if ((service_enabled 'wuauserv') -eq 'disabled') { return (Wm-Exit 1) }
        return (Wm-Exit 0)
    } catch { return (Wm-Exit 1) }
}

# --- Package/file integrity verifier ---------------------------------------
function integrity_verifier {
    if (_have 'sfc') { return 'sfc' }
    return 'none'
}
function integrity_verify_all {
    # System File Checker is the heaviest read; run it through io_run when io-courtesy is loaded.
    $runner = { param($block) if (Get-Command io_run -ErrorAction SilentlyContinue) { io_run @block } else { & $block[0] @($block[1..($block.Count-1)]) } }
    if (-not (_have 'sfc')) { [Console]::Error.WriteLine('integrity: no verifier available'); return (Wm-Exit 2) }
    try {
        # sfc /verifyonly reports integrity-violation status without repairing (read-only).
        $out = & sfc.exe /verifyonly 2>&1
        $joined = ($out -join "`n")
        if ($joined -match 'did not find any integrity violations') { return }
        if ($joined -match 'found.*integrity violations') { "sfc: integrity violations detected (see %windir%\Logs\CBS\CBS.log)" }
        # DISM component-store health (read-only CheckHealth).
        if (_have 'dism') {
            $d = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1
            if (($d -join "`n") -notmatch 'No component store corruption detected') { "dism: component store corruption flagged" }
        }
    } catch { [Console]::Error.WriteLine("integrity: $($_.Exception.Message)"); return (Wm-Exit 2) }
}

# --- Control panel ----------------------------------------------------------
# cPanel/WHM is Linux-only; on Windows these self-gate to empty (as cPanel does off non-cPanel).
function control_panel_detect { return '' }
function cpanel_version { return '' }
function cpanel_log_paths { return }

# --- Crash / OOM postmortem events (diagnose-crash on Windows) --------------
# The journald-equivalent for diagnose-crash. Walks the Windows event logs for the crash/abnormal
# -shutdown signals: System 41 (kernel power / dirty shutdown), 6008 (unexpected shutdown),
# 1001 (BugCheck/BSOD), and Application 1000/1001 (app crash / WER). Read-only; one line per event:
#   "<time>`t<log>`t<id>`t<source>`t<message-first-line>". diagnose-crash journals from these.
function diagnose_crash_events {
    param([int]$days = 14)
    if (-not (_have 'Get-WinEvent')) { [Console]::Error.WriteLine('diagnose_crash_events: Get-WinEvent unavailable'); return }
    $since = (Get-Date).AddDays(-1 * [math]::Abs($days))
    $specs = @(
        @{ Log = 'System';      Ids = @(41, 6008, 1001) },
        @{ Log = 'Application'; Ids = @(1000, 1001) }
    )
    foreach ($spec in $specs) {
        try {
            Get-WinEvent -FilterHashtable @{ LogName = $spec.Log; Id = $spec.Ids; StartTime = $since } -ErrorAction Stop |
                ForEach-Object {
                    $msg = ($_.Message -split "`n")[0]
                    "{0}`t{1}`t{2}`t{3}`t{4}" -f $_.TimeCreated.ToString('o'), $spec.Log, $_.Id, $_.ProviderName, $msg
                }
        } catch {}   # no matching events is the common, healthy case
    }
}

# --- Native Windows hardening scan (audit-system on Windows) ----------------
# Lynis has no Windows port, so audit-system on Windows runs this native hardening set and journals
# each result with the same category/severity/risk_tier shape, plus a trackable hardening score.
# Runs INSIDE the wm dispatcher, so its cmdlets need no extra allowlist (framework base covers it).
function windows_hardening_scan {
    $family = 'windows'
    $profile = if (Get-Command watchman_profile -ErrorAction SilentlyContinue) { watchman_profile } else { 'workstation' }
    $checks = 0; $passed = 0
    function _hard([string]$check_id, [string]$severity, [string]$risk_tier, [bool]$ok, [string]$title, [string]$detail, [string]$remediation) {
        $script:_h_checks++
        if ($ok) { $script:_h_passed++; return }
        if (Get-Command journal_upsert -ErrorAction SilentlyContinue) {
            journal_upsert $family $profile 'security' $severity $risk_tier $check_id '' $title $detail $remediation | Out-Null
        } else {
            "FINDING $check_id [$severity/$risk_tier]: $title"
        }
    }
    $script:_h_checks = 0; $script:_h_passed = 0

    # Defender real-time protection + signature freshness
    $mp = $null; if (_have 'Get-MpComputerStatus') { try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {} }
    _hard 'defender_realtime' 'high' 'review' ([bool]($mp -and $mp.RealTimeProtectionEnabled)) `
        'Microsoft Defender real-time protection is off' 'RealTimeProtectionEnabled is false or Defender is unavailable.' 'Enable: Set-MpPreference -DisableRealtimeMonitoring $false'
    $sigOld = $false; if ($mp) { $sigOld = ($mp.AntivirusSignatureAge -gt 7) }
    _hard 'defender_signatures' 'medium' 'safe' (-not $sigOld) `
        'Defender signatures are stale' 'AntivirusSignatureAge exceeds 7 days.' 'Update: Update-MpSignature'

    # BitLocker on the system drive
    $bl = $null; if (_have 'Get-BitLockerVolume') { try { $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch {} }
    _hard 'bitlocker_systemdrive' 'medium' 'manual' ([bool]($bl -and $bl.ProtectionStatus -eq 'On')) `
        'System drive is not BitLocker-encrypted' 'ProtectionStatus is not On for the system drive.' 'Enable BitLocker via Manage-bde or the Control Panel; requires a recovery-key decision.'

    # UAC enabled
    $uac = $null; try { $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction Stop).EnableLUA } catch {}
    _hard 'uac_enabled' 'high' 'review' ($uac -eq 1) `
        'User Account Control (UAC) is disabled' 'EnableLUA is not 1.' 'Set EnableLUA=1 (requires reboot).'

    # All firewall profiles enabled
    $fwOk = $false; if (_have 'Get-NetFirewallProfile') { try { $fwOk = -not (Get-NetFirewallProfile | Where-Object { -not $_.Enabled }) } catch {} }
    _hard 'firewall_profiles_enabled' 'high' 'review' $fwOk `
        'A Windows Firewall profile is disabled' 'One or more of Domain/Private/Public profiles is not enabled.' 'Enable: Set-NetFirewallProfile -All -Enabled True'

    # SMBv1 absent (legacy, wormable)
    $smb1 = $null; if (_have 'Get-WindowsOptionalFeature') { try { $smb1 = (Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop).State } catch {} }
    _hard 'smb1_disabled' 'high' 'review' ($smb1 -ne 'Enabled') `
        'SMBv1 is enabled' 'The legacy SMB1Protocol feature is enabled.' 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'

    # RDP NLA required (only meaningful if RDP is enabled)
    $rdpDenied = $null; try { $rdpDenied = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop).fDenyTSConnections } catch {}
    if ($rdpDenied -eq 0) {
        $nla = $null; try { $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction Stop).UserAuthentication } catch {}
        _hard 'rdp_nla' 'high' 'review' ($nla -eq 1) `
            'RDP is enabled without Network Level Authentication' 'fDenyTSConnections=0 and UserAuthentication is not 1.' 'Require NLA: set UserAuthentication=1 on RDP-Tcp.'
    }

    # Windows Update service healthy
    _hard 'windowsupdate_service' 'medium' 'safe' ((service_enabled 'wuauserv') -ne 'disabled') `
        'Windows Update service is disabled' 'wuauserv StartMode is Disabled.' 'Set-Service wuauserv -StartupType Manual (or Automatic).'

    # Built-in Guest account disabled
    $guest = $null; try { $guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-501'" -ErrorAction Stop } catch {}
    _hard 'guest_disabled' 'medium' 'review' ([bool](-not $guest -or $guest.Disabled)) `
        'The built-in Guest account is enabled' 'A local account with RID 501 is not disabled.' 'Disable-LocalUser -Name Guest'

    # Record the hardening score (passed / total) as a trackable metric.
    if ($script:_h_checks -gt 0 -and (Get-Command journal_record_metric -ErrorAction SilentlyContinue)) {
        $score = [math]::Round(100.0 * $script:_h_passed / $script:_h_checks, 0)
        journal_record_metric 'windows_hardening_index' $score
    }
    "hardening: $($script:_h_passed)/$($script:_h_checks) checks passed"
}
