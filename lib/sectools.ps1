# lib/sectools.ps1 — discover the box's OWN defensive tooling and bring it into scope (Windows port).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# sectools is READ-ONLY. It detects installed defensive tools, reads their status/last-run state
# (never TRIGGERS a scan), and emits finding-candidates. It never installs, enables, or changes
# anything. Absent-defense findings are MANUAL tier; a degraded-tool finding is REVIEW tier.
#
# Windows mapping (PORT_CONVENTIONS): Defender (Get-MpComputerStatus) is the antivirus class;
# Windows Firewall is always present (no fail2ban analogue — brute_force is reported as a gap when
# CrowdSec/cscli is absent); Sysmon (if installed) is the host_audit/audit class; CrowdSec's cscli
# also runs on Windows and is wrapped where present. A class with no Windows tool reports 'absent'.
#
# Depends on lib/distro.ps1 + lib/profile.ps1 (loaded first by the dispatcher): it uses
# service_status / watchman_family / watchman_profile / profile_severity / pkg_install_cmd —
# each call is guarded so the file still parses/smoke-runs on a non-Windows host.
#
# OWNERSHIP BOUNDARY (so we never double-journal): where a dedicated engine owns a tool's deeper
# finding, sectools emits ONLY the `info` inventory row and counts the tool toward its defense
# class (defender signature staleness -> check-security-currency; crowdsec hub/alerts -> the
# currency/inspect-logs engines). Findings never collide (the fingerprint includes check_id), but
# deferring keeps the journal free of redundant rows.

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# --- The registry -----------------------------------------------------------
# One row per tool claude-watchman can observe on Windows. Pipe-separated columns:
#   id | defense_class | category | service
#     id            — canonical tool name (also the inventory finding's target)
#     defense_class — what protective capability it provides (drives absent-detection)
#     category      — finding category for the health row (inventory rows are config/info)
#     service       — Windows service name to check active/enabled, or '-' if none
$script:_ST_REGISTRY = @'
defender|antivirus|security|WinDefend
firewall|brute_force|security|MpsSvc
crowdsec|brute_force|security|crowdsec
sysmon|host_audit|security|Sysmon
auditpol|host_audit|security|-
'@

# Iterate the registry rows (blank lines stripped).
function _st_rows {
    $script:_ST_REGISTRY -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

# Emit one finding-candidate TSV record (8 tab-separated columns), identical layout to
# security_currency's _sc_emit:
#   category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation
function _st_emit {
    param([string]$category, [string]$severity, [string]$risk_tier, [string]$check_id,
          [string]$target, [string]$title, [string]$detail, [string]$remediation)
    return ($category, $severity, $risk_tier, $check_id, $target, $title, $detail, $remediation -join "`t")
}

# --- Detection --------------------------------------------------------------
# True when the tool id is present on this host. Detect by the tool's own command/cmdlet or service.
function _st_present {
    param([string]$id)
    switch ($id) {
        'defender' { if (_have 'Get-MpComputerStatus') { return $true }
                     try { if (Get-Service -Name 'WinDefend' -ErrorAction Stop) { return $true } } catch {}
                     return $false }
        'firewall' { if (_have 'Get-NetFirewallProfile') { return $true }
                     try { if (Get-Service -Name 'MpsSvc' -ErrorAction Stop) { return $true } } catch {}
                     return $false }
        'crowdsec' { if (_have 'cscli') { return $true }
                     try { if (Get-Service -Name 'crowdsec' -ErrorAction Stop) { return $true } } catch {}
                     return $false }
        'sysmon'   { if ((_have 'Sysmon') -or (_have 'Sysmon64')) { return $true }
                     try { if (Get-Service -Name 'Sysmon','SysmonDrv' -ErrorAction Stop) { return $true } } catch {}
                     return $false }
        'auditpol' { return (_have 'auditpol') }
        default    { return $false }
    }
}

function _st_service_active {
    param([string]$s)
    if (Get-Command service_status -ErrorAction SilentlyContinue) {
        return ((service_status $s) -eq 'active')
    }
    try { return ((Get-Service -Name $s -ErrorAction Stop).Status -eq 'Running') } catch { return $false }
}

# --- Observe (shallow + cheap, strictly read-only) --------------------------
# Returns a [pscustomobject] with .detail (one-line health string) and .ok (true=healthy,
# false=degraded: installed but not actually protecting). NEVER triggers a scan. Deferred-ownership
# tools always report ok with an inventory-only detail (their deep finding belongs to another engine).
function _st_observe {
    param([string]$id, [string]$service)
    switch ($id) {
        'defender' {
            $mp = $null
            if (_have 'Get-MpComputerStatus') { try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {} }
            if (-not $mp) { return [pscustomobject]@{ detail = 'installed but Defender status is unavailable (third-party AV may have disabled it)'; ok = $false } }
            if (-not $mp.RealTimeProtectionEnabled) { return [pscustomobject]@{ detail = 'installed but real-time protection is OFF (nothing is being scanned on access)'; ok = $false } }
            return [pscustomobject]@{ detail = "active; real-time protection on; signature age $($mp.AntivirusSignatureAge) day(s) — freshness via check-security-currency"; ok = $true }
        }
        'firewall' {
            if (-not (_have 'Get-NetFirewallProfile')) { return [pscustomobject]@{ detail = 'present'; ok = $true } }
            try {
                $off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
                if ($off.Count -gt 0) {
                    return [pscustomobject]@{ detail = ("present but $($off.Count) profile(s) disabled: " + (($off | ForEach-Object { $_.Name }) -join ', ')); ok = $false }
                }
                return [pscustomobject]@{ detail = 'active; all firewall profiles enabled'; ok = $true }
            } catch { return [pscustomobject]@{ detail = 'present'; ok = $true } }
        }
        'crowdsec' {
            return [pscustomobject]@{ detail = 'present — inbound alerts via inspect-logs, hub freshness via check-security-currency'; ok = $true }
        }
        'sysmon' {
            if (_st_service_active $service) { return [pscustomobject]@{ detail = 'agent present and the Sysmon service is running'; ok = $true } }
            # Some Sysmon installs register as SysmonDrv only; treat a present binary as ok-but-idle.
            return [pscustomobject]@{ detail = 'installed but the Sysmon service is not running'; ok = $false }
        }
        'auditpol' {
            return [pscustomobject]@{ detail = 'present — Windows audit policy tool (configure categories via auditpol)'; ok = $true }
        }
        default { return [pscustomobject]@{ detail = 'present'; ok = $true } }
    }
}

# --- The scan ---------------------------------------------------------------
# Walk the registry: for every PRESENT tool emit an inventory row (+ a health row if degraded and
# the profile runs it), then emit an absent-defense finding for any defense class no present tool
# satisfies. Severity + profile-gating come from lib/profile.ps1. No output beyond inventory = the
# box's defenses look healthy and well-covered.
function sectools_scan {
    $prof = if (Get-Command watchman_profile -ErrorAction SilentlyContinue) { watchman_profile } else { 'workstation' }
    $out = [System.Collections.Generic.List[string]]::new()
    $satisfied = @{}

    foreach ($row in (_st_rows)) {
        $parts = $row -split '\|'
        if ($parts.Count -lt 4) { continue }
        $id = $parts[0]; $class = $parts[1]; $cat = $parts[2]; $service = $parts[3]
        if (-not (_st_present $id)) { continue }
        $satisfied[$class] = $true
        if ($service -eq '-') { $service = '' }

        $obs = _st_observe $id $service

        # Inventory row — always (context, not an alarm).
        $out.Add((_st_emit 'config' 'info' 'safe' 'sectool_inventory' $id `
            "$id present" $obs.detail ''))

        # Health row — only when degraded AND the profile runs the check.
        if (-not $obs.ok) {
            $hsev = if (Get-Command profile_severity -ErrorAction SilentlyContinue) { profile_severity 'sectool_health' $prof } else { 'medium' }
            if ($hsev -ne 'skip') {
                $unitHint = if ($service) { $service } else { $id }
                $out.Add((_st_emit $cat $hsev 'review' 'sectool_health' $id `
                    "$id is installed but not effective" `
                    "$($obs.detail) — a defense that is installed but not running or configured gives false comfort." `
                    "Enable and configure it (e.g. 'Start-Service $unitHint' / 'Set-MpPreference -DisableRealtimeMonitoring `$false'); apply via 'watchman fix'."))
            }
        }
    }

    # Absent-defense classes (the "adopt scope" inverse). MANUAL tier always.
    $g = _st_gap 'brute_force' 'defense_gap_bruteforce' 'security' $prof $satisfied `
        'No brute-force/IPS protection beyond the firewall is installed' `
        'Nothing is throttling password-guessing against RDP, SSH, or the web server — no CrowdSec is present. On a public-facing host this is a primary path to credential compromise.' `
        "Install one (operator's choice): CrowdSec for Windows ($(if (Get-Command pkg_install_cmd -ErrorAction SilentlyContinue) { pkg_install_cmd } else { 'winget install --id' }) CrowdSec.CrowdSec)."
    if ($g) { $out.Add($g) }

    $g = _st_gap 'host_audit' 'defense_gap_audit' 'security' $prof $satisfied `
        'No host audit/telemetry subsystem is installed' `
        'Sysmon is not present, so security-relevant process/network/registry events are not being recorded for forensics beyond the default Windows audit policy.' `
        'Install Sysmon (Sysinternals) with a vetted config (e.g. SwiftOnSecurity); then it records detailed host telemetry to the event log.'
    if ($g) { $out.Add($g) }

    # Antivirus-absent: opinionated, OFF by default — flagged only when the operator opts in.
    if (($env:WATCHMAN_FLAG_AV_ABSENT) -eq 'yes') {
        $g = _st_gap 'antivirus' 'defense_gap_antivirus' 'security' $prof $satisfied `
            'No antivirus engine is installed' `
            'Neither Microsoft Defender nor a recognized third-party AV is present. On any internet-facing or user-operated host, on-access malware scanning is a baseline layer.' `
            'Enable Microsoft Defender (built in) or install a maintained AV product.'
        if ($g) { $out.Add($g) }
    }

    if ($out.Count -gt 0) { return $out }
}

# Emit an absent-defense finding for one class, unless a present tool satisfies it or the profile
# does not run the check. Returns the TSV string, or $null.
function _st_gap {
    param([string]$class, [string]$check_id, [string]$category, [string]$prof, [hashtable]$satisfied,
          [string]$title, [string]$detail, [string]$rem)
    if ($satisfied.ContainsKey($class)) { return $null }
    $sev = if (Get-Command profile_severity -ErrorAction SilentlyContinue) { profile_severity $check_id $prof } else { 'low' }
    if ($sev -eq 'skip') { return $null }
    return (_st_emit $category $sev 'manual' $check_id $class $title $detail $rem)
}

# --- Helpers for the skill summary and the preflight ------------------------
# The present tools, one id per line (for the skill's plain-language summary).
function sectools_present {
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($row in (_st_rows)) {
        $id = ($row -split '\|')[0]
        if ($id -and (_st_present $id)) { $out.Add($id) }
    }
    if ($out.Count -gt 0) { return $out }
}

# sectools_observe_commands — used ONLY by the preflight (the `sectool_status` resolver_op). On
# Windows the observe step runs cmdlets inside the wm dispatcher (already allowed by the framework
# base), so no extra command allowlist is needed — return nothing, mirroring the bash contract of
# emitting only for tools that need a privileged external command.
function sectools_observe_commands { return }

# sectool_log_paths — a resolver token declared in the skill's manifest `reads`. On Windows the
# defensive tools log to the event log (read via Get-WinEvent, not a file path) except CrowdSec,
# which keeps a log dir. Echo only directories that actually exist on this host.
function sectool_log_paths {
    $out = [System.Collections.Generic.List[string]]::new()
    if (_st_present 'crowdsec') {
        foreach ($d in @('C:\ProgramData\CrowdSec\log', "$env:ProgramData\CrowdSec\log")) {
            if ($d -and (Test-Path -LiteralPath $d)) { $out.Add($d) }
        }
    }
    if ($out.Count -gt 0) { return ($out | Sort-Object -Unique) }
}
