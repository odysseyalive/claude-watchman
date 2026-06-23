# lib/security_currency.ps1 — are the machine's defenses being kept CURRENT? (Windows port)
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# Configuration checks ask "is it set up right." This asks the time-based question: "is it up to
# date, and is something keeping it up to date." As attackers gain new tricks, stale defenses (old
# Defender signatures, unpatched packages, an auto-updater that quietly turned off) are how a
# once-hardened box drifts open. The journal tracks the staleness as a trend, so the loop EMAILS you
# when a fresh defense goes stale — staleness is a slow drift, and the loop is built to catch drift.
#
# This file is READ-ONLY: it reads state and emits finding-candidates. It NEVER syncs over the
# network, never installs, and NEVER applies an update — applying one can break a production server,
# so every finding is detect-and-propose; the operator confirms via `watchman fix` (review) or
# enables the automation. Detection only.

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# Emit one finding-candidate the skill journals (tab-separated, matching the bash _sc_emit shape):
#   category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation
function _sc_emit {
    param([string]$category, [string]$severity, [string]$risk_tier, [string]$check_id,
        [string]$target, [string]$title, [string]$detail, [string]$remediation)
    "{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}" -f $category, $severity, $risk_tier, $check_id, $target, $title, $detail, $remediation
}

# Resolve autoupdate_enabled (which returns a WmExit 0/1/2) into a plain bool: $true when enabled.
function _sc_autoupdate_on {
    if (-not (Get-Command autoupdate_enabled -ErrorAction SilentlyContinue)) { return $false }
    try {
        $r = autoupdate_enabled
        if ($null -ne $r -and $r.GetType().Name -eq 'WmExit') { return ($r.Code -eq 0) }
        if ($r -is [bool]) { return $r }
        return $false
    } catch { return $false }
}

# Defender (or third-party AV) signature age in days, or -1 when no AV status is available. This is
# the Windows analogue of ClamAV/threat-intel signature freshness.
function _sc_defender_sig_age {
    if (-not (_have 'Get-MpComputerStatus')) { return -1 }
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        $age = $s.AntivirusSignatureAge
        if ($null -ne $age) { return [int]$age }
        return -1
    } catch { return -1 }
}

# Scan everything and emit records (no output = defenses look current).
function seccur_scan {
    $fam = if (Get-Command watchman_family -ErrorAction SilentlyContinue) { watchman_family } else { 'windows' }
    $staleDays = if ($env:WATCHMAN_SIG_STALE_DAYS) { [int]$env:WATCHMAN_SIG_STALE_DAYS } else { 7 }
    $updateStale = if ($env:WATCHMAN_UPDATE_STALE_DAYS) { [int]$env:WATCHMAN_UPDATE_STALE_DAYS } else { 30 }
    $cmd = if (Get-Command security_update_cmd -ErrorAction SilentlyContinue) { security_update_cmd } else { 'winget upgrade --all' }

    # 1. Update-metadata staleness — a stale view makes "0 updates pending" a lie. On Windows this is
    #    how long since Windows Update last successfully searched (pkg_db_age_days, registry-derived).
    $dbage = -1
    if (Get-Command pkg_db_age_days -ErrorAction SilentlyContinue) {
        try { $dbage = [int](pkg_db_age_days) } catch { $dbage = -1 }
    }
    if ($dbage -ge 0 -and $dbage -gt $updateStale) {
        _sc_emit 'config' 'medium' 'manual' 'pkg_db_stale' 'package-db' `
            "Update metadata not refreshed in $dbage days" `
            "Windows Update last searched $($dbage)d ago (limit $($updateStale)d) — it cannot see new security fixes, so any 'up to date' reading is unreliable. The durable fix is to let Windows Update check automatically." `
            "Refresh + keep auto-check on: $cmd"
    }

    # 2. Pending updates (read from CACHED state — no network sync here).
    $upg = @()
    if (Get-Command pkg_list_upgradable -ErrorAction SilentlyContinue) {
        try { $upg = @(pkg_list_upgradable | Where-Object { $_ -and ([string]$_).Trim() }) } catch { $upg = @() }
    }
    $n = $upg.Count
    if ($n -gt 0) {
        $first5 = ($upg | Select-Object -First 5) -join ', '
        _sc_emit 'security' 'medium' 'review' 'security_updates_pending' 'packages' `
            "$n package update(s) available" `
            "$n packages/updates are pending — applying them is how you pick up fixes for known exploits. First: $first5" `
            $cmd
    }

    # 3. CVE scanner — run it, or note that visibility is limited. On Windows the scanner is
    #    PSWindowsUpdate's Security Updates category (vuln_scanner/vuln_scan in distro.ps1).
    $scanner = if (Get-Command vuln_scanner -ErrorAction SilentlyContinue) { vuln_scanner } else { 'none' }
    if ($scanner -eq 'none') {
        _sc_emit 'config' 'low' 'review' 'vuln_scanner_missing' 'vuln-scanner' `
            'No CVE/security-update scanner available' `
            "Install the PSWindowsUpdate module so claude-watchman can flag pending security updates (KBs) with fixes available." `
            'Install-Module PSWindowsUpdate -Scope AllUsers'
    } else {
        $v = @()
        if (Get-Command vuln_scan -ErrorAction SilentlyContinue) {
            try { $v = @(vuln_scan | Where-Object { $_ -and ([string]$_).Trim() }) } catch { $v = @() }
        }
        $vn = $v.Count
        if ($vn -gt 0) {
            $top5 = ($v | Select-Object -First 5) -join '; '
            _sc_emit 'security' 'high' 'review' 'vuln_packages' 'cve' `
                "$vn security update(s) with known fixes available" `
                "$scanner reports $vn security update(s) (KBs) with fixes available. Top: $top5" `
                $cmd
        }
    }

    # 4. Auto security updates — the automation that keeps the OS current.
    $mech = if (Get-Command autoupdate_mechanism -ErrorAction SilentlyContinue) { autoupdate_mechanism } else { 'windowsupdate' }
    if ($mech -ne 'rolling') {
        if (-not (_sc_autoupdate_on)) {
            _sc_emit 'security' 'medium' 'review' 'auto_security_updates_off' $mech `
                'Automatic security updates are not enabled' `
                "$mech is this platform's auto-update path and it is not active — fixes won't apply on their own. Enabling it is the durable way to stay current; claude-watchman then just verifies it stays on." `
                'Enable Windows Update automatic updates (set NoAutoUpdate=0 and start the wuauserv service).'
        }
    }

    # 5. Threat-intel freshness — Microsoft Defender signature age (the Windows analogue of ClamAV).
    $sigAge = _sc_defender_sig_age
    if ($sigAge -ge 0 -and $sigAge -gt $staleDays) {
        _sc_emit 'security' 'medium' 'review' 'defender_sig_stale' 'defender' `
            "Microsoft Defender signatures are $sigAge days old" `
            "Signatures older than $($staleDays)d miss recent malware. Refresh them and ensure the Defender signature update task runs." `
            'Update-MpSignature'
    }

    # 6. CrowdSec hub freshness (cscli.exe also exists on Windows; reads local state).
    if (_have 'cscli') {
        $tainted = $false
        try {
            $hub = & cscli hub list 2>$null
            if ($hub -and (($hub -join "`n") -match '(?i)tainted|outdated|⚠')) { $tainted = $true }
        } catch { $tainted = $false }
        if ($tainted) {
            _sc_emit 'security' 'medium' 'review' 'crowdsec_hub_stale' 'crowdsec' `
                'CrowdSec hub has outdated or tainted items' `
                'Detection scenarios/collections are not current — refreshing them is how CrowdSec keeps up with new attack patterns.' `
                'cscli hub update && cscli hub upgrade'
        }
    }
}
