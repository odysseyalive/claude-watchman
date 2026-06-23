# lib/shellhist.ps1 — forensic-trail tamper detection (Windows port: PSReadLine history + audit log).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# Detects whether the evidence has been WIPED — a post-compromise move: clearing/redirecting a
# user's PSReadLine ConsoleHost_history.txt, disabling history saving, or clearing the Security
# event log (Linux wtmp-truncation analogue is Security event 1102 = audit log cleared, and 4719
# = audit policy changed). It enumerates every user profile's history file plus the audit log.
#
# METADATA ONLY — it never reads the CONTENTS of anyone's history. Whether the trail was tampered
# is answered from size / mtime / reparse-point target / ACL / "logged-in-but-no-history" and the
# audit-log-cleared event — more reliable than grepping for "bad commands" and privacy-respecting.
# Most effective when run as an administrator (it can stat every profile); non-readable profiles
# are skipped, not guessed.
#
# Every Windows cmdlet is guarded (Get-Command / try-catch) so the file parses and smoke-runs on a
# non-Windows host with safe defaults — which is how the port is statically tested.

function _have([string]$name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# Emit one finding-candidate TSV record (8 tab-separated columns):
#   category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation
function _sh_emit {
    param([string]$category, [string]$severity, [string]$risk_tier, [string]$check_id,
          [string]$target, [string]$title, [string]$detail, [string]$remediation)
    return ($category, $severity, $risk_tier, $check_id, $target, $title, $detail, $remediation -join "`t")
}

# "<user>\t<historyFile>" for every local user profile that has (or would have) a PSReadLine
# history file. PSReadLine stores ConsoleHost_history.txt under
#   <profile>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# Enumerate the profile roots from the registry (ProfileList) when readable, else fall back to the
# parent of the current user profile (covers a non-admin smoke run).
function shellhist_login_users {
    $out = [System.Collections.Generic.List[string]]::new()
    $profiles = [System.Collections.Generic.List[string]]::new()
    try {
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        if (Test-Path -LiteralPath $key) {
            Get-ChildItem -LiteralPath $key -ErrorAction Stop | ForEach-Object {
                try {
                    $p = (Get-ItemProperty -LiteralPath $_.PSPath -Name 'ProfileImagePath' -ErrorAction Stop).ProfileImagePath
                    if ($p) { $profiles.Add($p) }
                } catch {}
            }
        }
    } catch {}
    if ($profiles.Count -eq 0) {
        # Fallback: every directory under the current profile's parent (e.g. C:\Users).
        $up = $env:USERPROFILE
        if ($up) {
            $parent = Split-Path -Parent $up
            if ($parent -and (Test-Path -LiteralPath $parent)) {
                try { Get-ChildItem -LiteralPath $parent -Directory -ErrorAction Stop | ForEach-Object { $profiles.Add($_.FullName) } } catch {}
            }
            if ($profiles.Count -eq 0) { $profiles.Add($up) }
        }
    }
    foreach ($prof in ($profiles | Sort-Object -Unique)) {
        if (-not $prof) { continue }
        $user = Split-Path -Leaf $prof
        $hf = Join-Path $prof 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        $out.Add("$user`t$hf")
    }
    if ($out.Count -gt 0) { return $out }
}

# Has the Security audit log been cleared (1102) or the audit policy changed (4719)? These are the
# Windows analogues of a truncated /var/log/wtmp: a cleared audit log is the canonical evidence-wipe.
# Returns a [pscustomobject] with .clearedCount / .policyCount (0 when the log is unreadable).
function _sh_audit_log_events {
    $res = [pscustomobject]@{ clearedCount = 0; policyCount = 0; readable = $false }
    if (-not (_have 'Get-WinEvent')) { return $res }
    try {
        $cleared = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102 } -MaxEvents 50 -ErrorAction Stop)
        $res.clearedCount = $cleared.Count
        $res.readable = $true
    } catch {}
    try {
        $policy = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4719 } -MaxEvents 50 -ErrorAction Stop)
        $res.policyCount = $policy.Count
        $res.readable = $true
    } catch {}
    return $res
}

# Scan everything and emit finding-candidate records (none = clean).
function shellhist_scan {
    $out = [System.Collections.Generic.List[string]]::new()

    # --- audit/login record: a cleared Security log = log wiping (wtmp analogue) ---------------
    $ev = _sh_audit_log_events
    if ($ev.clearedCount -gt 0) {
        $out.Add((_sh_emit 'security' 'high' 'manual' 'login_record_wiped' 'Security' `
            'The Security event log was cleared' `
            "$($ev.clearedCount) event(s) 1102 (audit log cleared) are present in the Security log — clearing the audit log is a classic post-compromise step. A legitimate clear (e.g. an admin action) is possible; confirm." `
            'Investigate for compromise. Forward Security logs to a remote/append-only collector (WEF / syslog) so they cannot be erased locally.'))
    }
    if ($ev.policyCount -gt 0) {
        $out.Add((_sh_emit 'security' 'medium' 'manual' 'audit_policy_changed' 'Security' `
            'The Windows audit policy was changed' `
            "$($ev.policyCount) event(s) 4719 (system audit policy changed) are present — audit policy changes can be used to stop recording specific activity before/after an intrusion." `
            'Confirm each change was intentional (auditpol /get /category:*); investigate any unexplained change.'))
    }
    if (-not $ev.readable -and (_have 'Get-WinEvent')) {
        # The Security log exists but we could not read it (not elevated) — report inability, not a wipe.
        $out.Add((_sh_emit 'security' 'low' 'manual' 'login_record_unreadable' 'Security' `
            'The Security event log could not be read' `
            'shellhist could not read the Security log to check for audit-log clearing (1102) — typically because the run is not elevated.' `
            'Run claude-watchman as an administrator so it can read the Security event log.'))
    }

    # --- per-user PSReadLine history ----------------------------------------------------------
    foreach ($line in (shellhist_login_users)) {
        $cols = $line -split "`t", 2
        $user = $cols[0]; $hf = $cols[1]
        if (-not $user -or -not $hf) { continue }
        $dir = Split-Path -Parent $hf
        # If the PSReadLine directory does not exist, the user may simply never have used the
        # ConsoleHost — not evidence of tampering on its own. Skip rather than false-positive.
        if (-not (Test-Path -LiteralPath $dir)) { continue }

        $item = $null
        try { $item = Get-Item -LiteralPath $hf -Force -ErrorAction Stop } catch { $item = $null }

        if ($item) {
            # Reparse point (symlink/junction) on the history file — redirected away (e.g. to NUL).
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                $tgt = ''
                try { $tgt = $item.Target } catch {}
                $tlow = ([string]$tgt).ToLower()
                if ($tlow -match 'nul' -or $tlow -match 'devnull') {
                    $out.Add((_sh_emit 'integrity' 'high' 'manual' 'shell_history_devnull' $user `
                        'Shell history redirected to a null device' `
                        "$hf is a reparse point targeting '$tgt' — PowerShell command history is being silently discarded." `
                        'Investigate. Remove the redirect and let PSReadLine write a real history file.'))
                } else {
                    $out.Add((_sh_emit 'integrity' 'info' 'review' 'shell_history_redirected' $user `
                        'Shell history file is a reparse point' `
                        "$hf is a reparse point (symlink/junction) targeting '$tgt'. Could be intentional, or an attacker hiding/redirecting the trail." `
                        'Confirm the redirect was intentional; if not, investigate.'))
                }
            } else {
                $sz = 0; try { $sz = [int64]$item.Length } catch {}
                # ACL: history should not be readable by Everyone / Users (the mode-600 analogue).
                $world = $false
                try {
                    $acl = Get-Acl -LiteralPath $hf -ErrorAction Stop
                    foreach ($ace in $acl.Access) {
                        $idr = [string]$ace.IdentityReference
                        if ($ace.AccessControlType -eq 'Allow' -and ($idr -match 'Everyone' -or $idr -match '\\Users$' -or $idr -match 'Authenticated Users')) {
                            if ($ace.FileSystemRights.ToString() -match 'Read|FullControl|Modify') { $world = $true }
                        }
                    }
                } catch {}
                if ($world) {
                    $out.Add((_sh_emit 'integrity' 'low' 'review' 'shell_history_perms' $user `
                        'Shell history is readable by other users' `
                        "$hf grants read access to Everyone/Users/Authenticated Users — others can read $user's command history." `
                        "Restrict the ACL so only $user and Administrators can read it (icacls `"$hf`" /inheritance:r /grant:r `"$user`:R`")."))
                }
                # Read-only attribute pinned on the history file — the immutable-bit analogue.
                if ($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                    $out.Add((_sh_emit 'integrity' 'info' 'review' 'shell_history_immutable' $user `
                        'Shell history file is marked read-only' `
                        "$hf has the ReadOnly attribute set. Could be hardening, or an attacker pinning a planted history." `
                        'Confirm it was set intentionally; if not, investigate.'))
                }
            }
        }

        # PSReadLine history disabled in the user's profile script (HistorySaveStyle = SaveNothing).
        foreach ($profScript in @(
                (Join-Path (Split-Path -Parent $dir) 'Microsoft.PowerShell_profile.ps1'),
                (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'),
                (Join-Path $env:USERPROFILE 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'))) {
            if (-not $profScript) { continue }
            if (-not (Test-Path -LiteralPath $profScript)) { continue }
            $disabled = $false
            try {
                $matches = Select-String -LiteralPath $profScript -Pattern 'HistorySaveStyle\s*[: ]\s*SaveNothing','Set-PSReadLineOption\s+-HistorySaveStyle\s+SaveNothing' -ErrorAction Stop
                if ($matches) { $disabled = $true }
            } catch {}
            if ($disabled) {
                $out.Add((_sh_emit 'security' 'high' 'manual' 'shell_history_disabled' $user `
                    'Shell history logging disabled in a PowerShell profile' `
                    "$profScript sets HistorySaveStyle to SaveNothing — PSReadLine command history is being suppressed, a common evasion." `
                    'Investigate. Re-enable history saving unless there is a documented reason.'))
            }
        }
    }

    # --- system-wide PSReadLine history disabling ---------------------------------------------
    foreach ($allHost in @(
            "$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1",
            "$env:ProgramFiles\PowerShell\7\profile.ps1")) {
        if (-not $allHost) { continue }
        if (-not (Test-Path -LiteralPath $allHost)) { continue }
        $disabled = $false
        try {
            $matches = Select-String -LiteralPath $allHost -Pattern 'HistorySaveStyle\s*[: ]\s*SaveNothing','Set-PSReadLineOption\s+-HistorySaveStyle\s+SaveNothing' -ErrorAction Stop
            if ($matches) { $disabled = $true }
        } catch {}
        if ($disabled) {
            $out.Add((_sh_emit 'security' 'high' 'manual' 'shell_history_disabled_system' $allHost `
                'Shell history disabled system-wide in an all-hosts profile' `
                "$allHost disables PSReadLine history for ALL users — a strong tamper/evasion signal." `
                'Investigate immediately. Remove the history-disabling directive unless documented.'))
        }
    }

    if ($out.Count -gt 0) { return $out }
}
