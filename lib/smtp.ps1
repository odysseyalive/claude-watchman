# lib/smtp.ps1 — THE ONLY code that reads SMTP credentials and dispatches mail (PowerShell port).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# Just as lib/journal.ps1 is the sole gate to findings.db, this is the sole gate to the SMTP
# secrets. Skills never read credentials directly — they call the send-report skill, which calls
# send_report() here. Credentials live ONLY in the gitignored .env at the repo root (never
# watchman.conf, never hardcoded). See CLAUDE.md "Mail dispatch".
#
# Transport: System.Net.Mail.SmtpClient (built into .NET — no external dependency, unlike the
# Linux port's msmtp). Windows uses the system certificate store automatically, so there is no
# CA-bundle path to configure. The .env is PARSED line-by-line (never executed).
#
# Graceful degradation: if .env is missing or SMTP_PASS is blank, mail is treated as UNCONFIGURED —
# send_report logs and returns success (skips) rather than crashing the loop. A monitoring tool must
# never die because mail is not set up. smtp_send_test is the LOUD version (fails on error) behind
# `watchman testmail`.

function _smtp_root {
    if ($env:WATCHMAN_ROOT) { return $env:WATCHMAN_ROOT }
    return (Split-Path -Parent $PSScriptRoot)
}
$script:SMTP_ENV_FILE = if ($env:SMTP_ENV_FILE) { $env:SMTP_ENV_FILE } else { Join-Path (_smtp_root) '.env' }

# Hold the loaded credentials in a script-scope hashtable rather than the environment: the .env is
# parsed, not sourced, so there is no shell to export into.
$script:SMTP_CFG = @{}

# Parse the .env into $script:SMTP_CFG (only the keys we use). Returns $true if readable.
# Comments and blank lines are skipped; surrounding single/double quotes are stripped. The file is
# NEVER executed — we read it as data, exactly like the bash version's safe KEY=VALUE loop.
function _smtp_load_env {
    if (-not (Test-Path -LiteralPath $script:SMTP_ENV_FILE)) { return $false }
    $script:SMTP_CFG = @{}
    try {
        $lines = Get-Content -LiteralPath $script:SMTP_ENV_FILE -ErrorAction Stop
    } catch { return $false }
    foreach ($line in $lines) {
        if ($line -match '^\s*#') { continue }
        if ($line -match '^\s*$') { continue }
        $eq = $line.IndexOf('=')
        if ($eq -lt 0) { continue }
        $key = $line.Substring(0, $eq).Trim()
        $val = $line.Substring($eq + 1)
        # strip surrounding single or double quotes if present
        if ($val.Length -ge 2) {
            if (($val[0] -eq '"' -and $val[-1] -eq '"') -or ($val[0] -eq "'" -and $val[-1] -eq "'")) {
                $val = $val.Substring(1, $val.Length - 2)
            }
        }
        switch ($key) {
            'SMTP_HOST'    { $script:SMTP_CFG[$key] = $val }
            'SMTP_PORT'    { $script:SMTP_CFG[$key] = $val }
            'SMTP_USER'    { $script:SMTP_CFG[$key] = $val }
            'SMTP_PASS'    { $script:SMTP_CFG[$key] = $val }
            'REPORT_EMAIL' { $script:SMTP_CFG[$key] = $val }
        }
    }
    return $true
}

function _smtp_get([string]$key) {
    if ($script:SMTP_CFG.ContainsKey($key)) { return $script:SMTP_CFG[$key] }
    return ''
}

# $true = configured (host/user/pass/recipient all present), $false = not.
function smtp_is_configured {
    if (-not (_smtp_load_env)) { return $false }
    return ((_smtp_get 'SMTP_HOST') -and (_smtp_get 'SMTP_USER') -and `
            (_smtp_get 'SMTP_PASS') -and (_smtp_get 'REPORT_EMAIL'))
}

# send_report SUBJECT [BODY_FILE]
#   Reads BODY_FILE (or stdin if omitted) as the message body and emails it to REPORT_EMAIL.
#   Degrades gracefully when unconfigured: logs to stderr and returns $true so the loop continues.
function send_report {
    param([string]$subject, [string]$body_file = '')

    if (-not (smtp_is_configured)) {
        [Console]::Error.WriteLine('smtp: mail unconfigured (.env missing or SMTP_PASS blank) — skipping dispatch.')
        return $true   # not an error: the loop continues
    }

    $smtpHost = _smtp_get 'SMTP_HOST'
    $smtpUser = _smtp_get 'SMTP_USER'
    $smtpPass = _smtp_get 'SMTP_PASS'
    $recipient = _smtp_get 'REPORT_EMAIL'
    $port = _smtp_get 'SMTP_PORT'
    if (-not $port) { $port = '587' }
    $portNum = 587
    [void][int]::TryParse($port, [ref]$portNum)

    # Body: read BODY_FILE if given and readable, else read stdin (the pipeline).
    $body = ''
    if ($body_file -and (Test-Path -LiteralPath $body_file)) {
        try { $body = Get-Content -Raw -LiteralPath $body_file -ErrorAction Stop } catch { $body = '' }
    } else {
        $stdin = @($input)
        if ($stdin.Count -gt 0) { $body = ($stdin -join "`n") }
    }

    $mail = $null
    $client = $null
    try {
        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = New-Object System.Net.Mail.MailAddress($smtpUser)
        $mail.To.Add($recipient)
        $mail.Subject = $subject
        $mail.Body = $body
        $mail.BodyEncoding = [System.Text.Encoding]::UTF8
        $mail.SubjectEncoding = [System.Text.Encoding]::UTF8
        $mail.IsBodyHtml = $false

        $client = New-Object System.Net.Mail.SmtpClient($smtpHost, $portNum)
        $client.Credentials = New-Object System.Net.NetworkCredential($smtpUser, $smtpPass)
        $client.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
        # Port 587 = STARTTLS: System.Net.Mail upgrades the cleartext connection with EnableSsl.
        # NOTE: System.Net.Mail does NOT support implicit TLS (port 465) — it only does STARTTLS.
        # We still set EnableSsl=$true for 465 (best effort), but operators should prefer 587. The
        # Windows system certificate store validates the server automatically (no CA-bundle path).
        $client.EnableSsl = $true

        $client.Send($mail)
        [Console]::Error.WriteLine("smtp: report sent to $recipient")
        return $true
    } catch {
        [Console]::Error.WriteLine("smtp: send failed — $($_.Exception.Message). Report not delivered.")
        return $false
    } finally {
        if ($mail) { $mail.Dispose() }
        if ($client) { $client.Dispose() }
    }
}

# smtp_send_test — send a fixed test message to prove the .env credentials and the System.Net.Mail
# transport actually deliver, end to end. This is the plumbing-verification path behind
# `watchman testmail`, so it does NOT degrade silently the way send_report does for the loop: an
# operator running a test wants a loud, explicit result. Unconfigured is a FAILURE here (returns
# $false with a pointer to the fix), not a quiet skip.
#
# Read-only: it sends one email and writes nothing to the system or the journal.
function smtp_send_test {
    if (-not (smtp_is_configured)) {
        [Console]::Error.WriteLine('smtp: mail is NOT configured — cannot send a test.')
        [Console]::Error.WriteLine("      Fill in $($script:SMTP_ENV_FILE): SMTP_HOST, SMTP_USER, SMTP_PASS, REPORT_EMAIL.")
        [Console]::Error.WriteLine('      (Copy .env.example to .env if you have not yet.)')
        return $false
    }

    $smtpHost = _smtp_get 'SMTP_HOST'
    $port = _smtp_get 'SMTP_PORT'; if (-not $port) { $port = '587' }
    $recipient = _smtp_get 'REPORT_EMAIL'
    $machine = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else {
        try { [System.Net.Dns]::GetHostName() } catch { 'unknown' }
    }

    [Console]::Error.WriteLine("smtp: sending test to $recipient via ${smtpHost}:$port ...")

    $body = @"
claude-watchman test email from $machine.

If you are reading this, SMTP delivery works: .env credentials authenticated
to $smtpHost and System.Net.Mail delivered to $recipient. No findings are attached —
this is only a transport check.

Reports will arrive here when the loop's delta crosses a notify threshold.
"@

    if ($body | send_report "claude-watchman: test email from $machine") {
        [Console]::Error.WriteLine("smtp: test sent — check the $recipient inbox (and spam folder).")
        return $true
    }
    [Console]::Error.WriteLine('smtp: test FAILED to send (see the error above).')
    return $false
}
