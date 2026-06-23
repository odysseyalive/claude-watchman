# lib/cpanel.ps1 — the cPanel/WHM observe engine (Windows port: self-gating no-op).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# cPanel & WHM is a LINUX-ONLY control plane (it runs on the RHEL family / Ubuntu LTS, never on
# Windows). On Windows there is no cPanel to observe, so this engine self-gates to nothing —
# exactly as the bash cpscan returns early off a non-cPanel box and as control_panel_detect in
# distro.ps1 returns '' on Windows. The PUBLIC function names are kept so the shared, family-blind
# skills (inspect-cpanel) resolve and call them identically; each body is a no-op/empty return.

# cpscan — read every cPanel signal and emit finding-candidates. On Windows there is no cPanel, so
# it emits nothing (the inspect-cpanel skill's self-gate also short-circuits before calling it).
function cpscan {
    if ((Get-Command control_panel_detect -ErrorAction SilentlyContinue) -and ((control_panel_detect) -eq 'cpanel')) {
        # Defensive: cPanel cannot exist on Windows, so even if a profile forced this we have no
        # control-plane tools to query. Emit nothing rather than guess.
        return
    }
    return
}
