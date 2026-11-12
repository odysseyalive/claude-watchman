# lib/interworx.ps1 — the InterWorx/NodeWorx observe engine (Windows port: self-gating no-op).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# InterWorx is a LINUX-ONLY control plane (RHEL family EL8/EL9, never Windows). On Windows there
# is nothing to observe, so this engine self-gates to nothing, exactly as the bash iwscan returns
# early off a non-InterWorx box and as control_panel_detect in distro.ps1 returns '' on Windows.
# The public name is kept so the shared, family-blind skill (inspect-interworx) resolves it.

# iwscan — read every InterWorx signal and emit finding-candidates. On Windows it emits nothing
# (the inspect-interworx skill's self-gate also short-circuits before calling it).
function iwscan {
    return
}
