# lib/wordpress.ps1 — the WordPress discovery engine (Windows port: self-gating no-op).
#
# > PRIME DIRECTIVE (outranks everything below). Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.ps1. This rule has no exceptions and no mode that overrides it.
#
# The bash engine (lib/wordpress.sh) finds WordPress through the Apache/nginx docroot resolver
# (webserver_docroots in distro.sh). The Windows port has no IIS docroot resolver yet, so there is
# nothing to observe: these functions self-gate to nothing. The public names are kept so the
# shared, family-blind skill (inspect-wordpress) resolves them. wordpress_rebaseline and
# wordpress_sites are listed in wm.mutators.ps1, mirroring _WM_MUTATORS in lib/wm.

function wordpress_scan { return }
function wordpress_sites { return }
function wordpress_rebaseline { return }
