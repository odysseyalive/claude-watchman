---
name: check-log-retention
description: "OBSERVE: are logs kept, persistent across boots, and rotated? Handles both Linux journald and macOS Unified Log."
lane: coding
allowed-tools: Read, Glob, Grep, Bash
---

# check-log-retention (Grammar / Observe)

Establishes whether the forensic trail will even survive. On a workstation this is
the **highest-value check**: journald often defaults to volatile storage, so logs
vanish on reboot — and `diagnose-crash` depends on logs persisting across the very
reboot that followed the failure. Read-only.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## When to use

Every `/watchman audit` / `/watchman loop`. On a fresh Arch install several of these
often need fixing — surface them clearly.

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** `source lib/journal.sh lib/distro.sh lib/profile.sh`; `journal_init`;
   resolve `family="$(watchman_family)"`.

2. **Platform branch.**

   **Linux (family != darwin):**
   - **journald persistence.** Read `Storage=` in `/etc/systemd/journald.conf` (and
     drop-ins). Volatile or unset + no `/var/log/journal/` directory ⇒ logs do NOT
     survive reboot. Journal `check_id=log_retention_volatile`, severity from
     `profile_severity` (higher on workstation), `risk_tier=safe`,
     remediation: set `Storage=persistent` and `mkdir /var/log/journal`.
   - **journald size limits.** Read `SystemMaxUse=`; unbounded growth is
     `check_id=journal_size_unbounded`, `risk_tier=safe`.
   - **logrotate.** Is logrotate installed and is `/etc/logrotate.conf` +
     `/etc/logrotate.d/` present and non-empty? Missing rotation for active log files
     ⇒ `check_id=log_rotation_missing`, `risk_tier=safe`.

   **macOS (family == darwin):**
   - **Unified Log persistence.** macOS Unified Log is persistent by default (stored
     in `/var/db/diagnostics`). Check that the directory exists and is non-empty:
     `ls /var/db/diagnostics/ 2>/dev/null | grep -q .` — if missing or empty, journal
     `check_id=log_retention_volatile`, `risk_tier=safe`, remediation: check that
     Full Disk Access is granted to the terminal in System Settings > Privacy & Security.
   - **Log store size.** `du -sh /var/db/diagnostics 2>/dev/null` — record as
     `check_id=journal_size_unbounded` info finding with detail showing the size. No
     automatic max on macOS; note this for the operator.
   - **ASL / system log retention.** Check `/etc/asl.conf` and `/etc/asl/` for
     retention configuration. Missing ASL config is `check_id=log_rotation_missing`,
     `risk_tier=safe`, detail: "ASL config absent — log rotation for legacy syslog
     entries may be unconfigured".
   - **Note:** `log show` access requires Full Disk Access. If `log show --last 1m`
     returns a permission error, journal `check_id=log_retention_volatile`,
     `severity=medium`, `risk_tier=manual`, detail: "macOS Unified Log not readable —
     grant Full Disk Access to your terminal in System Settings > Privacy & Security".

3. **Journal each** with a clear plain-language `detail` of what is lost if
   unaddressed. Never edit these configs here — that is `fix-redflag` (all `safe`-tier).
<!-- /origin -->

## Grounding

- `lib/distro.sh` — `pkg_is_installed` (logrotate), `service_status`.
- `lib/profile.sh` — `profile_severity` (retention weighs heavier on workstation).
- `lib/journal.sh` — `journal_upsert`.
