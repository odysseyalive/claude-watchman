---
name: diagnose-crash
description: "ANALYZE: crash and OOM postmortem. Linux: journalctl across boots. macOS: DiagnosticReports and Unified Log jetsam events."
lane: coding
allowed-tools: Read, Glob, Grep, Bash
---

# diagnose-crash (Logic / Analyze)

Relates the facts into a cause. Walks journald **across boots** to explain crashes
and OOM kills. Key insight: a reboot (or series of them) often *follows* the
failure, so the evidence lives in the boot *before* the current one. Read-only —
it diagnoses and journals a remediation suggestion; it never applies it.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## When to use

Every `/watchman audit`; especially after an unexpected reboot. Depends on logs
persisting across boots — see `check-log-retention`.

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** `source lib/journal.sh lib/distro.sh lib/profile.sh lib/io-courtesy.sh`;
   `journal_init`; `family="$(watchman_family)"`. **I/O courtesy:** crash log analysis
   can be heavy — IF `io_should_defer_heavy`, journal one `capacity`/`info`/`safe`
   `diagnostic_deferred` (`target=diagnose-crash`,
   detail `"deferred: $(io_pressure_reason)"`) and skip this pass.

2. **Platform branch — enumerate crash evidence.**

   **Linux (family != darwin):**
   - `io_run sudo journalctl --list-boots` — walk boots **backward** from current.
   - Per boot, hunt the kernel's own words:
     `io_run sudo journalctl -b <id> -k -g 'Out of memory|Killed process|oom'`
   - From the OOM message extract the killed process and the memory consumer.

   **macOS (family == darwin):**
   - **DiagnosticReports.** List `/Library/Logs/DiagnosticReports/*.{ips,crash}` and
     `/Users/*/Library/Logs/DiagnosticReports/*.{ips,crash}` — sort by mtime, read the
     5 most recent. Look for `Exception Type: EXC_RESOURCE` (OOM) or
     `Termination Reason: Namespace JETSAM` (memory pressure kill by jetsam).
   - **Unified Log (memory kills).** `io_run log show --predicate 'eventMessage contains "killed" OR eventMessage contains "jetsam"' --last 24h 2>/dev/null`
     — extract process names and memory figures from jetsam log lines.
   - **I/O courtesy note:** `log show` can be slow on macOS. Run through `io_run` and
     cap with a time filter (`--last 48h` maximum).
   - **Note:** accessing other users' DiagnosticReports requires sudo. If access is
     denied, limit scan to system-level reports.

3. **Identify victim and hog.** From the OOM/jetsam message extract:
   - The killed process name and PID.
   - The memory consumer driving the kill (the hog).
   - Correlate with `check-capacity`'s `memory_pressure` finding.

4. **Journal a finding** `check_id=oom_recent_kill`, `category=capacity`,
   `severity=high`, `risk_tier=review` (the fix touches service/app config), with a
   concrete remediation suggestion:
   - **Linux:** protect the victim with `OOMScoreAdjust=` or cap the offender with
     a cgroup `MemoryMax=`. Put the exact unit and numbers in `detail`/`remediation`.
   - **macOS:** there is no `OOMScoreAdjust`. Suggest reviewing the offending process
     memory usage, increasing RAM, or configuring the app's own memory limits. Note
     that jetsam thresholds are not user-configurable on macOS.

5. **Explain, never act.** Applying memory limits is `review`-tier and belongs to
   the operator-run fixer.
<!-- /origin -->

## Grounding

- `lib/distro.sh` — `journalctl` access (resolver_op `journal_read`).
- `lib/journal.sh` — `journal_upsert`.
- `check-capacity`, `check-log-retention` — the facts this skill correlates.
