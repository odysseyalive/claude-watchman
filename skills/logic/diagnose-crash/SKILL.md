---
name: diagnose-crash
description: "ANALYZE: OOM-killer / journalctl postmortem across boots. The evidence often lives in the boot BEFORE the current one, because the reboot followed the failure."
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

1. **Preflight.** Run every claude-watchman function through the dispatcher —
   `bash lib/wm <function> [args…]` — which sources the libs under bash internally; never
   `source lib/…` directly (dontAsk refuses a dot-source). Initialize with
   `bash lib/wm journal_init`. Determine the machine's family and profile by running
   `bash lib/wm watchman_family` and `bash lib/wm watchman_profile` and reading the printed
   values — use them to decide which checks apply. You do NOT pass them to `journal_upsert`
   (it auto-resolves them; pass `"" ""`). **I/O courtesy:** walking journald across boots
   can be heavy — IF `bash lib/wm io_should_defer_heavy`, journal one
   `capacity`/`info`/`safe` `diagnostic_deferred`
   (`target=diagnose-crash`): first run `bash lib/wm io_pressure_reason`, then set detail to
   `"deferred: "` followed by its printed output (no `$(…)`). Skip this pass.
2. **Enumerate boots.** `bash lib/wm io_run sudo journalctl --list-boots`. Walk them **backward**
   from the current boot.
3. **Per boot, hunt the kernel's own words.** Search for
   `Out of memory`, `Killed process`, `oom-kill`, and services exiting with
   **code 137** (SIGKILL — typically the OOM killer), at idle priority:
   `bash lib/wm io_run sudo journalctl -b <id> -k -g 'Out of memory|Killed process|oom'`.
4. **Identify victim and hog.** From the OOM message extract the killed process and
   the memory consumer. Correlate with `check-capacity`'s `memory_pressure` finding.
5. **Journal a finding** `check_id=oom_recent_kill`, `target=<victim unit name>` —
   the systemd unit of the killed process (`mysqld`), never a PID or a `pid 3614`
   string: PIDs change every boot, so a PID-bearing target duplicates the finding
   each run instead of folding it. `category=capacity`,
   `severity=high`, `risk_tier=review` (the fix touches service config), with a
   concrete remediation suggestion: protect the victim with
   `OOMScoreAdjust=` or cap the offender with a cgroup `MemoryMax=`. Put the exact
   unit and numbers in `detail`/`remediation`.
6. **Explain, never act.** Applying `OOMScoreAdjust`/`MemoryMax` is `review`-tier and
   belongs to the operator-run fixer.
<!-- /origin -->

## Grounding

These claude-watchman functions are reached via the dispatcher (`bash lib/wm <function> [args…]`),
never by dot-sourcing the libs directly.

- `lib/distro.sh` — `journalctl` access (resolver_op `journal_read`).
- `lib/journal.sh` — `journal_upsert`.
- `check-capacity`, `check-log-retention` — the facts this skill correlates.
