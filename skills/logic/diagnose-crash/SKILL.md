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

1. **Preflight.** `source lib/journal.sh lib/distro.sh lib/profile.sh`; `journal_init`.
2. **Enumerate boots.** `sudo journalctl --list-boots`. Walk them **backward** from
   the current boot.
3. **Per boot, hunt the kernel's own words.** Search for
   `Out of memory`, `Killed process`, `oom-kill`, and services exiting with
   **code 137** (SIGKILL — typically the OOM killer):
   `sudo journalctl -b <id> -k -g 'Out of memory|Killed process|oom'`.
4. **Identify victim and hog.** From the OOM message extract the killed process and
   the memory consumer. Correlate with `check-capacity`'s `memory_pressure` finding.
5. **Journal a finding** `check_id=oom_recent_kill`, `category=capacity`,
   `severity=high`, `risk_tier=review` (the fix touches service config), with a
   concrete remediation suggestion: protect the victim with
   `OOMScoreAdjust=` or cap the offender with a cgroup `MemoryMax=`. Put the exact
   unit and numbers in `detail`/`remediation`.
6. **Explain, never act.** Applying `OOMScoreAdjust`/`MemoryMax` is `review`-tier and
   belongs to the operator-run fixer.
<!-- /origin -->

## Grounding

- `lib/distro.sh` — `journalctl` access (resolver_op `journal_read`).
- `lib/journal.sh` — `journal_upsert`.
- `check-capacity`, `check-log-retention` — the facts this skill correlates.
