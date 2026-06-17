---
name: check-capacity
description: "OBSERVE: disk, inodes, memory, and journal size against configured thresholds. A full disk or inode table breaks services silently."
lane: coding
allowed-tools: Read, Glob, Grep, Bash
---

# check-capacity (Grammar / Observe)

Establishes whether the machine is about to run out of something. Disk, inodes,
memory pressure, and journal disk usage — measured against the thresholds in
`config/watchman.conf`. Read-only.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## When to use

Every `/watchman audit` / `/watchman loop`.

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** `source lib/journal.sh lib/profile.sh`; `journal_init`; load thresholds
   from `config/watchman.conf` (`WATCHMAN_DISK_WARN_PCT`, `WATCHMAN_INODE_WARN_PCT`,
   `WATCHMAN_MEM_WARN_PCT`).
2. **Disk.** `df -P` per mounted filesystem; any usage ≥ threshold ⇒
   `check_id=disk_capacity`, `target=<mountpoint>`, severity from `profile_severity`,
   `risk_tier=safe` (the safe remediation is cleaning caches, not deleting user data —
   the fixer never deletes data).
3. **Inodes.** `df -iP`; ≥ threshold ⇒ `check_id=inode_capacity` (often the silent killer).
4. **Memory.** `free`; sustained low available memory ⇒ `check_id=memory_pressure`.
   Record current values; `diagnose-crash` correlates with OOM history.
5. **Journal size.** `journalctl --disk-usage` vs `SystemMaxUse`; record as a capacity
   metric and a finding if unbounded growth is observed.
6. **Journal each** with concrete numbers in `detail`. Never free space or delete
   files here — only observe.
<!-- /origin -->

## Grounding

- `lib/profile.sh` — `profile_severity`.
- `lib/journal.sh` — `journal_upsert`, `journal_record_metric`.
- `config/watchman.conf` — capacity thresholds.
