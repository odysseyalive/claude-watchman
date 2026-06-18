---
name: check-capacity
description: "OBSERVE: disk, inodes, memory, and log store size against configured thresholds. Handles both Linux (free/journalctl) and macOS (vm_stat/Unified Log)."
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

1. **Preflight.** `source lib/journal.sh lib/profile.sh lib/distro.sh`; `journal_init`; load thresholds
   from `config/watchman.conf` (`WATCHMAN_DISK_WARN_PCT`, `WATCHMAN_INODE_WARN_PCT`,
   `WATCHMAN_MEM_WARN_PCT`); resolve `family="$(watchman_family)"`.
2. **Disk.** `df -P` per mounted filesystem; any usage ≥ threshold ⇒
   `check_id=disk_capacity`, `target=<mountpoint>`, severity from `profile_severity`,
   `risk_tier=safe` (the safe remediation is cleaning caches, not deleting user data —
   the fixer never deletes data).
3. **Inodes.** `df -iP`; ≥ threshold ⇒ `check_id=inode_capacity` (often the silent killer).
   Note: macOS APFS volumes do not report inode limits the same way; if `df -iP` shows
   0 for inodes on Darwin, skip the inode check and note it as not applicable.
4. **Memory pressure.**
   - **Linux:** `free`; sustained low available memory ⇒ `check_id=memory_pressure`.
   - **macOS:** `vm_stat`; calculate free pages × 4096 vs `sysctl -n hw.memsize`. Low
     available percentage ⇒ `check_id=memory_pressure`. Record `pages_free`,
     `pages_wired_down`, and `pages_active` from `vm_stat` output in `detail`.
5. **Log store size.**
   - **Linux:** `journalctl --disk-usage` vs `SystemMaxUse`; record as a capacity
     metric and a finding if unbounded growth is observed (`check_id=journal_size_unbounded`).
   - **macOS:** `du -sh /var/db/diagnostics 2>/dev/null` for the Unified Log store.
     Record the size as an info metric. No hard limit on macOS; note to operator.
6. **Journal each** with concrete numbers in `detail`. Never free space or delete
   files here — only observe.
<!-- /origin -->

## Grounding

- `lib/profile.sh` — `profile_severity`.
- `lib/journal.sh` — `journal_upsert`, `journal_record_metric`.
- `config/watchman.conf` — capacity thresholds.
