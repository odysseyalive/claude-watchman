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

1. **Preflight.** `source lib/journal.sh lib/profile.sh lib/io-courtesy.sh lib/capacity.sh`;
   `journal_init`; load thresholds from `config/watchman.conf`: the warn band
   (`WATCHMAN_DISK_WARN_PCT`, `WATCHMAN_INODE_WARN_PCT`, `WATCHMAN_MEM_WARN_PCT`) and the
   danger band (`WATCHMAN_DISK_CRIT_PCT`, `WATCHMAN_INODE_CRIT_PCT`). A missing CRIT value
   falls back to `95`.
2. **Disk.** `df -P` per mounted filesystem (skip pseudo/`tmpfs`/`devtmpfs` and read-only
   mounts — they cannot be cleaned). Two bands, computed per mountpoint:
   - usage ≥ `WATCHMAN_DISK_CRIT_PCT` ⇒ **dangerously low: severity `critical` (red)** —
     escalated above the profile floor, because a filesystem this full breaks services
     silently and imminently. Put the free figure in human units (`df -Ph`) in `detail`,
     **then name what is filling it** (next bullet).
   - else usage ≥ `WATCHMAN_DISK_WARN_PCT` ⇒ severity from `profile_severity disk_capacity`
     (the warn-band floor: high on a server, medium on a workstation).
   - below warn ⇒ no finding (record the metric only).

   **Critical band only — the largest-files enrichment (heavy read, deferrable).** A
   filesystem walk is heavy, so gate it: IF `io_should_defer_heavy`, append
   `"top-consumers scan deferred: $(io_pressure_reason)"` to `detail` and skip the walk
   (the critical finding from `df` is cheap and is journaled regardless — only this
   enrichment defers). OTHERWISE run `capacity_top_consumers "<mountpoint>"` and fold its
   output (largest files, `<human-size>\t<path>`, top `WATCHMAN_TOPFILES_COUNT`) into
   `detail` so the finding — and the email it triggers — answers "what do I delete?" The
   engine is read-only, stays on the one filesystem (`-xdev`), and reads metadata only; it
   NEVER frees space (that is the operator's call via `watchman fix`).

   Either band: `check_id=disk_capacity`, `target=<mountpoint>`, `risk_tier=safe` (the safe
   remediation is cleaning caches, not deleting user data — the fixer never deletes data).
   The fingerprint is stable across bands, so a filesystem that climbs from warn into the
   danger band UPDATES the existing finding in place (severity rises, the file list is
   added), never duplicates it.
3. **Inodes.** `df -iP`; ≥ `WATCHMAN_INODE_CRIT_PCT` ⇒ severity `critical` (red), else ≥
   `WATCHMAN_INODE_WARN_PCT` ⇒ `profile_severity inode_capacity`. `check_id=inode_capacity`
   (often the silent killer — a full inode table fails writes with space still free).
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
- `lib/capacity.sh` — `capacity_top_consumers <mountpoint>` (read-only largest-files walk,
  critical band only).
- `lib/io-courtesy.sh` — `io_should_defer_heavy` / `io_pressure_reason` (defer the walk
  under load); `capacity_top_consumers` itself runs via `io_run` when this is sourced.
- `config/watchman.conf` — capacity thresholds: the warn band (`*_WARN_PCT`) and the
  danger band (`WATCHMAN_DISK_CRIT_PCT` / `WATCHMAN_INODE_CRIT_PCT`) that escalates a
  finding to `critical` (red) when space is dangerously low.
