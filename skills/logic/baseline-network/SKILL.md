---
name: baseline-network
description: "ANALYZE: snapshot the machine's normal outbound connections to a baseline file, so the loop can flag NEW connections to NEW destinations as deltas."
lane: coding
allowed-tools: Read, Glob, Grep, Bash, Write
---

# baseline-network (Logic / Analyze)

Defines *normal* so change becomes visible. Snapshots the set of remote
destinations the machine normally talks to into `journal/network-baseline.txt`;
`inspect-logs` and `correlate-findings` then flag connections to destinations not
in the baseline. On a workstation, new outbound destinations are the highest-signal
delta the loop can detect.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## When to use

Run once during `/watchman audit` to establish the baseline (when none exists), and
on operator request to **re-baseline** after intended network changes. The loop
reads the baseline; it does not rewrite it.

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** `source lib/journal.sh lib/profile.sh`; `journal_init`.
   `BASELINE="journal/network-baseline.txt"`.
2. **Snapshot.** Collect established outbound remote endpoints: `ss -tunp state established`.
   Reduce to a stable set of `address:port` (and resolved owner where available),
   sorted and de-duplicated.
3. **Establish vs compare.**
   - If `$BASELINE` does **not** exist → write the snapshot to it. This is the
     skill's own state artifact (like the journal), not a destructive overwrite.
   - If it **does** exist → **do not overwrite it** in the unattended loop. Diff the
     current snapshot against it; emit nothing here (the comparison is reported by
     `inspect-logs`/`correlate-findings`). Re-baselining (overwriting) is an
     explicit operator action only.
4. **Never widen access.** This skill only reads connection state and writes its own
   baseline file; it never opens ports or changes the firewall.
<!-- /origin -->

## Grounding

- `lib/distro.sh` — `net_connections` (`ss`).
- `lib/journal.sh` — `journal_upsert` (if a baseline-establishment note is recorded).
- `inspect-logs`, `correlate-findings` — consumers of the baseline.
