---
name: audit-system
description: "OBSERVE: run the profile-appropriate security audit by wrapping Lynis, fold warnings/suggestions into the journal, and track the hardening index over time."
lane: coding
allowed-tools: Read, Glob, Grep, Bash
---

# audit-system (Grammar / Observe)

Establishes *what is* about system hardening. Wraps **Lynis** — claude-watchman
does not re-detect what Lynis already detects; its value-add is journaling, dedup,
risk-tiering, and plain-language explanation. Read-only: it scans and journals, it
never fixes.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## When to use

Part of every `/watchman audit` and `/watchman loop` pass. Run it to refresh the
hardening picture and track the Lynis hardening index as a trend.

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** `source lib/journal.sh lib/distro.sh lib/profile.sh`; `journal_init`.
   Resolve `family="$(watchman_family)"` and `profile="$(watchman_profile)"`.
2. **Run Lynis** (read-only system audit): `sudo lynis audit system --quiet --no-colors`.
   Lynis writes machine-readable results to `$(log_path_lynis)`
   (`/var/log/lynis-report.dat`). Do not parse human stdout — parse the report file.
3. **Capture the hardening index** as a tracked metric:
   read `hardening_index=` from the report and
   `journal_record_metric lynis_hardening_index "$value"` so the loop can chart drift.
4. **Fold findings in.** For each `warning[]` and `suggestion[]` line in the report:
   - `category=security` (or `config` for non-security hardening suggestions);
   - severity: warnings → `high`/`medium`, suggestions → `low`/`info`, adjusted by
     `profile_severity` where a matching `check_id` exists; skip checks that
     `profile_runs_check` says do not apply to this profile;
   - risk tier: default `manual` (Lynis suggestions are usually context-specific);
     only mark `safe` for unambiguous toggles;
   - `journal_upsert "$family" "$profile" "$category" "$severity" "$risk_tier" \
       "lynis_<test-id>" "$target" "$title" "$detail" "$remediation"`.
5. **Never remediate here.** Hand fixes to `fix-redflag`. Re-running must update
   findings in place (the fingerprint guarantees no duplicates).
<!-- /origin -->

## Grounding

- `lib/journal.sh` — the only gate to findings.db (`journal_upsert`, `journal_record_metric`).
- `lib/distro.sh` — `log_path_lynis`, `watchman_family`.
- `lib/profile.sh` — `profile_severity`, `profile_runs_check`.
- `manifest.json` — declared permissions (lynis + the report path).
