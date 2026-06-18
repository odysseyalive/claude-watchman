---
name: inventory-security-tools
description: "OBSERVE: discover the host's OWN defensive tooling and bring it into scope — fail2ban, sshguard, CrowdSec, rkhunter, chkrootkit, auditd, ClamAV, AIDE, debsecan/arch-audit, wazuh/ossec. Reports what is present, whether it is actually effective, and flags a whole class of defense that is missing. Read-only; never installs or enables anything."
lane: coding
allowed-tools: Read, Glob, Grep, Bash
---

# inventory-security-tools (Grammar / Observe)

claude-watchman wraps battle-tested tools instead of reinventing them. This skill
makes that concrete from the *other* direction: it asks **what defensive tools does
this box already run**, brings each into scope, and checks it is actually doing its
job — then flags any whole *class* of defense (brute-force protection, rootkit
checking, host audit, file-integrity baseline) that is missing entirely. The box's
own toolset shapes what gets monitored. Read-only `security` / `integrity` / `config`
findings.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## What it does NOT do (the ownership boundary)

It is **discovery + health + gap detection only**, and strictly read-only — it never
runs a scan (no `rkhunter --check`, no `clamscan`, no `aide --check`) and never installs,
enables, or configures a tool. Where another engine already owns a tool's deeper finding,
this skill emits only the `info` inventory row and **defers**: CrowdSec hub freshness and
ClamAV/AIDE/CVE-scanner currency belong to `check-security-currency`; CrowdSec inbound
alerts belong to `inspect-logs`; AIDE file checks belong to `integrity`. No finding is
duplicated.

## When to use

Every `/watchman audit` / `/watchman loop` / `/watchman inventory`, after
`inventory-services` (which inventories the *service* surface — web/db/runtime).
Relevant on both profiles; the gap checks are profile-aware (rootkit/audit gaps are
server-only, via `lib/profile.sh`).

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** Run every claude-watchman function through the dispatcher —
   `bash lib/wm <function> [args…]` — which sources the libs (`lib/journal.sh`,
   `lib/distro.sh`, `lib/profile.sh`, `lib/sectools.sh`, `lib/io-courtesy.sh`) under bash
   internally; never `source lib/…` directly (dontAsk refuses a dot-source). Initialize with
   `bash lib/wm journal_init`. Determine the machine's family and profile by running
   `bash lib/wm watchman_family` and `bash lib/wm watchman_profile` and reading the printed
   values — use them to decide which checks apply. You do NOT pass them to `journal_upsert`
   (it auto-resolves them; pass `"" ""`). **I/O courtesy:** the observe step reads a
   couple of last-run logs; IF `bash lib/wm io_should_defer_heavy`, journal a `capacity`/`info`/`safe`
   `diagnostic_deferred` (`target=inventory-security-tools`): first run
   `bash lib/wm io_pressure_reason`, then set detail to its printed output (no `$(…)`).
   Skip this pass.
2. **Scan.** Run `bash lib/wm sectools_scan`. It is read-only — it detects each registry tool, reads its
   live status and the tail of any existing last-run log (never triggering a scan), and emits
   one TSV finding-candidate per row:
   `category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation`.
   It emits: an `info` **inventory** row per present tool (`check_id=sectool_inventory`,
   `target=<tool>`); a **health** row when a present tool is degraded — inactive, no jails,
   zero audit rules (`check_id=sectool_health`, `review` tier); and an **absent-defense** row
   per uncovered class (`check_id=defense_gap_*`, `manual` tier). No rows beyond inventory =
   the defenses are present and healthy.
3. **Journal each record** through the dispatcher exactly as emitted (pass `"" ""` for
   family/profile — `journal_upsert` auto-resolves them):
   `bash lib/wm journal_upsert "" "" <category> <severity> <risk_tier> <check_id> <target> <title> <detail> <remediation>`.
   `target` is the tool (inventory/health) or the class (gaps), so a defense that goes
   degraded or a tool that is removed **regresses loudly** on the next run.
4. **Tiers — never apply.** Inventory rows are `info`/`safe` context. A `sectool_health` row is
   `review`: the fix (e.g. `systemctl enable --now <unit>`) is shown and confirmed per-finding by
   the operator-run `watchman fix` — never the loop. A `defense_gap_*` row is `manual`: installing
   software is the operator's call; explain it and hand it back. NEVER install, enable, or
   configure a tool here.
5. **Summarize.** Lead with the most important gap (e.g. a public server with no brute-force
   protection) or any degraded defense; then name the protective tools that ARE present and
   healthy. If everything is covered, say the box's defensive tooling looks complete.
<!-- /origin -->

## Grounding

All claude-watchman functions below are reached via `bash lib/wm <function>` — the
dispatcher sources these libs internally; never `source lib/…` directly.

- `lib/sectools.sh` — `sectools_scan` (the registry + observe engine), `sectools_present`
  (present tools for the summary). Knob: `WATCHMAN_FLAG_AV_ABSENT` (flag absent antivirus; off by default).
- `lib/distro.sh` — `pkg_is_installed`, `service_status`, `pkg_install_cmd`, `watchman_family`.
- `lib/profile.sh` — `profile_severity` for `sectool_health` / `defense_gap_*` (single source of
  severity + profile-gating; rootkit/audit gaps are server-only).
- `lib/io-courtesy.sh` — `io_should_defer_heavy` / `io_pressure_reason` (defer under load).
- `lib/journal.sh` — `journal_upsert` (per-tool / per-class findings; regress over time).
- `skills/grammar/check-security-currency`, `skills/grammar/inspect-logs`, `skills/grammar/audit-system`
  — own the deferred deep findings (hub/signature/CVE currency, inbound alerts, Lynis).
- `skills/rhetoric/fix-redflag` — applies a `sectool_health` repair (review-tier, confirmed).
- `manifest.json` — declared permissions (`sectool_status`, `sectool_log_paths`, `service_status`, `pkg_query`).
