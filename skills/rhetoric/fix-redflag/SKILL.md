---
name: fix-redflag
description: "ACT: propose or apply remediation, STRICTLY bounded by each finding's risk_tier, and update the journal. The fixer — where the Prime Directive governs most directly."
lane: coding
allowed-tools: Read, Glob, Grep, Bash, Edit, Write
---

# fix-redflag (Rhetoric / Act)

Remediates findings and updates their status. This is the only skill that changes
system state, so the Prime Directive governs it most directly: its destructive-action
gate **is** the Prime Directive, layered on top of — never instead of — the risk
tiers. Operator-run only (`watchman fix`); it is deliberately absent from the
unattended loop's allowlist and from the watchman sudoers file.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## When to use

Only via `watchman fix`, interactively, with the operator present to confirm.

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Risk-tier gate (a hard safety boundary)

For every finding, behavior is bounded by its `risk_tier` — never widened:

- **`safe`** — may be applied on simple operator approval, and may be batch-applied
  *only where the profile permits* (`profile_allows_safe_batch`). These cannot
  plausibly break anything: add a missing security header, enable logrotate,
  persist journald.
- **`review`** — present the **exact change** and apply only after **explicit
  per-finding confirmation**. Never batch. This covers anything that can lock the
  operator out or break legitimate traffic: firewall rule changes, CORS tightening,
  anything touching SSH or authentication. **Firewall changes MUST show the exact
  rule and confirm before touching anything — a wrong rule can sever SSH.**
- **`manual`** — detect and explain only; **never auto-apply**. The correct fix is
  too context-specific to generate safely (a Content-Security-Policy is the canonical
  example). Flag it, explain it, hand it back.

## Workflow

1. **Preflight.** `source lib/journal.sh lib/distro.sh lib/profile.sh`; `journal_init`.
2. **Select** the finding(s) to address from the journal (operator chooses, or work
   the prioritized list).
3. **Branch on `risk_tier`** per the gate above. For `safe`, set status to `fixed`
   after applying. For `review`, show the exact diff/command, get a yes for THIS
   finding, then apply via the resolver (`firewall_allow`/`firewall_deny` show and
   confirm the exact rule; config edits via Edit). For `manual`, set status
   `in-review` and print the explanation — do not change the system.
4. **Prime-Directive preflight before EVERY mutating step.** If the action would
   delete/overwrite a file, modify a database, sever access, or stop/remove a
   service/package → STOP, WARN in plain language, ASK. Proceed only on explicit
   per-action consent. (Backing up a file you are about to edit is good practice;
   deleting one is destructive.)
5. **Verify, then journal.** After applying, verify the fix actually took (re-read
   the config / re-list the rule), then `journal_set_status <fp> fixed "<note>"`.
   If verification fails, leave it `open` and say so.
6. **Never escalate a tier.** Do not reclassify `review`/`manual` as `safe` to avoid
   a prompt. If a fix needs a tier you cannot satisfy, hand it back.
<!-- /origin -->

## Grounding

- `lib/journal.sh` — `journal_set_status`, finding reads.
- `lib/distro.sh` — `firewall_allow`/`firewall_deny`/`firewall_list`, `service_*` (all MUTATING; shown-and-confirmed).
- `lib/profile.sh` — `profile_allows_safe_batch`.
- `manifest.json` — note `fixes` is documented but NEVER granted to the loop.
