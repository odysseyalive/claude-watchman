---
name: send-report
description: "EXPRESS: email the operator via SMTP when the delta crosses a threshold. A quiet machine sends nothing. Credentials come only from .env via lib/smtp.sh."
lane: coding
allowed-tools: Read, Glob, Grep, Bash
---

# send-report (Rhetoric / Express)

How a headless, scheduled claude-watchman reaches the operator. Builds the report
(via `report-status`) and dispatches it **only when** `correlate-findings` says the
delta crossed a configured threshold — so the operator hears from the tool only
when something is worth hearing about. Mail credentials live solely in `.env` and
are read solely by `lib/smtp.sh`.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## When to use

In `/watchman loop`, after `correlate-findings`, gated by the threshold. Not part of
a plain `/watchman report` (that just prints).

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** `source lib/journal.sh lib/smtp.sh lib/profile.sh`; `journal_init`.
2. **Threshold check.** Read the run summary / counts. Send **only if**:
   a new finding ≥ `WATCHMAN_NOTIFY_MIN_SEVERITY`, OR a regression occurred and
   `WATCHMAN_NOTIFY_ON_REGRESSION=yes`, OR (workstation) a new outbound destination and
   `WATCHMAN_NOTIFY_ON_NEW_OUTBOUND=yes`. Otherwise **send nothing** and exit quietly.
3. **Build the body** from `report-status` output. Subject should name the machine and
   lead with the headline (e.g. "watchman: 1 REGRESSED, 2 new high on <host>").
4. **Dispatch** via `send_report "<subject>" <body_file>` in `lib/smtp.sh`. Never read
   `.env` or SMTP creds directly — `smtp.sh` is the only gate.
5. **Degrade gracefully.** If mail is unconfigured (`.env` missing / `SMTP_PASS` blank)
   or `msmtp` absent, `smtp.sh` logs and skips — the loop continues, never crashes.
6. **No system changes.** This skill only reads the journal and sends mail.
<!-- /origin -->

## Grounding

- `lib/smtp.sh` — `send_report`, `smtp_is_configured` (the only reader of `.env`).
- `lib/journal.sh` — run summary and counts.
- `config/watchman.conf` — notify thresholds.
- `report-status` — supplies the email body.
