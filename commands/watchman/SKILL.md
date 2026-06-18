---
name: watchman
description: "claude-watchman operator commands — run IN a Claude Code session so token use is visible. Modes: audit | report | loop | fix | inventory | stats. (selfcheck and preflight are zero-token bash — run those with the `watchman` shell CLI, not here.)"
lane: coding
allowed-tools: Read, Glob, Grep, Bash, Edit, Write
---

# watchman (in-session operator commands)

This is the AI-augmented half of claude-watchman. The token-spending operations —
**audit, report, loop, fix, inventory** — run here, inside a visible Claude Code
session, so you always see what they do and what they spend. (The zero-token plumbing,
`selfcheck` and `preflight`, stays in the `watchman` shell CLI — do not run it here.)

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## How to invoke

The verb arrives as this skill's argument: `/watchman audit`, `/watchman report`,
`/watchman loop`, `/watchman fix`, `/watchman inventory`, `/watchman stats`. Run from the
claude-watchman repo root (paths below are relative to it). Journal every finding **only**
through `lib/journal.sh` — never touch `findings.db` directly. If no verb is given, list
the verbs and stop.

**Shell-CLI verbs are not handled here — redirect, don't run.** `selfcheck`, `preflight`,
and `update` are the zero-token, bash-only half of claude-watchman; they live in the
`watchman` shell CLI on purpose (no Claude, no tokens). If the argument is one of these,
do **not** read files or improvise — print this one-liner and stop, mirroring the shell's
own redirect of the AI verbs:

> `<verb>` is a zero-token shell command — run **`watchman <verb>`** in your shell, not
> here. (`selfcheck` = plumbing check, `preflight` = regenerate the allowlist + this
> command, `update` = re-fetch the latest product.) The in-session verbs are: audit,
> report, loop, fix, inventory, stats.

For any other unrecognized argument, list the in-session verbs and stop.

---

## audit — Observe + Analyze (no fixes)

1. Execute each OBSERVE skill in order, following its `SKILL.md` exactly:
   `skills/grammar/audit-system`, `skills/grammar/inventory-services`,
   `skills/grammar/inventory-security-tools`,
   `skills/grammar/inspect-web-config`, `skills/grammar/inspect-cpanel`, `skills/grammar/inspect-logs`,
   `skills/grammar/check-log-retention`, `skills/grammar/check-shell-history`,
   `skills/grammar/check-security-currency`, `skills/grammar/check-capacity`.
2. Then each ANALYZE skill: `skills/logic/diagnose-crash`,
   `skills/logic/baseline-network`, `skills/logic/correlate-findings`,
   `skills/logic/prioritize-redflags`.

Journal every finding through `lib/journal.sh` (create-or-update; never duplicate). Do
**not** apply any remediation. When done, tell the operator to run `/watchman report`
for the summary.

## report — Plain-language summary of the journal

Execute `skills/rhetoric/report-status/SKILL.md` exactly: produce a human-readable
summary of the current journal state (`open`, `regressed`, `fixed`, `ignored`), reading
only through `lib/journal.sh`. Make no changes.

## loop — ONE pass: observe → journal → delta → conditional report

1. Execute the OBSERVE skills under `skills/grammar/` by following each `SKILL.md`,
   journaling via `lib/journal.sh` only.
2. Execute `skills/logic/correlate-findings/SKILL.md` to compute the delta against the
   previous run (new high-severity findings, and especially **regressed** findings).
3. **Only if** the delta crosses the configured threshold, execute
   `skills/rhetoric/send-report/SKILL.md` to email the operator. A quiet machine sends
   nothing.

This pass is OBSERVE + REPORT ONLY — never apply a fix. (For unattended cadence, the
operator drives this with Claude Code's `/loop 6h /watchman loop` inside a tmux session
they can re-attach to.)

## fix — Interactive remediation, bounded by risk tier

**Run this in a FIX-profile session, launched from the shell with `watchman fix`** — NOT
the loop's read-only `dontAsk` session, where every mutating command auto-denies and the
fixer can apply nothing. The launcher binds the session to `.claude/settings.fix.json`
("default" mode): safe-tier ops are pre-approved, every other mutating step prompts (that
prompt IS the risk-tier confirmation), and the destructive deny base still blocks
`rm`/`dd`/`systemctl stop`/sudoers. If you find mutations silently denied here, you are in
the wrong session — exit and relaunch with `watchman fix`.

Execute `skills/rhetoric/fix-redflag/SKILL.md` exactly. For each finding, act STRICTLY
within its `risk_tier`: `safe` on simple approval; `review` only after showing the exact
change and getting explicit per-finding confirmation (firewall rules MUST show the exact
rule first — a wrong rule can sever SSH); `manual` is explained and handed back, never
auto-applied. Update finding status via `lib/journal.sh` as work is done. The Prime
Directive's stop-warn-ask gate governs every destructive action.

## inventory — What is installed and how it serves

Execute `skills/grammar/inventory-services/SKILL.md` exactly and report what is installed
and how it serves (web server, database, php-fpm, etc.). Then execute
`skills/grammar/inventory-security-tools/SKILL.md` exactly to discover the host's defensive
tooling (fail2ban, CrowdSec, rkhunter, auditd, ClamAV, AIDE, …), whether each is effective,
and any whole class of defense that is missing. Journal findings only through
`lib/journal.sh`. Observe only — no changes.

## stats — Privacy-respecting web traffic analytics (on demand, NOT the loop)

Execute `skills/rhetoric/web-stats/SKILL.md` exactly: a GDPR-friendly traffic report built
from the server's own access logs — page views, unique visitors, top pages by unique
visitor (dedup'd so reloads don't skew), referrers, status mix, bots-vs-humans, daily
trend. IPs are correlated **in memory only** and never stored or shown; the report is pure
anonymous aggregates. Read-only — no findings, no config, no firewall. This is an
operator-run feature: it is **never** part of the audit or loop.
