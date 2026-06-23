---
name: watchman
description: "claude-watchman operator commands — run IN a Claude Code session so token use is visible. Modes: audit | report | loop | monitor | fix | inventory | stats. (selfcheck and preflight are zero-token bash — run those with the `watchman` shell CLI, not here.)"
lane: coding
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, WebSearch, WebFetch
---

# watchman (in-session operator commands)

This is the AI-augmented half of claude-watchman. The token-spending operations —
**audit, report, loop, monitor, fix, inventory** — run here, inside a visible Claude Code
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
`/watchman loop`, `/watchman monitor`, `/watchman fix`, `/watchman inventory`,
`/watchman stats`. Run from the
claude-watchman repo root (paths below are relative to it). Journal every finding **only**
through `lib/journal.sh` — never touch `findings.db` directly. If no verb is given, list
the verbs and stop.

**Shell-CLI verbs are not handled here — redirect, don't run.** `selfcheck`, `preflight`,
`update`, and `uninstall` are the zero-token, bash-only half of claude-watchman; they live
in the `watchman` shell CLI on purpose (no Claude, no tokens). `uninstall` especially must
**never** be improvised in-session: it is destructive, and its tiered stop-warn-ask gating
lives in the shell script, not here. If the argument is one of these, do **not** read files
or improvise — print this one-liner and stop, mirroring the shell's own redirect of the AI
verbs:

> `<verb>` is a zero-token shell command — run **`watchman <verb>`** in your shell, not
> here. (`selfcheck` = plumbing check, `preflight` = regenerate the allowlist + this
> command, `update` = re-fetch the latest product, `uninstall` = remove claude-watchman.)
> The in-session verbs are: audit, report, loop, monitor, fix, inventory, stats.

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

**This session cannot fix anything — say so.** `audit` (whether launched with `watchman
audit`, `watchman safe`, or typed live) runs under the DEFAULT read-only profile, where
every mutating command auto-denies. So when you surface findings that need remediation,
warn the operator in plain language: to apply fixes they must **exit Claude and run
`watchman fix` from the shell** — that launcher opens a fresh session in the FIX profile
with the correct (mutating) permissions. Do not attempt the fixes here; you do not have
the permissions, and trying will only hit dead-end denials.

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

## monitor — Attended, announce-only watch of a single concern

`monitor` is the **inverse of `loop`**: where `loop` is a heavyweight whole-machine
journaling pass on a long cadence, `monitor` is a lightweight, single-concern, **ephemeral**
watch the operator runs *while they work*. The operator states — in plain words — what to
keep an eye on, and each pass announces only what is **new** since the last pass, giving
them a chance to react in real time. The canonical case: *"watch the Apache logs for CORS
preflight rejections while I tune `Access-Control-Allow-Origin`."*

**The argument is a freeform focus**, e.g. `/watchman monitor "watch the nginx error log
for CSP report-uri hits"` or `/watchman monitor "watch /var/log/myapp.log for stack
traces"`. If no focus is given, explain the verb and stop.

**How the operator drives it — their own `/loop`, in their own session.** monitor is one
pass; the operator makes it recurring by running it under Claude Code's `/loop` in the
session they are already working in:

```
/loop 1m /watchman monitor "watch the apache error log for CORS preflight 403s"
```

A 1–2 minute interval feels near-live during active testing. The watch lives and dies with
that `/loop` — stop the loop (or close the session) and monitoring ends. This is the
explicitly **attended** counterpart to the headless `watchman run`: there is **no email,
no OS trigger, and no journal write** — monitor only announces, in-session, where the
operator can see it.

**This runs in the operator's normal session, NOT the loop's `dontAsk` profile.** Because
the operator chooses what to watch, monitor needs to read arbitrary files and run arbitrary
**read-only** commands — which the read-only loop allowlist deliberately does not grant. So
monitor relies on the operator being present: the first time a pass reads a new file or runs
a new command, Claude Code prompts, the operator approves, and the approval is remembered for
the rest of the session. Do **not** try to widen any allowlist to silence those prompts.

**Each pass — decide a read-only probe, emit only the delta, interpret, announce:**

1. From the focus, work out *what to read*. Resolve real paths through the library when the
   concern is web/server-shaped (e.g. `bash lib/wm webserver_log_paths`,
   `bash lib/wm log_path_auth`) rather than guessing; otherwise use the explicit path the
   operator named.
2. Read **only what is new since the last pass**, via one of two deterministic helpers, so
   you never re-announce content already shown:
   - **File watch** → `bash lib/wm monitor_file_delta <path…>` — emits only the bytes
     appended since the previous pass (own offsets in `journal/monitor-offsets.txt`;
     rotation and truncation handled).
   - **Command watch** (a snapshot with no byte offset — open connections, a `grep` result
     set) → run the read-only command **yourself** (so the permission layer sees and gates
     the real command, e.g. `ss -tnp`, `journalctl -u … --since …`) and pipe it through
     `bash lib/wm monitor_diff <key>` — which prints only the lines new since the prior
     snapshot and saves the new baseline under `journal/monitor-state/<key>`. Use a stable
     `<key>` per watch (e.g. `cors-403`) so its baseline persists across passes.
   The **first** pass has no baseline, so it announces the current state — that establishes
   the baseline; subsequent passes announce only changes.
3. Interpret the new lines against the focus and **announce in plain language** — what
   appeared, why it matters, and the adjustment it points to (e.g. *"3 preflight `OPTIONS
   /api` got 403 in the last minute — your `Access-Control-Allow-Origin` doesn't list
   `https://staging.example.com`."*). If nothing new matches, say so briefly (one line) and
   end the pass — a quiet watch is a quiet pass.

**Read-only, by the Prime Directive.** monitor observes; it never fixes. **Never use a
mutating command as a watch probe** — no `rm`, no redirection that truncates a file, nothing
that changes service or firewall state. If the operator's focus can only be satisfied by a
mutating action, STOP and surface that instead of doing it. The two helpers above write only
their own gitignored scratch state (offsets and snapshot baselines), which is the sanctioned
advisory-state category — not a system change and not a journal database write.

## fix — Interactive remediation, bounded by risk tier

**Run this in a FIX-profile session, launched from the shell with `watchman fix`** — NOT
the loop's read-only `dontAsk` session, where every mutating command auto-denies and the
fixer can apply nothing. The launcher binds the session to `.claude/settings.fix.json`
("default" mode): safe-tier ops are pre-approved, every other mutating step prompts (that
prompt IS the risk-tier confirmation), and the destructive deny base still blocks
`rm`/`dd`/`systemctl stop`/sudoers. If you find mutations silently denied here, you are in
the wrong session — exit and relaunch with `watchman fix`.

The launcher opens the session **already running this command**: it submits `Run /watchman
fix` as the first prompt (natural language, not a bare slash command — Claude Code drops a
startup positional prompt that begins with `/`, but executes one that reads as a normal
turn), so the operator lands in the remediation flow instead of a blank prompt. If you
ever do start from a blank prompt, just type `/watchman fix` live — typed slash commands
work in-session.

Execute `skills/rhetoric/fix-redflag/SKILL.md` exactly. For each finding, act STRICTLY
within its `risk_tier`: `safe` on simple approval; `review` only after showing the exact
change and getting explicit per-finding confirmation (firewall rules MUST show the exact
rule first — a wrong rule can sever SSH); `manual` is explained and handed back, never
auto-applied. Update finding status via `lib/journal.sh` as work is done. The Prime
Directive's stop-warn-ask gate governs every destructive action.

**Be proactive — open with a plan, prepare every change, don't just acknowledge.** The
operator came here to remediate. So *first* pull the prioritized `open`+`regressed`
worklist and present it as a numbered remediation plan. Then for **every** finding
prepare the exact change up front — the config line, the diff, the firewall rule, the
drafted policy — so their only decision is yes/no, never "go write the fix yourself."
Batch the `safe` tier into one "apply all N?" prompt where the profile permits; show
the exact change before any `review` apply; hand `manual` back as a drafted,
ready-to-paste artifact, not advice. Handing a fixable finding back as advice instead
of a staged change is a defect. **Fill knowledge gaps with the web** before proposing
(`WebSearch` + `WebFetch` an authoritative source, cite it) — research is read-only and
never bypasses a tier. See the skill's "Stance" and "Fill knowledge gaps" sections.

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
