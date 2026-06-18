# claude-watchman

> **It only speaks up when something's wrong.** claude-watchman watches a Linux box,
> remembers what it sees, and emails you only when something actually changes. A quiet
> machine stays quiet. No dashboards to babysit, no alert fatigue.

> **PRIME DIRECTIVE — it never does anything destructive.** Every skill carries one
> rule, verbatim: nothing that deletes data, modifies a database, severs access, or
> stops a service happens without stopping to ask you first. The unattended loop has
> no one to ask — so it physically cannot reach a destructive step. [How that's enforced →](#safety--two-seatbelts-and-a-backstop)

claude-watchman is a set of Claude Code skills that run one loop: look at the machine,
write down what's wrong, help you fix it. It only reaches out when the picture changes.
It runs on Debian/Ubuntu, RHEL-family, and Arch, and adapts to whether the box is a
public **server** or a personal **workstation**.

It drives proven tools (Lynis, CrowdSec, journald, your distro's own integrity
verifier) and layers on a durable journal, plain-language explanations, and the
judgment to tell a new problem from old news.

> **Bonus: privacy-respecting web analytics, no trackers.** Your web server already
> keeps access logs for security. claude-watchman turns them into a decent traffic
> report — page views, unique visitors, top pages, referrers, bots-vs-humans — with
> **no Google Analytics, no cookies, no JavaScript, no third parties**. IPs are
> correlated in memory only and never stored or shown, so it's a GDPR-friendly stand-in
> for the analytics you can't run compliantly. Run `/watchman stats`. [More →](#web-analytics-without-the-trackers)

## How it works

One cycle, running at different speeds. The journal in the middle is what lets the
pieces talk to each other.

| Stage | Role | What it does |
|-------|------|--------------|
| **Observe** | grammar skills | Read the machine: hardening scan, services, logs, log retention, capacity. |
| **Analyze** | logic skills | Make sense of it: OOM/crash postmortem, network baseline, dedupe, compute the delta. |
| **Act & report** | rhetoric skills | Fix what's safe (with your OK), summarize, and email when a threshold trips. |

Every finding lands in a SQLite journal with a stable fingerprint, so re-running never
creates duplicates — it updates what's already there. The highest-signal event the loop
can raise is a **regression**: something you fixed that came back.

## Install

**No `git clone` needed.** Make a directory for claude-watchman and run the installer
from inside it — it fetches the project file-by-file from a manifest into that directory.
Use the `bash -c "$(...)"` form so the prompts keep your terminal:

```bash
mkdir watchman && cd watchman && bash -c "$(curl -fsSL https://raw.githubusercontent.com/odysseyalive/claude-watchman/main/install.sh)"
```

Run it as root. It detects your distro and profile, installs dependencies, sets up the
journal and config, and generates the Claude permission allowlist. Every privileged
step asks first. There's no service user to create — claude-watchman runs as root and
reads your logs directly. **The same command installs and updates** — see Updating.

## Quick start

**1. Check the plumbing first — no Claude needed.** This proves the resolvers, journal,
dependencies, and permissions all work on this box before you trust anything else.

```bash
watchman selfcheck
```

**2. Launch Claude Code — this is its own step.** The `audit`, `report`, `fix`,
`inventory`, and `stats` features are AI-driven, so they run *inside* a Claude Code
session (where you watch the work and the token meter), **not** from the shell. Open a
session, as root:

```bash
claude
```

The first time, type `/login` at the Claude prompt to authenticate (it remembers you
after). You are now **inside the session**, at Claude Code's own prompt — this is the only
place the `/watchman` slash-commands work.

**3. Run your first audit — from inside that session.** At the Claude prompt, type:

```
/watchman audit
```

It observes and analyzes the machine and journals what it finds (no changes). Then ask for
a plain-language summary:

```
/watchman report
```

That's the whole loop: launch `claude` once, then drive it with `/watchman …` commands.
(If you type `watchman audit` at your **shell** by mistake, it will point you back here —
the slash-command form, inside `claude`, is the one that runs.)

**4. Turn on recurring monitoring.** Keep the loop in a tmux session so it persists but
stays visible. Start a persistent session:

```bash
tmux new -s watchman
```

Inside it, launch Claude as root (`claude`, run `/login` once), then start the recurring
pass:

```
/loop 6h /watchman loop
```

Press `Ctrl-b` then `d` to detach — the loop keeps running. It observes, journals, and
emails you only when something crosses a threshold. Re-attach with
`tmux attach -t watchman` whenever you want to see what it's doing.

## Email reports — fill in `.env`

The loop reaches you by email, and only when a threshold trips. Those reports go out
through **your own SMTP relay**, whose credentials live in a gitignored `.env` at the repo
root — never in `config/watchman.conf`, never in a skill. `lib/smtp.sh` is the only code
that reads them, and nothing leaves the host except the report itself.

The installer copies the template to `.env` for you and prompts you to fill it in. To do it
by hand from your watchman directory:

```bash
cp .env.example .env
```

Then edit `.env` and set these keys:

| Key | What it is |
|-----|------------|
| `SMTP_HOST` | Relay hostname, e.g. `smtp.example.com`. |
| `SMTP_PORT` | `587` for STARTTLS (the usual choice), `465` for implicit TLS. |
| `SMTP_USER` | Auth user for the relay — also used as the `From:` address. |
| `SMTP_PASS` | App password / relay secret. **Leave blank to disable email.** |
| `REPORT_EMAIL` | The inbox where reports land — your operator address. |

**Email is optional.** If `SMTP_PASS` is left blank, mail is treated as unconfigured: the
loop logs "unconfigured" and skips sending instead of crashing, so you can run `audit`,
`report`, `fix`, and even the loop with no relay at all — you just won't get email until
you fill it in. `.env` is gitignored and is the single source of mail credentials; the
committed `.env.example` is only a placeholder template.

## Commands

claude-watchman splits its verbs on the token line. The ones that spend nothing are
shell commands; the AI features run inside a Claude Code session as `/watchman <verb>`,
so their token use is always in front of you.

**The two halves run in two different places, and they're not interchangeable.** The
shell verbs (`selfcheck`, `preflight`, `update`) are typed at your **OS terminal** — the
same prompt where you'd type `ls`, with **no** leading slash. The `/watchman` verbs are
typed at the **Claude Code prompt**, *inside* a session, **with** the leading slash. Typing
a shell verb like `watchman update` into the Claude prompt won't update anything — Claude
will just point you back to your terminal (and vice-versa). When in doubt: no slash → your
shell; slash → inside `claude`.

**Shell CLI** — bash only, no Claude, no tokens (run at your OS terminal):

| Command | What it does |
|---------|--------------|
| `watchman selfcheck` | Bash-only plumbing check. Run first on any new host. |
| `watchman preflight` | Regenerate the Claude allowlist + the in-session `/watchman` command. |
| `watchman update` | Re-fetch the latest product (manifest, no git) + regenerate locals. Same as installing. |

**In a Claude Code session** — AI features, visible token use (typed at the `claude` prompt, with the slash):

| Command | What it does |
|---------|--------------|
| `/watchman audit` | Observe + analyze, journal findings. No fixes. |
| `/watchman report` | Plain-language summary of the journal. |
| `/watchman loop` | One pass: observe → journal → delta → email if it matters. |
| `/watchman fix` | Interactive remediation, bounded by each finding's risk tier. |
| `/watchman inventory` | What's installed and how it serves. |
| `/watchman stats` | Privacy-respecting web traffic analytics from access logs. On demand, not the loop. |

`fix` is the only verb that ever changes the system, and it's always interactive. It
shows you the exact change, asks before applying anything risky, and never touches a
firewall rule or SSH config without showing the rule first.

## Running it

Run claude-watchman as **root** — it reads every log and journal directly, so there's
no service user and no sudoers to manage. Auth is Claude Code's own login; there are no
API keys. The AI verbs run in-session on purpose: Claude Code spends tokens on every
pass, and you should be able to see that happening — never a silent background daemon.

**One-off checks** — launch a session as root:

```bash
claude
```

Then, inside the session, run `/watchman audit` and `/watchman report`.

**Recurring monitoring** — keep the loop in a tmux session; it persists across logout but
stays attachable, so you always see what it's doing and what it spends. Start a persistent
session:

```bash
tmux new -s watchman
```

Inside it, launch Claude as root (`claude`, run `/login` once), then start the loop:

```
/loop 6h /watchman loop
```

Press `Ctrl-b` then `d` to detach; re-attach any time with `tmux attach -t watchman`.

**It won't take down a busy server — and it knows its own footprint.** The heavy reads
(integrity verification, full log scans, Lynis, journald walks) run at a priority set by
its **role**, and are **skipped when the box is under real I/O pressure** — measured by
the kernel's `/proc/pressure/io` (PSI) where available, not just a load average — with the
loop recording "deferred — system busy" and retrying next pass. It also **measures what it
itself costs** per check (time, and I/O where GNU `time` is present) and flags a check that
gets expensive. Set the **role** in `config/watchman.conf`: `WATCHMAN_PRIORITY=guest` (yield
to everything, the default), `peer`, or `priority` — the last for a **dedicated monitoring
box where claude-watchman is the critical workload** and should keep running rather than
defer. Thresholds (`WATCHMAN_IO_GUARD_PSI`, `WATCHMAN_CHECK_TIME_BUDGET`, …) are tunable.
And the loop reads logs **incrementally** — only the new lines since the last pass — so its
read stays proportional to recent traffic, not the size of your logs (`/watchman stats`
still reads the full set for an authoritative report).

## Safety — two seatbelts and a backstop

The loop is observe-and-report only. Two independent layers keep it that way, with a
deny base beneath them:

1. **Risk tiers.** The fixer never auto-applies a `review` or `manual` finding. It shows
   the exact change and confirms per-finding.
2. **Loop allowlist.** The loop runs under a read-only observe + report profile in
   `dontAsk` mode, so it *cannot* invoke a mutating command — it auto-denies and fails
   loud. Remediation lives in a **separate** profile that only `watchman fix` selects.
3. **Deny base (backstop).** Even running as root, every profile embeds the same deny
   list — `rm`, `dd`, `mkfs`, `systemctl stop/disable`, anything touching sudoers, plus
   `Edit`/`Write` of shadow & sudoers — and an allow can never override a deny.

`bypassPermissions` is never used. Remediation only ever happens when **you** run
`watchman fix`, which launches a dedicated session in `"default"` mode: safe toggles are
pre-approved, every other fix prompts per finding (that prompt *is* the confirmation),
and the deny base above still holds. Maintainers get a third profile via `watchman dev`
(repo-write, `acceptEdits`) so editing the source never means loosening the live policy.

## What it watches

| | Server | Workstation |
|---|--------|-------------|
| Looks for | Inbound attack surface — exposed ports, web headers, CORS, SSH hardening, probes, and request-rate spikes (DDoS/abuse) that propose a firewall block | What the machine talks *to* — new outbound connections vs. a baseline |
| Top concern | Public-facing exposure | **Log retention** — volatile journald loses the forensic trail on reboot |
| Both | Lynis hardening index over time, capacity (disk/inodes/memory), OOM/crash postmortem, package integrity, forensic-trail tampering (shell history / login records wiped), and **security currency** — pending updates, known-CVE packages, threat-intel/signature freshness, and whether auto-update is even on | |

## Web analytics, without the trackers

You can't run Google Analytics GDPR-cleanly, and most privacy-first tools still want
JavaScript and a third-party service. But your web server already writes an access log
for every request — kept for security — and that log holds everything a traffic report
needs. `/watchman stats` reads it and prints:

- **page views** and **unique visitors** (deduplicated, so one person reloading doesn't
  skew the numbers), **top pages by unique visitor**, **referrers**, **status-code mix**,
  **bots-vs-humans**, and a **daily trend**.

Privacy is the point — the client IP is used **only in memory** to correlate a visitor's
requests, then discarded; it is never stored, never hashed-and-kept, never shown. The
report is pure anonymous aggregates, computed entirely on your own box — nothing
client-side to install, and **nothing leaves the host**. It reads current and rotated logs
(including `.gz`), and breaks down per site when you serve several.

Run it on demand — it is deliberately **not** part of the monitoring loop:

```
/watchman stats
```

## Distro support

Skills stay distro-blind; one resolver knows the differences.

| | Debian / Ubuntu | RHEL family | Arch |
|---|---|---|---|
| Packages | apt / dpkg | dnf / rpm | pacman |
| Firewall | ufw | firewalld | nftables / ufw |
| MAC | AppArmor | SELinux | (none by default) |
| Integrity | debsums | rpm -V | pacman -Qkk |

## Updating

**Updating is the same command as installing** — re-run it from your watchman directory,
or use the verb:

```bash
watchman update
```

Both re-fetch the latest product from the manifest into your directory, then regenerate
the local artifacts (the permission allowlist and the in-session `/watchman` command) and
run any additive journal migration. It is **safe by construction**: the manifest lists
only the portable product, so a re-fetch overwrites code files and **never touches your
machine-specific state** — `.env`, `config/watchman.conf`, `journal/findings.db` aren't in
the manifest. The fetch is atomic (everything downloads to a temp dir and moves into place
only if all files succeed), so a dropped connection can't leave you half-updated. A lossy
schema migration would stop and ask (the Prime Directive). No `git` is involved — none of
the clone/pull/divergence failure modes apply.

Maintainers: after adding or removing a product file, run `watchman update --sync` to
regenerate `manifest.txt` from the tracked product, then `watchman update --check` (in the
git repo, after `git add`) before committing. The check asserts the update story still
holds: every machine artifact is gitignored and untracked, **`manifest.txt` lists exactly
the tracked product** (so a new skill can't silently fail to ship), every skill carries the
Prime Directive, every observe/analyze skill is wired into the `/watchman` orchestration,
and the journal schema version is in sync.

## What gets committed

Portable product only: `skills/`, `commands/`, `lib/`, `bin/watchman`,
`journal/schema.sql`, `install.sh`, `manifest.txt`, the `*.example` templates,
`.gitignore`, and this README. Anything machine-specific or secret — `.env`,
`config/watchman.conf`, `journal/findings.db`, `.claude/`, `CLAUDE.md` — is gitignored and
never leaves the host.

## License

MIT
