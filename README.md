# claude-watchman

> **It only speaks up when something's wrong.** claude-watchman watches a Linux or macOS box,
> remembers what it sees, and emails you only when something actually changes. A quiet
> machine stays quiet. No dashboards to babysit, no alert fatigue.

> **PRIME DIRECTIVE: it never does anything destructive.** Every skill carries one
> rule, verbatim: nothing that deletes data, modifies a database, severs access, or
> stops a service happens without stopping to ask you first. The unattended loop has
> no one to ask, so it physically cannot reach a destructive step. [How that's enforced →](#safety-two-seatbelts-and-a-backstop)

claude-watchman is a set of Claude Code skills that run one loop: look at the machine,
write down what's wrong, help you fix it. It only reaches out when the picture changes.
It runs on Debian/Ubuntu, RHEL-family, Arch, and macOS, and adapts to whether the box is a
public **server** or a personal **workstation**.

It drives proven tools (Lynis, CrowdSec, journald, your platform's own integrity
verifier) and layers on a durable journal, plain-language explanations, and the
judgment to tell a new problem from old news.

> **Bonus: privacy-respecting web analytics, no trackers.** Your web server already
> keeps access logs for security. claude-watchman turns them into a decent traffic
> report (page views, unique visitors, top pages, referrers, bots-vs-humans) with
> **no Google Analytics, no cookies, no JavaScript, no third parties**. IPs are
> correlated in memory only and never stored or shown, so it's a GDPR-friendly stand-in
> for the analytics you can't run compliantly. Run `/watchman stats`. [More →](#web-analytics-without-the-trackers)

## How it works

One cycle, running at different speeds. The journal in the middle is what lets the
pieces talk to each other.

| Stage | Role | What it does |
|-------|------|--------------|
| **Observe** | grammar skills | Read the machine: hardening scan, services, the host's own defensive tooling, logs, log retention, capacity. |
| **Analyze** | logic skills | Make sense of it: OOM/crash postmortem, network baseline, dedupe, compute the delta. |
| **Act & report** | rhetoric skills | Fix what's safe (with your OK), summarize, and email when a threshold trips. |

Every finding lands in a SQLite journal with a stable fingerprint, so re-running never
creates duplicates; it updates what's already there. The highest-signal event the loop
can raise is a **regression**: something you fixed that came back.

## Install

**Run this as `root`, from root's home directory (`/root`).** claude-watchman runs as
root (it reads your logs and journal directly, with no service user), so install it as
root too. Log in as root (or `sudo -i` to get a root shell in `/root`) before you start.

**No `git clone` needed.** Make a directory for claude-watchman and run the installer
from inside it. It fetches the project file-by-file from a manifest into that directory.
Use the `bash -c "$(...)"` form so the prompts keep your terminal:

```bash
cd /root && mkdir watchman && cd watchman && bash -c "$(curl -fsSL https://raw.githubusercontent.com/odysseyalive/claude-watchman/main/install.sh)"
```

That puts watchman at `/root/watchman`. It detects your platform and profile, installs
dependencies, sets up the journal and config, and generates the Claude permission
allowlist. Every privileged step asks first. There's no service user to create;
claude-watchman runs as root and reads your logs directly. **The same command installs
and updates** (see Updating).

### Windows

On Windows, claude-watchman runs as a native PowerShell port, no WSL, no Git Bash. Open an
**elevated** PowerShell (Run as administrator, the analogue of root), make a directory, and run
the installer one-liner. It detects the family/profile, sets up the journal and config, generates
the Claude permission profiles, and adds the install dir to your PATH:

```powershell
mkdir watchman; cd watchman; iwr -useb https://raw.githubusercontent.com/odysseyalive/claude-watchman/main/install.ps1 | iex
```

Open a **new** elevated PowerShell so the PATH change takes effect, then run the plumbing check:

```powershell
watchman selfcheck
```

Everything else is identical to the Linux flow (`watchman audit`, `/watchman loop`, `watchman fix`)
except the headless cadence uses Task Scheduler instead of systemd/cron (`watchman schedule
install --every 6h`), and `audit-system` runs native Windows hardening checks (Defender, BitLocker,
UAC, firewall, SMBv1, RDP/NLA) in place of Lynis.

## Quick start

**1. Check the plumbing first (no Claude needed).** This proves the resolvers, journal,
dependencies, and permissions all work on this box before you trust anything else.

```bash
watchman selfcheck
```

**2. Launch Claude Code (this is its own step).** The `audit`, `report`, `inventory`,
and `stats` features are AI-driven, so they run *inside* a Claude Code session (where you
watch the work and the token meter), **not** from the shell. Open a session, as root,
with the `watchman safe` launcher, which starts Claude in the watchman directory under the
default read-only profile (the same context as running `claude` here):

```bash
watchman safe
```

The first time, type `/login` at the Claude prompt to authenticate (it remembers you
after). You are now **inside the session**, at Claude Code's own prompt. This is the only
place the `/watchman` slash-commands work. (This is a read-only session; to *apply* a
fix later, exit and run `watchman fix`, which opens the FIX profile with the right
permissions.)

> **Note: `watchman safe` is for diagnostics only.** It opens Claude under the default
> read-only profile, which is designed to run diagnostic routines and nothing else. It
> exists precisely to keep Claude from making any destructive decisions. Observe, analyze,
> report: yes. Changing the system: no. Every mutating command auto-denies in this
> session, so the only way to *apply* a fix is to exit and run `watchman fix`, where each
> change is shown and confirmed.

**Pick the model (Opus is recommended).** Once you're inside the session, choose which
Claude model does the work by typing `/model` at the prompt. claude-watchman leans on the
model's judgment (telling a real regression from old news, reading a crash postmortem,
deciding a finding's risk tier), so the sharper the model, the better the analysis. Choose
**Opus** for the strongest reasoning and the most reliable risk-tiering. Whatever you pick
is the model that runs every watchman activity from then on: audits, reports, the loop,
remediation. The choice carries through the whole tool, not just this session.

**3. Run your first audit, from inside that session.** At the Claude prompt, type:

```
/watchman audit
```

It observes and analyzes the machine and journals what it finds (no changes). Then ask for
a plain-language summary:

```
/watchman report
```

That's the whole loop: launch a session once with `watchman safe`, then drive it with
`/watchman …` commands. (`watchman audit` and `watchman report` at your shell also work;
they just open a session already running that slash-command for you.)

**4. Turn on recurring monitoring.** Keep the loop in a detached tmux session so it
persists across logout but stays attachable. Both cadence options (the visible tmux
loop and the headless schedule) are covered under
[Recurring monitoring](#recurring-monitoring) below.

## Email reports: fill in `.env`

The loop reaches you by email, and only when a threshold trips. Those reports go out
through **your own SMTP relay**, whose credentials live in a gitignored `.env` at the repo
root, never in `config/watchman.conf` and never in a skill. `lib/smtp.sh` is the only code
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
| `SMTP_USER` | Auth user for the relay, and the `From:` address. |
| `SMTP_PASS` | App password / relay secret. **Leave blank to disable email.** |
| `REPORT_EMAIL` | The inbox where reports land (your operator address). |

**Email is optional.** If `SMTP_PASS` is left blank, mail is treated as unconfigured: the
loop logs "unconfigured" and skips sending instead of crashing, so you can run `audit`,
`report`, `fix`, and even the loop with no relay at all; you just won't get email until
you fill it in. `.env` is gitignored and is the single source of mail credentials; the
committed `.env.example` is only a placeholder template.

Once `.env` is filled in, prove delivery end to end before you trust the loop to reach
you. `watchman testmail` authenticates to your relay and sends one test message to
`REPORT_EMAIL`:

```bash
watchman testmail
```

It's a zero-token shell verb (no Claude), it changes nothing on the system, and it's
loud on failure: if mail is unconfigured or `msmtp` isn't installed it tells you exactly
what to fix rather than skipping quietly. A success means a message is on its way; check
the inbox (and the spam folder).

## Commands

claude-watchman splits its verbs on the token line. The ones that spend nothing are
shell commands; the AI features run inside a Claude Code session as `/watchman <verb>`,
so their token use is always in front of you.

**The two halves run in two different places, and they're not interchangeable.** The
shell verbs (`selfcheck`, `preflight`, `update`, plus the `fix`/`dev` *launchers*) are
typed at your **OS terminal**, the same prompt where you'd type `ls`, with **no** leading
slash. The `/watchman` verbs are typed at the **Claude Code prompt**, *inside* a session,
**with** the leading slash. Typing a shell verb like `watchman update` into the Claude
prompt won't update anything; Claude will just point you back to your terminal (and
vice-versa). When in doubt: no slash → your shell; slash → inside `claude`.

**Shell CLI**, bash only, no Claude, no tokens (run at your OS terminal):

| Command | What it does |
|---------|--------------|
| `watchman selfcheck` | Bash-only plumbing check. Run first on any new host. |
| `watchman preflight` | Regenerate the Claude allowlist + the in-session `/watchman` command. |
| `watchman update` | Re-fetch the latest product (manifest, no git) + regenerate locals. Same as installing. |
| `watchman testmail` | Send one test email to prove your `.env` SMTP creds + `msmtp` deliver to `REPORT_EMAIL`. Loud on failure; changes nothing on the system. |
| `watchman uninstall` | Remove claude-watchman in tiers, each confirmed (default No): unlink the CLI, drop generated artifacts, then (only if you confirm) your data/secrets and the product files. Never removes packages; never deletes the directory wholesale. `--yes` to auto-confirm. |
| `watchman safe` | **Launcher** (spends nothing itself): opens a Claude session in the watchman directory under the default read-only profile, the easy way to start Claude in the same context. Observe only; it can apply nothing. |
| `watchman audit` | **Launcher**: opens a read-only session (default profile) already running `/watchman audit`. |
| `watchman report` | **Launcher**: opens a read-only session (default profile) already running `/watchman report`. |
| `watchman status` | **Launcher**: opens a read-only session (default profile) already running `/watchman status`, a plain-language report of the last monitoring run, written for a non-technical reader. |
| `watchman fix` | **Launcher** (spends nothing itself): opens a Claude session in the FIX profile and **auto-runs the fixer for you**. You don't type anything, you just confirm each change. |
| `watchman dev` | **Launcher** for maintainers: opens a session in the DEV profile (repo-write, `acceptEdits`) for editing the source. |
| `watchman schedule` | Install / remove / inspect the headless monitoring trigger (systemd timer or cron) for indefinite, unattended monitoring. `install [--every 6h] [--cron\|--systemd]`, `remove`, `status`. Install/remove are operator-confirmed system changes. |
| `watchman run` | The one token-spending shell verb: run ONE headless loop pass (what the schedule fires). Read-only like the loop; logs its token cost to the ledger. Normally fired by the schedule, not by hand. |

**In a Claude Code session**, AI features, visible token use (typed at the `claude` prompt, with the slash):

| Command | What it does |
|---------|--------------|
| `/watchman audit` | Observe + analyze, journal findings. No fixes. |
| `/watchman report` | Plain-language summary of the journal. |
| `/watchman status` | Plain-language report of the **last run**: when it ran, what happened, and any important issues explained for a non-technical reader. Read-only, on demand. |
| `/watchman loop` | One pass: observe → journal → delta → email if it matters. |
| `/watchman monitor "<focus>"` | Attended live watch of one concern you state in words. Run it under your own `/loop` while you work; what it can do is set by the session you launch it in: observe-only under `watchman safe`, watch-and-fix (per-change confirmation) under `watchman fix`. See below. |
| `/watchman fix` | Interactive remediation, bounded by each finding's risk tier. Don't type this one in a normal session; launch it from the shell with `watchman fix`, which opens the FIX profile and runs it for you (a plain session can't apply fixes; see below). |
| `/watchman inventory` | What's installed and how it serves. |
| `/watchman stats` | Privacy-respecting web traffic analytics from access logs. On demand, not the loop. |

`fix` is the only verb that ever changes the system, and it's always interactive. It
shows you the exact change, asks before applying anything risky, and never touches a
firewall rule or SSH config without showing the rule first. A session's permission mode
is fixed at startup, so `fix` can't run in your loop's read-only session. Run it from
the shell instead with `watchman fix`, which launches a fresh FIX-profile session and
runs the fixer automatically. You land in the remediation flow, not a blank prompt.

## Running it

Run claude-watchman as **root**: it reads every log and journal directly, so there's
no service user and no sudoers to manage. Auth is Claude Code's own login; there are no
API keys. The AI verbs run in-session on purpose, because Claude Code spends tokens on
every pass and you should be able to see that happening, never a silent background daemon.

**One-off checks.** Launch a read-only session as root with `watchman safe` (the same as
running `claude` here, under the default observe-only profile):

```bash
watchman safe
```

Then, inside the session, run `/watchman audit` and `/watchman report`. (Or skip straight
to one with `watchman audit` / `watchman report`, which open a session already running it.)

### Watch while you work

`monitor` is the inverse of the recurring loop below: a lightweight watch of a single thing
you state in plain words, meant to run *while you change something* so you see the effect
immediately. The classic case is tuning CORS or a Content-Security-Policy and watching the
web server's logs for rejections as you go. Each pass announces only what's new since the
last one and points at the adjustment to make.

You make it recurring with Claude Code's own `/loop`, in whichever session you launched. State
the focus in words and pick a short interval:

```
/loop 1m /watchman monitor "watch the apache error log for CORS preflight 403s"
```

**The session you launch it in decides what it can do: same command, two capabilities.**
monitor never inspects the permission mode; it always observes, announces, and (when it spots
a fixable issue) stages the exact change and tries to apply it. The profile you started the
session under transparently allows or denies that apply:

| | `watchman safe` (read-only) | `watchman fix` (remediation) |
|---|---|---|
| Watch the logs, announce what's new | yes | yes |
| Apply a staged fix | auto-denied ("relaunch in `watchman fix`") | prompts you per change (that prompt is the confirmation) |
| CORS change | flagged only | exact diff → one-click confirm → applied → next tick verifies |
| CSP policy | flagged only | drafted and handed back, never auto-applied |
| Journal / record | nothing (ephemeral) | only when a change is actually applied |

Launched under `watchman safe`, monitor is a pure watcher: it tells you a CORS preflight got
a 403 and what origin it was, and stops there. Launched under `watchman fix`, the same watch
becomes a tight loop: the moment a 403 lands it stages the precise `Access-Control-Allow-Origin`
change, you confirm with one keystroke that the origin is legitimate, it applies, and the next
tick shows the rejections stopped. It never applies a CORS or CSP change without that
per-change confirmation, because deciding whether an origin is trustworthy is the one judgment it
always leaves to you. Stop the loop (or close the session) and the watch ends.

### Recurring monitoring

There are two ways to run watchman on a cadence. Both run the same read-only pass and can
apply no fixes; they differ in what fires the pass and how you see the token cost.

**Method 1, the visible tmux loop (recommended default).** Claude Code's built-in `/loop`
re-runs the pass on an interval inside a tmux session, so it persists across logout but
stays attachable, so you always see what it's doing and what it spends on a live meter. Start
a persistent session:

```bash
tmux new -s watchman
```

Inside it, launch Claude as root (`claude`, run `/login` once), then start the loop:

```
/loop 6h /watchman loop
```

Press `Ctrl-b` then `d` to detach; re-attach any time with `tmux attach -t watchman`. One catch: **a `/loop` expires after about 7 days**, so you re-launch it roughly weekly.

**Method 2, the headless schedule (for indefinite, unattended monitoring).** When a host
must be watched without anyone re-launching a `/loop`, install an OS trigger that fires one
headless pass on an interval and outlives any session. It uses a systemd timer where systemd
is present, else cron. Install it (default interval 6h; it asks you to confirm the system
change first):

```bash
watchman schedule install --every 6h
```

Check the trigger and what the headless passes have spent:

```bash
watchman schedule status
```

Remove it when you're done (also confirmed):

```bash
watchman schedule remove
```

Because a scheduled trigger has no session to show a live token meter, each headless pass
records its tokens and cost to `journal/run-ledger.tsv`. `watchman schedule status` prints
that ledger, and the email report folds in the running total, so token use stays visible
after the fact. The trigger calls `watchman run`, the headless single-pass verb; you can run
it by hand once to test it:

```bash
watchman run
```

For this to work headlessly, root must have logged into Claude once (`claude`, then
`/login`) so `watchman run` can authenticate with no prompt.

**Fixing what it finds.** Don't run `/watchman fix` in the loop or a plain session; it
can't apply anything there (that's the seatbelt). Instead, from your shell run:

```bash
watchman fix
```

That opens a fresh Claude session in the FIX profile and **runs the fixer for you**: you
don't have to type the command, you just review and confirm each change. Safe toggles are
pre-approved; anything riskier prompts per finding, and the destructive deny base always
holds.

**It won't take down a busy server, and it knows its own footprint.** The heavy reads
(integrity verification, full log scans, Lynis, journald walks) run at a priority set by
its **role**, and are **skipped when the box is under real I/O pressure**, measured by
the kernel's `/proc/pressure/io` (PSI) where available rather than a bare load average.
When it defers, the loop records a "system busy" deferral and retries next pass. It also
**measures what it itself costs** per check (time, and I/O where GNU `time` is present)
and flags a check that gets expensive. Set the **role** in `config/watchman.conf`:
`WATCHMAN_PRIORITY=guest` (yield to everything, the default), `peer`, or `priority` (the
last for a **dedicated monitoring box where claude-watchman is the critical workload**,
which should keep running rather than defer). Thresholds (`WATCHMAN_IO_GUARD_PSI`,
`WATCHMAN_CHECK_TIME_BUDGET`, …) are tunable. And the loop reads logs **incrementally**
(only the new lines since the last pass), so its read stays proportional to recent
traffic, not the size of your logs (`/watchman stats` still reads the full set for an
authoritative report).

## Safety: two seatbelts and a backstop

The loop is observe-and-report only. Two independent layers keep it that way, with a
deny base beneath them:

1. **Risk tiers.** The fixer never auto-applies a `review` or `manual` finding. It shows
   the exact change and confirms per-finding.
2. **Loop allowlist.** The loop runs under a read-only observe + report profile in
   `dontAsk` mode, so it *cannot* invoke a mutating command: it auto-denies and fails
   loud. Remediation lives in a **separate** profile that only `watchman fix` selects.
3. **Deny base (backstop).** Even running as root, every profile embeds the same deny
   list (`rm`, `dd`, `mkfs`, `systemctl stop/disable`, anything touching sudoers, plus
   `Edit`/`Write` of shadow & sudoers), and an allow can never override a deny.

`bypassPermissions` is never used. Remediation only ever happens when **you** run
`watchman fix`, which launches a dedicated session in `"default"` mode: safe toggles are
pre-approved, every other fix prompts per finding (that prompt *is* the confirmation),
and the deny base above still holds. Maintainers get a third profile via `watchman dev`
(repo-write, `acceptEdits`) so editing the source never means loosening the live policy.

## What it watches

| | Server | Workstation |
|---|--------|-------------|
| Looks for | Inbound attack surface: exposed ports, web headers, CORS, SSH hardening, probes, and request-rate spikes (DDoS/abuse) that propose a firewall block | What the machine talks *to*: new outbound connections vs. a baseline |
| Top concern | Public-facing exposure | **Log retention**: volatile journald loses the forensic trail on reboot |
| Both | Lynis hardening index over time, capacity (disk/inodes/memory), OOM/crash postmortem, package integrity, forensic-trail tampering (shell history / login records wiped), **security currency** (pending updates, known-CVE packages, threat-intel/signature freshness, and whether auto-update is even on), and the host's own **defensive tooling**: discovers what's installed (fail2ban, CrowdSec, rkhunter, auditd, ClamAV, AIDE...), checks each is actually effective, and flags a whole class of defense that's missing | |

## Web analytics, without the trackers

You can't run Google Analytics GDPR-cleanly, and most privacy-first tools still want
JavaScript and a third-party service. But your web server already writes an access log
for every request (kept for security), and that log holds everything a traffic report
needs. `/watchman stats` reads it and prints:

- **page views** and **unique visitors** (deduplicated, so one person reloading doesn't
  skew the numbers), **top pages by unique visitor**, **referrers**, **status-code mix**,
  **bots-vs-humans**, and a **daily trend**.

Privacy is the point: the client IP is used **only in memory** to correlate a visitor's
requests, then discarded, never stored or shown. The
report is pure anonymous aggregates, computed entirely on your own box, with nothing
client-side to install and **nothing leaving the host**. `/watchman stats` reads current
and rotated logs (including `.gz`), and breaks down per site when you serve several.

Run it on demand; it is deliberately **not** part of the monitoring loop:

```
/watchman stats
```

## Platform support

Skills stay platform-blind; one resolver knows the differences.

| | Debian / Ubuntu | RHEL family | Arch | macOS | Windows |
|---|---|---|---|---|---|
| Packages | apt / dpkg | dnf / rpm | pacman | Homebrew | winget / Windows Update |
| Firewall | ufw | firewalld | nftables / ufw | pf | Defender Firewall |
| MAC / protection | AppArmor | SELinux | (none by default) | SIP | Defender + BitLocker |
| Integrity | debsums | rpm -V | pacman -Qkk | codesign | sfc / DISM |
| Logs | journald / `/var/log` | journald / `/var/log` | journald | Unified Log | Event Log (Get-WinEvent) |
| Cadence trigger | systemd / cron | systemd / cron | systemd / cron | launchd / cron | Task Scheduler |

On Windows the implementation is a native PowerShell port (`lib/*.ps1`, `bin/watchman.ps1`,
`install.ps1`) that runs elevated; the bash port (`lib/*.sh`) drives Linux and macOS. Both share
the same journal schema, risk tiers, Prime Directive, and read-only-loop seatbelt.

## Updating

**Updating is the same command as installing.** Re-run it from your watchman directory,
or use the verb:

```bash
watchman update
```

Both re-fetch the latest product from the manifest into your directory, then regenerate
the local artifacts (the permission allowlist and the in-session `/watchman` command) and
run any additive journal migration. It is **safe by construction**: the manifest lists
only the portable product, so a re-fetch overwrites code files and **never touches your
machine-specific state** (`.env`, `config/watchman.conf`, and `journal/findings.db` aren't
in the manifest). The fetch is atomic (everything downloads to a temp dir and moves into
place only if all files succeed), so a dropped connection can't leave you half-updated. A
lossy schema migration would stop and ask (the Prime Directive). No `git` is involved, so
none of the clone/pull/divergence failure modes apply.

Maintainers: after adding or removing a product file, run `watchman update --sync` to
regenerate `manifest.txt` from the tracked product, then `watchman update --check` (in the
git repo, after `git add`) before committing. The check asserts the update story still
holds: every machine artifact is gitignored and untracked, **`manifest.txt` lists exactly
the tracked product** (so a new skill can't silently fail to ship), every skill carries the
Prime Directive, every observe/analyze skill is wired into the `/watchman` orchestration,
and the journal schema version is in sync.

## Uninstalling

To remove claude-watchman, run the verb from your watchman directory:

```bash
watchman uninstall
```

It's the destructive inverse of installing, so it follows the same rule the rest of the
tool does: it **stops and asks before each tier**, defaulting to No. First it unlinks the
`/usr/local/bin/watchman` CLI (only if that symlink points at this install), then offers
to drop the regenerable artifacts (`.claude/`, preflight scratch). Only if you explicitly
confirm does it delete your **data and secrets** (`.env`, `config/watchman.conf`, the
`journal/findings.db` history) or the **product files**. It **never removes packages**
(sqlite3, jq, msmtp, lynis, which other software may use; it just names them) and **never
deletes the install directory wholesale**, because claude-watchman can be a guest inside a host
repo, so it removes only the files it owns and hands the final `rm -rf` back to you. Pass
`--yes` to auto-confirm every tier for a scripted teardown.

## What gets committed

Portable product only: `skills/`, `commands/`, `lib/`, `bin/watchman`,
`journal/schema.sql`, `install.sh`, `manifest.txt`, the `*.example` templates,
`.gitignore`, and this README. Anything machine-specific or secret (`.env`,
`config/watchman.conf`, `journal/findings.db`, `.claude/`, `CLAUDE.md`) is gitignored and
never leaves the host.

## License

MIT
