# claude-watchman

> **It only speaks up when something's wrong.** claude-watchman watches a Linux box,
> remembers what it sees, and emails you only when something actually changes. A quiet
> machine stays quiet. No dashboards to babysit, no alert fatigue.

> **PRIME DIRECTIVE — it never does anything destructive.** Every skill carries one
> rule, verbatim: nothing that deletes data, modifies a database, severs access, or
> stops a service happens without stopping to ask you first. The unattended loop has
> no one to ask — so it physically cannot reach a destructive step. [How that's enforced →](#safety--three-seatbelts)

claude-watchman is a set of Claude Code skills that run one loop: look at the machine,
write down what's wrong, help you fix it. It only reaches out when the picture changes.
It runs on Debian/Ubuntu, RHEL-family, and Arch, and adapts to whether the box is a
public **server** or a personal **workstation**.

It drives proven tools (Lynis, CrowdSec, journald, your distro's own integrity
verifier) and layers on a durable journal, plain-language explanations, and the
judgment to tell a new problem from old news.

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

**2. Run your first audit, in a session.** `audit` and `report` are AI features, so you
run them *inside* Claude Code — where you watch the work and the token meter. Launch a
session as root (run `/login` once if needed):

```bash
claude
```

Then, inside that session, run `/watchman audit` (observe + analyze, journal findings),
followed by `/watchman report` (a plain-language summary).

**3. Turn on recurring monitoring.** Keep the loop in a tmux session so it persists but
stays visible. Start a persistent session:

```bash
tmux new -s watchman
```

Inside it, launch Claude as root (`claude`, run `/login` once), then start the recurring
pass:

```
/loop 30m /watchman loop
```

Press `Ctrl-b` then `d` to detach — the loop keeps running. It observes, journals, and
emails you only when something crosses a threshold. Re-attach with
`tmux attach -t watchman` whenever you want to see what it's doing.

## Commands

claude-watchman splits its verbs on the token line. The ones that spend nothing are
shell commands; the AI features run inside a Claude Code session as `/watchman <verb>`,
so their token use is always in front of you.

**Shell CLI** — bash only, no Claude, no tokens:

| Command | What it does |
|---------|--------------|
| `watchman selfcheck` | Bash-only plumbing check. Run first on any new host. |
| `watchman preflight` | Regenerate the Claude allowlist + the in-session `/watchman` command. |
| `watchman update` | Re-fetch the latest product (manifest, no git) + regenerate locals. Same as installing. |

**In a Claude Code session** — AI features, visible token use:

| Command | What it does |
|---------|--------------|
| `/watchman audit` | Observe + analyze, journal findings. No fixes. |
| `/watchman report` | Plain-language summary of the journal. |
| `/watchman loop` | One pass: observe → journal → delta → email if it matters. |
| `/watchman fix` | Interactive remediation, bounded by each finding's risk tier. |
| `/watchman inventory` | What's installed and how it serves. |

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
/loop 30m /watchman loop
```

Press `Ctrl-b` then `d` to detach; re-attach any time with `tmux attach -t watchman`.

## Safety — two seatbelts and a backstop

The loop is observe-and-report only. Two independent layers keep it that way, with a
deny base beneath them:

1. **Risk tiers.** The fixer never auto-applies a `review` or `manual` finding. It shows
   the exact change and confirms per-finding.
2. **Claude allowlist.** Scoped to read-only observe + report under `dontAsk`, so the
   loop *cannot* invoke a mutating command — it auto-denies and fails loud.
3. **Deny base (backstop).** Even running as root, `settings.json` explicitly denies the
   destructive command patterns — `rm`, `dd`, `mkfs`, `systemctl stop/disable`, anything
   touching sudoers — and an allow can never override a deny.

`bypassPermissions` is never used. Remediation only ever happens when **you** run
`watchman fix`.

## What it watches

| | Server | Workstation |
|---|--------|-------------|
| Looks for | Inbound attack surface — exposed ports, web headers, CORS, SSH hardening, probes | What the machine talks *to* — new outbound connections vs. a baseline |
| Top concern | Public-facing exposure | **Log retention** — volatile journald loses the forensic trail on reboot |
| Both | Lynis hardening index over time, capacity (disk/inodes/memory), OOM/crash postmortem, package integrity | |

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
