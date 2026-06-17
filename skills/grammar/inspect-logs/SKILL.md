---
name: inspect-logs
description: "OBSERVE: on a server, hunt inbound attack patterns; on a workstation, watch outbound connections. Queries CrowdSec where present, degrades gracefully when not."
lane: coding
allowed-tools: Read, Glob, Grep, Bash
---

# inspect-logs (Grammar / Observe)

The same skill points two directions, chosen by the profile resolver:
- **server** → inbound attack patterns in the web-server/auth logs;
- **workstation** → outbound connections (what the machine is talking *to*).

Prefers **CrowdSec** (`cscli`) over fragile log regex, and uses its **alert-only**
mode for visibility without enforcement. Degrades gracefully when CrowdSec is
absent. Read-only.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## When to use

Every `/watchman audit` / `/watchman loop`. On a workstation it pairs with
`baseline-network`: it flags outbound connections to destinations not in the baseline.

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** `source lib/journal.sh lib/distro.sh lib/profile.sh`; `journal_init`;
   `dir="$(profile_log_direction)"` → `inbound` or `outbound`.
2. **CrowdSec path (preferred).** If `cscli` is available:
   `sudo cscli alerts list -o json` and `sudo cscli decisions list -o json`
   (alert-only — never auto-ban from here, especially on a workstation). Respect the
   family collections (`crowdsecurity/{nginx,apache2,sshd,linux}`).
3. **Degrade gracefully.** If `cscli` is missing, journal one `config`/`low`
   finding "CrowdSec not configured — log analysis degraded" with a remediation to
   install it, then fall back:
   - inbound: scan `$(log_path_webserver)` and `$(log_path_auth)` (or journald via
     `journalctl -u sshd`) for repeated 4xx/401/auth-failure bursts;
   - outbound: `ss -tunp` current connections; compare remote addresses against
     `journal/network-baseline.txt` from `baseline-network`.
4. **Journal findings.** Inbound probe clusters → `category=security`; new outbound
   destinations → `category=security`, severity per `profile_severity outbound_new_connections`.
   `check_id` stable per pattern/destination so re-runs update in place.
5. **Never block or ban.** Enforcement (firewall/ban) is the operator-run fixer's
   job under the risk tiers — this skill only observes and records.
<!-- /origin -->

## Grounding

- `lib/distro.sh` — `log_path_webserver`, `log_path_auth`.
- `lib/profile.sh` — `profile_log_direction`, `profile_severity`.
- `lib/journal.sh` — `journal_upsert`.
- `baseline-network` — produces `journal/network-baseline.txt`.
