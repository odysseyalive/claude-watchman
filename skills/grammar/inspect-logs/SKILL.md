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
   - inbound: scan EVERY directory returned by `$(webserver_log_paths)` — this is
     config-derived (parsed from each present server's config), so it covers custom
     `access_log`/`CustomLog` targets, per-vhost logs, and niche servers, NOT just
     `/var/log/{nginx,apache2,httpd}` — plus `$(log_path_auth)` (or journald via
     `journalctl -u sshd`) for repeated 4xx/401/auth-failure bursts;
   - outbound: `ss -tunp` current connections; compare remote addresses against
     `journal/network-baseline.txt` from `baseline-network`.
4. **Request-rate spikes (DDoS / abuse) — server profile.** If
   `profile_runs_check request_rate_spike`: `source lib/webstats.sh` and run
   `webstats_rate_offenders` (threshold `$WATCHMAN_RATE_PER_MIN`, default 300 — the
   peak requests-in-one-minute from a single source). This reuses the web-stats log
   parser but — unlike the anonymized `/watchman stats` analytics — **keeps the real
   offending IP**, because you cannot firewall-block a hash and this is the security
   path (defending the system, a different legal basis). For each offender, journal:
   `category=security`, `severity=$(profile_severity request_rate_spike)`,
   `risk_tier=review`, `check_id=request_rate_spike`, `target=<ip>` (per-IP, so the
   fingerprint is stable and a returning flooder regresses loudly); detail = the
   peak/min, total, and UA sample; remediation = `firewall_deny <ip>/32` — shown and
   confirmed per the risk tiers. Bots/crawlers may appear here; the operator decides
   (it is `review`, never auto-applied). CrowdSec, when present, is the real-time
   enforcement layer; this is the log-cadence detector that proposes the rule.
5. **Journal findings.** Inbound probe clusters → `category=security`; new outbound
   destinations → `category=security`, severity per `profile_severity outbound_new_connections`.
   `check_id` stable per pattern/destination so re-runs update in place.
6. **Never block or ban.** Enforcement (firewall/ban) is the operator-run fixer's
   job under the risk tiers — this skill only observes and records. The rate-spike
   finding PROPOSES the exact `firewall_deny` rule; it never applies it.
<!-- /origin -->

## Grounding

- `lib/distro.sh` — `webserver_log_paths` / `webserver_config_roots` / `webserver_detect`
  (config-derived web-log discovery — scans `/etc` config roots and parses log directives),
  `log_path_auth`.
- `lib/webstats.sh` — `webstats_rate_offenders` (the security-path rate detector; keeps the
  real IP for the firewall proposal — distinct from the anonymized `/watchman stats` report).
- `lib/profile.sh` — `profile_log_direction`, `profile_severity` (`request_rate_spike`).
- `lib/journal.sh` — `journal_upsert`.
- `skills/rhetoric/fix-redflag` — applies the proposed `firewall_deny` (review-tier, confirmed).
- `baseline-network` — produces `journal/network-baseline.txt`.
