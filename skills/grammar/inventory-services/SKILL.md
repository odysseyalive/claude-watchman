---
name: inventory-services
description: "OBSERVE: inventory what is installed and how it serves — web server, database, php-fpm — so other skills know what surface exists to check."
lane: coding
allowed-tools: Read, Glob, Grep, Bash
---

# inventory-services (Grammar / Observe)

Establishes *what is running*. A factual inventory of the service surface, so the
other skills (security headers, CORS, log inspection) know what exists to examine.
Read-only.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## When to use

Early in every `/watchman audit` / `/watchman inventory`, before the skills that
depend on knowing which web server or database is present.

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** `source lib/journal.sh lib/distro.sh lib/profile.sh`; `journal_init`;
   resolve `family`/`profile`.
2. **Web server.** Detect via `service_status` + `pkg_is_installed` for nginx,
   apache2/httpd. Record which is active and enabled.
3. **Database.** Detect mariadb/mysql, postgresql similarly.
4. **App runtime.** Detect php-fpm (and its version) and any obvious app server.
5. **Journal an inventory finding** per discovered service:
   `category=config`, `severity=info`, `risk_tier=safe`,
   `check_id=service_<name>`, `target=<unit>`, title/detail describing version and
   enabled/active state. These `info` rows are context, not alarms.
6. **Profile sanity-check (mismatch finding).** Compare the discovered surface against
   the active `profile`. The dangerous direction is a **`workstation` profile that is
   actually serving the public** — because the server-only checks (security headers,
   CORS, exposed-port review, SSH hardening, inbound-probe inspection) are then *silently
   skipped*, leaving real attack surface unaudited. Detect it: if `profile == workstation`
   AND any inventoried web server / database is **listening on a non-loopback address**
   (use the `net_connections` resolver — `ss -H -tln`; a loopback bind `127.*` / `[::1]`
   does NOT count, that is local-only dev), journal exactly ONE finding:
   `category=config`, `severity=medium`, `risk_tier=manual`,
   `check_id=profile_mismatch_public_service`, `target=` (leave empty — keeps the
   fingerprint stable across runs; the volatile service/port list goes in `detail`).
   - **title:** `Profile is 'workstation' but public-facing services are present`
   - **detail:** name the offending listeners (e.g. `nginx → 0.0.0.0:443`) and state
     plainly that the server-profile checks are not running, so that surface is unaudited.
   - **remediation:** `If this host is public-facing, switch to the server profile: re-run`
     `'bash install.sh --profile server' (or set WATCHMAN_PROFILE=server in`
     `config/watchman.conf) then 'watchman preflight'. If the exposure is intentional and`
     `you want workstation behaviour, mark this finding 'ignored'.`
   Do **not** flag the reverse (a `server` profile that merely looks quiet): extra checks
   finding nothing is harmless, and battery/desktop signals produce false alarms on real
   servers. Never change the profile yourself — `risk_tier=manual` means explain and hand
   back; the loop's allowlist cannot apply it regardless.
7. **Stay family-blind.** Never call `apt`/`pacman`/`dnf` directly — only the
   `pkg_*` and `service_*` resolvers. Never start, stop, or change a service.
<!-- /origin -->

## Grounding

- `lib/distro.sh` — `service_status`, `service_enabled`, `pkg_is_installed`.
- `lib/journal.sh` — `journal_upsert`.
- `net_connections` resolver (`ss -H -tln`) — listener addresses for the profile check.
- `lib/profile.sh` — `profile` (the active profile being sanity-checked).
- `manifest.json` — declared permissions.
