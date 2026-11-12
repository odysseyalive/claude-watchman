---
name: inspect-interworx
description: "OBSERVE (InterWorx/NodeWorx only): read the InterWorx control plane read-only — panel version EOL and advisories, EOL PHP pools, PHP-FPM socket drift (503s), daemontools/panel service health, plaintext panel login on 2080, CSF/APF test mode, panel brute-force wiring, failed panel logins, qmail queue, hotfix and ScriptWorx auto-update, Softaculous upgrade cron, pre-release channel. Self-gates to a no-op off InterWorx boxes. Detect + propose; never edits panel config or applies a fix."
lane: coding
allowed-tools: Read, Glob, Grep, Bash
---

# inspect-interworx (Grammar / Observe)

An InterWorx server runs on the RHEL family (EL8/EL9), so the rest of claude-watchman already
covers its OS. This skill adds the **control plane**: one read-only engine (`iwscan`) reads the
panel's config files and service state and journals what it finds. It **self-gates**: on a
non-InterWorx box it does nothing. Read-only `security`/`config` findings at `review`/`manual` tier.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## Why everything here is review/manual, never safe-auto

InterWorx rebuilds its own configs: any PHP or SSL change rewrites `/etc/httpd/conf.d/vhost_*.conf`,
so a hand-edit is lost (and can cause the very socket drift this skill detects). The firewall is
CSF/LFD or APF, owned through NodeWorx; a raw nftables rule fights them and can sever access. So
claude-watchman **never edits panel config or touches the firewall**: it surfaces the finding and
routes the fix back through the operator and NodeWorx/SiteWorx. That is the Prime Directive in
InterWorx's vocabulary.

**The `nodeworx`/`siteworx` CLI is never used.** It also suspends and deletes accounts and changes
PHP versions, so it is kept out of every allowlist, and `iwscan` does not call it. Do not call it
from this skill either, and never run the panel's fixers (`varpermsfix.pex`, `cvspermsfix.pex`,
`fastpermsfix.sh`, `update.pex`).

## When to use

Every `/watchman audit` / `/watchman loop`, on a `server` profile. On a non-InterWorx host the
engine returns immediately, so it is safe to run everywhere.

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** Run every claude-watchman function through the dispatcher —
   `bash lib/wm <function> [args…]` — which sources the libs under bash internally; never
   `source lib/…` directly (dontAsk refuses a dot-source). Initialize with
   `bash lib/wm journal_init`. Determine the machine's family and profile by running
   `bash lib/wm watchman_family` and `bash lib/wm watchman_profile` and reading the printed
   values — you do NOT pass them to journal_upsert (it auto-resolves them; pass `"" ""`).
   **Gate:** if `bash lib/wm control_panel_detect` is not `interworx`, journal nothing and
   stop — this is not an InterWorx box. No step here is a heavy read, so there is no
   io-courtesy deferral.
2. **Scan.** Run `bash lib/wm iwscan`. Read-only — it reads panel/PHP/firewall config files,
   runs `svstat`, `qmail-qstat`, `ss -ltn` and `systemctl is-active`, and nothing else. It emits
   one TSV finding-candidate per signal:
   `category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation`.
   No output = the control plane looks healthy.
3. **Journal each record** through `lib/journal.sh` exactly as emitted (pass `"" ""` for
   family/profile — journal_upsert auto-resolves them):
   `bash lib/wm journal_upsert "" "" <category> <severity> <risk_tier> <check_id> <target> <title> <detail> <remediation>`.
   **Use `target` exactly as emitted; never invent or rewrite it.** The engine pins it to a
   stable, machine-derived value: `interworx`, a PHP branch token (`php74`), a vhost file
   basename (`vhost_<site>.conf`), a daemontools service name with any `-<ip>` suffix stripped
   (`/service/tinydns-<ip>` → `tinydns`), a systemd unit name, or a fixed subject
   (`nodeworx-http`, `csf`, `csf-interworx`, `apf`, `qmail-queue`, `iworx-autohotfix`,
   `iworx-channel`). That keeps the fingerprint stable so a regression surfaces loudly.
4. **Tiers — never apply.** Every InterWorx finding is `review` or `manual`. NEVER edit a vhost,
   pool, `csf.conf`/`conf.apf` or `iworx.ini`, touch the firewall, restart a service, suspend an
   account, clear the qmail queue, or run an update here — propose the NodeWorx/SiteWorx action,
   the operator decides.
5. **Summarize.** Lead with the highest-severity finding (a vulnerable panel version, the panel
   login on plaintext HTTP, a firewall in test mode, a mail-queue spike, a 503-causing socket
   drift) and the one-line panel action; if clean, say the control plane looks healthy.
<!-- /origin -->

## InterWorx gotchas (read before reasoning about this box)

- **`iworx.ini` is secret.** `/usr/local/interworx/iworx.ini` holds the panel database
  credentials (`dsn=`, `rootdsn=`). Never `cat`, `Read` or quote it; `iwscan` reads single keys
  internally and emits only normalized tokens. The panel's own log dir
  (`/usr/local/interworx/var/log`: `api.log`, `login.log`, `iworx.log`) is likewise not granted.
  `/home/interworx` is a symlink to `/usr/local/interworx`; use the real path.
- **Site access logs are `transfer*.log`, not `access_log`**: per site under
  `/home/<user>/var/<domain>/logs/` (`transfer.log`, `transfer-ssl.log`, `error.log`,
  `error-ssl.log`, plus dated and zipped rotations).
- **Mail and DNS run under daemontools, not systemd.** qmail (`/service/smtp`, `/service/send`)
  and djbdns (`tinydns`, `dnscache`, `axfrdns`, often as `/service/<svc>-<ip>`) do not appear in
  `systemctl`. Their multilog logs (`/var/log/smtp`, `/var/log/send`, `/service/<svc>/log/main`)
  use **TAI64N timestamps** and must be piped through `tai64nlocal` to be read. A plain `down`
  in `svstat` can be deliberate (a `./down` file, e.g. pop3 when Dovecot serves 110/995); only
  `down …, normally up` is a fault.
- **Failed panel logins live in `login_failures.log`, not `login.log`.** `login.log` records
  successful sessions only, and `iworx.log` logs a failed and a successful login identically.
  The panel creates `/usr/local/interworx/var/log/login_failures.log` (mode 0600) on the first
  failure, one line per failure: `YYYY-MM-DD HH:MM:SS <NW|SW> <ip> <login>`. When CSF's
  InterWorx integration is on, LFD watches that file. A missing file just means no failure yet;
  it is not a defect. `iwscan` counts the last 24h and reports source IPs only, never the login
  name (threshold `WATCHMAN_IW_LOGIN_FAIL_MAX`, default 20).
- **DNS is djbdns, not BIND.** There is no `named`/`named.conf`; do not report BIND as missing.
- **The panel has its own stack beside the system one.** `httpd-iworx` (the panel web server on
  2080/2443), `iworx-db-mariadb` (the panel database) and the panel-only PHP-FPM
  (`iworxphp82-php-fpm`) are distinct from the system `httpd`, `mariadb` and the site
  `phpNN-php-fpm` units. Don't conflate them.
- **Site PHP is remi PHP-FPM** (`phpNN-php-fpm.service`, pools in
  `/etc/opt/remi/phpNN/php-fpm.d/<user>.conf`, sockets `/var/run/<user>-remi-safe-phpNN.sock`).
- **Configs are rebuilt by the panel.** Never hand-edit a vhost or pool; route every fix
  through NodeWorx/SiteWorx.
- **Two app installers, often only one in use.** ScriptWorx is the panel's built-in
  installer (`iworx.ini [scriptworx]`, installs under `/usr/local/interworx/var/scriptworx/`);
  it is frequently disabled (`status="0"`), and then its `autoupdate` setting means nothing.
  Softaculous (`/usr/local/softaculous`, per-user installs in
  `~/.softaculous/installations.php`) upgrades apps that have auto-upgrade enabled from its
  daily `cron.php` job in `/etc/cron.d/softaculous*` (sometimes named `softaculous2`). Many
  sites are installed by neither; don't assume an installer manages a site.

## Not yet covered (held back, pending verification)

- **`iworx.ini` `[update] autoiworx` / `autoos`** and **`[scriptworx] updatecheck`**: value
  semantics unverified. Flagged only: `[update] autohotfix` explicitly off, and
  `[scriptworx] autoupdate` explicitly off while ScriptWorx is explicitly enabled and manages
  installs.
- **Per-install Softaculous auto-upgrade flags** in `installations.php`: the field name is
  unconfirmed, so only the server-wide cron is checked (counts only; the file is never parsed).
- **WordPress core auto-update disabled in `wp-config.php`** (`AUTOMATIC_UPDATER_DISABLED`,
  `WP_AUTO_UPDATE_CORE`): deliberately not read, because `wp-config.php` holds database
  credentials. Operator decision (2026-11-11): do not add.
- **`iworx-filelist.txt` integrity verification** (the RPM-style `%attr` manifest of panel files).
- **Other advisories by version** (IWX-CVE-2023-11439, IWX-CVE-2023-10947, and the
  IW7 < 7.13.54 side of IWX-CVE-2025-13057). Only IW6/IW7 end of life and IW8 < 8.0.30 are flagged.

## Grounding

All claude-watchman functions below are reached via `bash lib/wm <function>` (never a
direct `source`); the lib files are where they live.

- `lib/interworx.sh` — `iwscan` (the read-only control-plane engine; thresholds
  `WATCHMAN_QMAIL_QUEUE_MAX`, EOL PHP list `WATCHMAN_EOL_PHP_IW`, IW7 EOL date
  `WATCHMAN_IW7_EOL`; every path overridable via `IW_*` variables for fixture testing).
- `lib/distro.sh` — `control_panel_detect`, `interworx_version`, `interworx_log_paths`,
  `service_status` / `service_enabled`.
- `lib/profile.sh` — the interworx_* check severities (server profile).
- `lib/journal.sh` — `journal_upsert` (per-subject findings; regress over time).
- `skills/rhetoric/fix-redflag` — surfaces the proposed panel actions (review/manual).
- `manifest.json` — declared permissions: none beyond the framework base (`bash lib/wm`).
