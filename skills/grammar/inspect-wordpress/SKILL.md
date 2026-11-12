---
name: inspect-wordpress
description: "OBSERVE (any host whose Apache/nginx serves WordPress): DISCOVERY ONLY. Inventory each WordPress site read-only: core version, which wp-config update/edit constants are defined (names only), notable/high-risk and likely-custom plugins, payment surface (WooCommerce + gateways), Wordfence WAF mode, xmlrpc.php/readme.html exposure, PHP under uploads. One high finding: new or changed PHP under wp-content/uploads versus the baseline (webshell signal). Self-gates to a no-op with no WordPress docroot. Never fixes, never writes to a docroot."
lane: coding
allowed-tools: Read, Glob, Grep, Bash
---

# inspect-wordpress (Grammar / Observe)

WordPress is the usual way into a hosting server, so this skill inventories every WordPress site
the web server serves and watches the one place a webshell usually lands: PHP under
`wp-content/uploads`. One read-only engine (`wordpress_scan`) finds the sites through the
Apache/nginx docroot resolver and journals what it finds. It **self-gates**: with no WordPress
docroot it prints nothing.

> **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
> would delete or overwrite a file or directory, modify a database in any way, sever access
> (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
> language why it is destructive, and ASK for explicit per-action permission before proceeding.
> In the unattended loop there is no one to ask, so the action does not happen: record it and
> surface it instead. The only non-destructive database operation is routine create-or-update
> through lib/journal.sh. This rule has no exceptions and no mode that overrides it.

## Discovery only (operator decision, 2026-11-11)

This skill is **inventory, not remediation**. It never fixes, never auto-acts, never proposes a
change that it then makes, and **never writes to a docroot**: no delete, quarantine, chmod, edit,
wp-cli, plugin toggle or database query. Every finding is `info` / `manual` except one
(`wordpress_uploads_new_php`, `security` / `high` / `manual`, report only). The only file the
engine writes is claude-watchman's own `journal/wp-uploads-baseline.txt`, and only to create a
site's baseline the first time the site is seen.

**`wp-config.php` holds the site's database credentials.** Never `Read`, `cat`, `grep`, quote or
open it yourself; the deny base refuses `Read(//**/wp-config.php)` anyway. The engine tests it
only with `grep -q` for the presence of four constant names in non-comment `define()` lines
(`AUTOMATIC_UPDATER_DISABLED`, `WP_AUTO_UPDATE_CORE`, `DISALLOW_FILE_MODS`, `DISALLOW_FILE_EDIT`)
and emits present/absent. **Do not open any file under a docroot** (plugins, uploads, `.user.ini`,
logs) to "confirm" a finding: the engine output is the whole story for this skill.

**Sites are named by label, never by domain or user.** A site's `target` is `wp-` plus the first
10 hex of sha256 of its canonical docroot, e.g. `wp-3a9cb898a9`: stable run to run and
non-identifying. Do not try to work out which site a label is, and **never call
`wordpress_sites`**: it prints docroots (usernames, domains) for the operator and `lib/wm` refuses
it without `WM_APPLY=1`.

## When to use

Every `/watchman audit` / `/watchman loop`. Primarily a `server` concern, but it runs in either
profile: a workstation with no Apache/nginx docroot holding WordPress gets no output. The engine
self-gates, so it is safe to run everywhere.

<!-- origin: watchman | version: 1.0 | modifiable: true -->
## Workflow

1. **Preflight.** Run every claude-watchman function through the dispatcher —
   `bash lib/wm <function> [args…]` — which sources the libs under bash internally; never
   `source lib/…` directly (dontAsk refuses a dot-source). Initialize with
   `bash lib/wm journal_init`. You do NOT pass family/profile to journal_upsert (it
   auto-resolves them; pass `"" ""`).
2. **Scan.** Run `bash lib/wm wordpress_scan`. Read-only toward every site. It emits one TSV
   finding-candidate per signal:
   `category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation`.
   No output = no WordPress site on this host; journal nothing and stop.
   **I/O courtesy is inside the engine:** the uploads walk is the heavy read, so the engine
   checks `io_should_defer_heavy` itself; under pressure it emits a `capacity`/`info`/`safe`
   `diagnostic_deferred` (`target=inspect-wordpress`), still emits the cheap inventory, and skips
   the walk and the webshell comparison for this pass. The walk runs through `io_run` (role
   priority, `WATCHMAN_IO_TIMEOUT`), capped by `WATCHMAN_WP_UPLOADS_MAXDEPTH` (12) and
   `WATCHMAN_WP_UPLOADS_MAX_FILES` (5000). A walk that times out or hits the cap emits
   `wordpress_uploads_walk_incomplete` and is never used to create or compare a baseline.
3. **Journal each record** through `lib/journal.sh` exactly as emitted:
   `bash lib/wm journal_upsert "" "" <category> <severity> <risk_tier> <check_id> <target> <title> <detail> <remediation>`.
   **Use `target` exactly as emitted; never invent or rewrite it.** It is the site label
   (`wp-<10 hex>`) for every per-site row, and `inspect-wordpress` for `diagnostic_deferred`.
4. **Never apply.** There is nothing to apply. Do not delete, move, chmod or open the PHP files a
   high finding lists; do not re-baseline. Those are operator actions.
5. **Summarize.** Lead with any `wordpress_uploads_new_php` (site label, count, the listed relative
   paths) and say plainly it is a webshell signal for the operator to inspect by hand. Then the
   inventory per label: core version, constants and what they mean, notable plugins, payment
   surface, Wordfence mode, exposure.
<!-- /origin -->

## What each check_id means

| check_id | category / severity | what it reports |
|---|---|---|
| `wordpress_core_version` | config / info | core version from `$wp_version` in `wp-includes/version.php` (digits and dots only) |
| `wordpress_config_constants` | config / info | which of the four constants are defined (names only) and what that means: none defined → core minor/security auto-updates on by default AND the admin plugin/theme file editor is enabled |
| `wordpress_plugins` | config / info | plugin count; notable/high-risk slugs present (`WATCHMAN_WP_NOTABLE_PLUGINS`); likely-custom count (heuristic: no `readme.txt` with `Stable tag:`); slugs outside `^[a-z0-9._-]+$` are counted, never shown |
| `wordpress_payment_surface` | security / info | WooCommerce and known gateway plugins (`WATCHMAN_WP_GATEWAY_PLUGINS`): PCI-relevant |
| `wordpress_wordfence_waf` | security / info | extended protection (`auto_prepend_file` → `wordfence-waf.php` in docroot `.user.ini`/`php.ini`/`.htaccess`), plugin-level only, or absent |
| `wordpress_exposure` | security / info | `xmlrpc.php` (brute force, pingback) and `readme.html` (version disclosure) present |
| `wordpress_uploads_php` | security / info | PHP-executable files under uploads (`.php`, `.phtml`, `.php3`-`.php8`, `.phar`), newest mtime, whether `uploads/.htaccess` appears to block PHP (heuristic) |
| `wordpress_uploads_baseline` | security / info | baseline created for a newly seen site |
| `wordpress_uploads_walk_incomplete` | capacity / info | walk timed out or hit the file cap; comparison skipped |
| `wordpress_uploads_new_php` | **security / high / manual** | PHP under uploads that is new or whose size/sha256 changed versus the baseline: one finding per site, up to 5 relative paths (safe charset only) plus the total |

## The uploads baseline and the empty-guard exemption

`journal/wp-uploads-baseline.txt` (gitignored) holds, per label, a marker row and one row per PHP
file: a sha256 key of the relative path, size, sha256 of the content, and the path only when it is
plain characters. The first scan of a site creates its baseline (atomically, temp file + `mv`).
**After that a scan never changes it**, so a high finding stays until the operator reviews and
re-baselines.

**Empty `index.php` guards are exempt.** A file named exactly `index.php` that is 0 bytes executes
nothing; WP All Import/Export write a fresh one into a new 32-hex directory on every run and
Elementor keeps one in `template-kits/`. Such files never alert and are kept **out of** the
baseline, so if one later gains content it is caught as a new non-empty file. Still high: any new
non-empty PHP file, any new PHP file with another name (0-byte included), and any baselined file
whose size or hash changed.

**Operator-only functions**, run from the operator's own shell, **outside any Claude session** (both are refused by the read-only dispatcher, so the loop cannot reach them; in a `watchman fix` session they would only prompt, and `wordpress_sites` output would land in the transcript, so do not run or suggest running them in-session):

- Map labels to docroots: `WM_APPLY=1 bash lib/wm wordpress_sites`
- Re-baseline one site after review: `WM_APPLY=1 bash lib/wm wordpress_rebaseline wp-<10 hex>`

## Defensive strategy for a WordPress host (operator-requested)

- **Watch `wp-login.php` and `xmlrpc.php` POST rates** in the site access logs (InterWorx:
  `transfer*.log` under `/home/<user>/var/<domain>/logs/`). inspect-logs' request-rate detector
  counts requests per source IP in the web logs it finds; a per-endpoint POST count is not yet
  implemented.
- **Watch for new PHP under uploads**: this skill's one high finding.
- **Admin-user creation and plugin installs are database-side** (`wp_users`, `wp_usermeta`,
  `active_plugins`): out of scope without read-only database access, which claude-watchman does not
  have. A new plugin *directory* shows up here as a changed plugin count.
- **Track CVEs** for Elementor and its addons (Elementor Pro, The Plus Addons), Code Snippets
  (admin compromise = arbitrary PHP), and WP All Import/Export (file import/export features).
- **A payment surface means PCI care**: patch WooCommerce and gateway plugins promptly and keep the
  admin and file editor locked down.

## Not yet covered

- WordPress installed in a **subdirectory** of a docroot, or served by Caddy/lighttpd/LiteSpeed:
  only the docroot itself, from Apache `DocumentRoot` and nginx `root`, is checked.
- Constant **values** (by design) and multi-line `/* … */` comments around a `define()`: a
  `define` inside a block comment counts as present.
- Plugin and theme **auto-update** choices, users, roles, active-vs-installed plugins: all in the
  database.
- **Themes** (only plugins are inventoried) and plugin **versions** / CVE matching.
- Per-endpoint `wp-login.php` / `xmlrpc.php` POST-rate counting in access logs.
- **nginx** equivalents of an uploads PHP block (the `.htaccess` check is Apache-only).
- PHP outside uploads (core/plugin file integrity), world-writable files.
- Windows hosts (`lib/wordpress.ps1` is a no-op; there is no IIS docroot resolver).

## Grounding

All claude-watchman functions below are reached via `bash lib/wm <function>` (never a
direct `source`); the lib files are where they live.

- `lib/wordpress.sh` — `wordpress_scan` (the read-only engine; overrides `WATCHMAN_WP_BASELINE`,
  `WATCHMAN_WP_NOTABLE_PLUGINS`, `WATCHMAN_WP_GATEWAY_PLUGINS`, `WATCHMAN_WP_UPLOADS_MAXDEPTH`,
  `WATCHMAN_WP_UPLOADS_MAX_FILES`), plus the operator-only `wordpress_sites` and
  `wordpress_rebaseline`.
- `lib/distro.sh` — `webserver_docroots` (Apache `DocumentRoot`, nginx `root`; fixture override
  `WATCHMAN_WP_DOCROOTS`).
- `lib/io-courtesy.sh` — `io_should_defer_heavy`, `io_run`.
- `lib/profile.sh` — the wordpress_* severities.
- `lib/journal.sh` — `journal_upsert`.
- `manifest.json` — declared permissions: none beyond the framework base (`bash lib/wm`).
