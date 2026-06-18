#!/usr/bin/env bash
# install.sh — one-time operator setup for claude-watchman.
#
# claude-watchman installs and runs as ROOT (CLAUDE.md "How it runs"): there is
# no dedicated watchman user and no OS sudoers file — root invokes the read/
# observe commands directly. This installer detects family + profile, installs
# dependencies, writes config/journal/.gitignore/.env, runs the preflight to
# generate the Claude permission allowlist, and links the bin/watchman CLI.
# Re-runnable: it never clobbers .env or an existing config, appends to
# .gitignore idempotently, and regenerates its own artifacts.
#
# > PRIME DIRECTIVE. This installer performs privileged, system-mutating setup
# > (package install, symlink) — but it is OPERATOR-RUN with explicit intent, and
# > it asks before each privileged step unless --yes is given. It still does
# > nothing DESTRUCTIVE: it never deletes user data, never overwrites .env or an
# > existing watchman.conf, never stops/removes services.
#
# Install AND update are the same command — no git clone. The installer fetches
# every file in manifest.txt from raw.githubusercontent INTO THE CURRENT DIRECTORY,
# so the operator makes a directory and runs it from inside (re-running updates).
#
# Usage (run as root, or via sudo):
#   Install/update:   mkdir watchman && cd watchman
#                     bash -c "$(curl -fsSL https://raw.githubusercontent.com/odysseyalive/claude-watchman/main/install.sh)"
#                     (use the bash -c "$(...)" form, NOT `curl | bash`, so the
#                      interactive prompts keep the terminal as stdin.)
#   Dev checkout:     bash install.sh [--profile server|workstation] [--yes]   (uses local files, no fetch)
#   Force re-fetch:   bash install.sh --update                                 (what `watchman update` runs)
#   Overridable:      WATCHMAN_RAW=<raw base url> WATCHMAN_REF=<branch>

set -euo pipefail

WATCHMAN_REF="${WATCHMAN_REF:-main}"
# Raw base for the manifest-driven fetch — NO git clone. Files are pulled from
# raw.githubusercontent into the install directory. Overridable for forks/mirrors.
WATCHMAN_RAW="${WATCHMAN_RAW:-https://raw.githubusercontent.com/odysseyalive/claude-watchman/$WATCHMAN_REF}"

# Early flag scan: the fetch decision below must know --update before the full
# argument parse (which only runs once the libs are present).
FORCE_FETCH=no
for _a in "$@"; do [[ "$_a" == "--update" ]] && FORCE_FETCH=yes; done

# Resolve our own location. Empty when piped/curled (no script file on disk) —
# then the install directory is simply the current directory the operator chose.
_self="${BASH_SOURCE[0]:-}"
if [[ -n "$_self" && -f "$_self" ]]; then
    ROOT="$(cd "$(dirname "$_self")" && pwd)"
else
    ROOT="$PWD"
fi

# --- Manifest-driven fetch (NO git) -----------------------------------------
# Self-contained (it bootstraps the first install, before any lib/ exists on
# disk). Fetches every path in manifest.txt from WATCHMAN_RAW into $1, ATOMICALLY:
# everything lands in a temp dir first and is moved into place only after ALL
# files succeed, so a dropped connection can never leave a half-updated tree.
# `keep`-flagged files are fetched only if absent; `hook` files get +x.
_watchman_fetch() {
    local dest="$1" tmp line flag path
    command -v curl >/dev/null 2>&1 || { echo "install: curl is required to fetch claude-watchman." >&2; exit 1; }
    tmp="$(mktemp -d)" || { echo "install: mktemp failed." >&2; exit 1; }
    echo "==> fetching claude-watchman ($WATCHMAN_REF) → $dest" >&2
    curl -fsSL "$WATCHMAN_RAW/manifest.txt" -o "$tmp/manifest.txt" \
        || { echo "install: could not fetch manifest.txt from $WATCHMAN_RAW" >&2; rm -rf "$tmp"; exit 1; }
    # Phase 1 — fetch everything into the temp tree (nothing touches dest yet).
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|\#*) continue ;; esac
        flag=""; path="$line"
        case "$line" in "keep "*) flag=keep; path="${line#keep }" ;; "hook "*) flag=hook; path="${line#hook }" ;; esac
        if [ "$flag" = keep ] && [ -f "$dest/$path" ]; then continue; fi
        mkdir -p "$tmp/$(dirname "$path")"
        curl -fsSL "$WATCHMAN_RAW/$path" -o "$tmp/$path" \
            || { echo "install: fetch failed for $path" >&2; rm -rf "$tmp"; exit 1; }
    done < "$tmp/manifest.txt"
    # Phase 2 — move into place (only now), and keep the manifest on disk so
    # `watchman update --check` can verify it stays in lockstep with the product.
    cp "$tmp/manifest.txt" "$dest/manifest.txt"
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|\#*) continue ;; esac
        flag=""; path="$line"
        case "$line" in "keep "*) flag=keep; path="${line#keep }" ;; "hook "*) flag=hook; path="${line#hook }" ;; esac
        [ -f "$tmp/$path" ] || continue            # keep-skipped file
        mkdir -p "$dest/$(dirname "$path")"
        mv -f "$tmp/$path" "$dest/$path"
        [ "$flag" = hook ] && chmod +x "$dest/$path"
    done < "$tmp/manifest.txt"
    rm -rf "$tmp"
}

# Fetch when running detached (the curl one-liner, no lib/ yet) OR on --update
# (re-run from an installed dir to pull the latest). A plain re-run from a dev
# checkout (lib/ present, no --update) skips the fetch and uses local files.
if [[ ! -f "$ROOT/lib/distro.sh" || "$FORCE_FETCH" == yes ]]; then
    _watchman_fetch "$ROOT"
fi

export WATCHMAN_ROOT="$ROOT"
# shellcheck source=lib/distro.sh
source "$ROOT/lib/distro.sh"

ASSUME_YES=no
PROFILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)  ASSUME_YES=yes ;;
        --update)  ASSUME_YES=yes ;;   # update is non-interactive (handled above)
        --profile) PROFILE="$2"; shift ;;
        *) echo "install: unknown arg '$1'" >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

confirm() {
    [[ "$ASSUME_YES" == yes ]] && return 0
    # No terminal (piped install) → cannot ask, so do NOT assume yes for a
    # privileged step. Fail safe: skip it and tell the operator.
    [[ -t 0 ]] || { warn "non-interactive shell — skipping (answer 'no'): $1"; return 1; }
    local reply
    read -r -p "    $1 [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

# Evidence-based profile guess — read-only, deterministic, NO AI, NO network.
# Echoes "<guess>\t<reasons>". Never fails; missing tools just drop a signal.
# Positive score → server, tie/negative → workstation (the quieter, safer default).
_profile_guess() {
    local score=0; local -a reasons=()

    # Strong server signal: something listening on a NON-loopback address.
    # ss is in iproute2 (near-universal); judge by address:port only (no root needed).
    local pub
    pub="$(ss -H -tln 2>/dev/null | awk '{print $4}' \
            | grep -Ev '^127\.|^\[::1\]' \
            | grep -E ':(22|25|80|443|3306|5432)' | tr '\n' ' ' || true)"
    [[ -n "$pub" ]] && { score=$((score+2)); reasons+=("public listeners: ${pub% }"); }

    # A running web server → server-leaning.
    local svc
    for svc in nginx apache2 httpd caddy; do
        systemctl is-active --quiet "$svc" 2>/dev/null \
            && { score=$((score+2)); reasons+=("$svc running"); break; }
    done

    # Laptop battery → workstation-leaning (strong).
    compgen -G '/sys/class/power_supply/BAT*' >/dev/null 2>&1 \
        && { score=$((score-2)); reasons+=("battery present (laptop)"); }

    # Boots to a desktop → workstation-leaning.
    [[ "$(systemctl get-default 2>/dev/null)" == graphical.target ]] \
        && { score=$((score-1)); reasons+=("boots to graphical.target"); }

    # Chassis hint from systemd.
    case "$(hostnamectl chassis 2>/dev/null)" in
        server)                        score=$((score+1)); reasons+=("chassis=server") ;;
        laptop|desktop|tablet|handset) score=$((score-1)); reasons+=("chassis=laptop/desktop") ;;
    esac

    local guess=workstation
    (( score > 0 )) && guess=server
    local why="no strong signal"
    (( ${#reasons[@]} )) && why="$(IFS='; '; printf '%s' "${reasons[*]}")"
    printf '%s\t%s\n' "$guess" "$why"
}

# sudo wrapper: prefer real sudo; if already root, run directly.
SUDO=""
if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "Not root and sudo not found. Re-run as root."
    SUDO="sudo"
fi

# --- 1. Detect family + profile --------------------------------------------
FAMILY="$(watchman_family)"
[[ "$FAMILY" == unknown ]] && die "Unsupported distro (need Debian/Ubuntu, RHEL family, or Arch)."
if [[ -z "$PROFILE" ]]; then
    IFS=$'\t' read -r GUESS GUESS_WHY < <(_profile_guess)
    if [[ "$ASSUME_YES" == yes || ! -t 0 ]]; then
        PROFILE="$GUESS"      # evidence-based default (override with --profile or config)
        say "Profile auto-detected: $PROFILE — $GUESS_WHY (override with --profile)"
    else
        say "Profile — best guess: $GUESS"
        say "  signals: $GUESS_WHY"
        if [[ "$GUESS" == server ]]; then
            read -r -p "    Use [S]erver, or switch to [w]orkstation? [S/w] " p
            case "$p" in w|W) PROFILE=workstation ;; *) PROFILE=server ;; esac
        else
            read -r -p "    Use [W]orkstation, or switch to [s]erver? [W/s] " p
            case "$p" in s|S) PROFILE=server ;; *) PROFILE=workstation ;; esac
        fi
    fi
fi
say "Family: $FAMILY   Profile: $PROFILE"

# --- 2. Dependencies --------------------------------------------------------
# Wrap battle-tested tools; do not rebuild them. crowdsec is AUR-only on Arch, so
# we detect-and-warn rather than fail — inspect-logs degrades when cscli is absent.
say "Checking dependencies"
declare -a CORE_DEPS=(sqlite3 jq msmtp lynis)
# Map the binary name to the package name where they differ per family.
pkg_for() {
    case "$1:$FAMILY" in
        sqlite3:arch) echo sqlite ;;
        sqlite3:*)    echo sqlite3 ;;
        *)            echo "$1" ;;
    esac
}
MISSING=()
for bin in "${CORE_DEPS[@]}"; do
    command -v "$bin" >/dev/null 2>&1 || MISSING+=("$(pkg_for "$bin")")
done
if (( ${#MISSING[@]} )); then
    say "Will install: ${MISSING[*]}"
    if confirm "Install these packages now?"; then
        pkg_install "${MISSING[@]}" || warn "Some packages failed to install; check output above."
    else
        warn "Skipping package install — the tool will degrade for any missing dependency."
    fi
fi
# crowdsec (optional, enriches inspect-logs)
if ! command -v cscli >/dev/null 2>&1; then
    if [[ "$FAMILY" == arch ]]; then
        warn "crowdsec is not in the Arch official repos (AUR only). Install it yourself if you"
        warn "want enriched inbound/outbound analysis; inspect-logs will degrade gracefully without it."
    else
        warn "crowdsec/cscli not found. Install the 'crowdsec' package for richer log analysis;"
        warn "inspect-logs degrades gracefully without it."
    fi
fi

# --- 3. Run-as user ---------------------------------------------------------
# claude-watchman runs as root — no dedicated service user is created. root reads
# every log and journal directly, so the loop needs no sudoers grant. The
# config records this for transparency.
WATCHMAN_USER=root
if [[ $EUID -ne 0 ]]; then
    warn "claude-watchman is designed to run as root; you are installing as a normal user."
    warn "Privileged setup steps below use sudo, and you should run 'claude' as root (see the"
    warn "tmux instructions at the end) so the loop can read all logs."
fi

# --- 4. config / .env / .gitignore / journal -------------------------------
# config — write only if absent (never clobber operator edits).
if [[ -f "$ROOT/config/watchman.conf" ]]; then
    say "config/watchman.conf exists — leaving it untouched"
else
    say "Writing config/watchman.conf"
    sed -e "s/^WATCHMAN_PROFILE=.*/WATCHMAN_PROFILE=$PROFILE/" \
        -e "s/^WATCHMAN_FAMILY=.*/WATCHMAN_FAMILY=$FAMILY/" \
        -e "s/^WATCHMAN_USER=.*/WATCHMAN_USER=$WATCHMAN_USER/" \
        "$ROOT/config/watchman.conf.example" > "$ROOT/config/watchman.conf"
fi

# .env — copy template only if absent (never clobber secrets).
if [[ -f "$ROOT/.env" ]]; then
    say ".env exists — leaving it untouched"
else
    say "Creating .env from template (fill in SMTP creds to enable mail)"
    cp "$ROOT/.env.example" "$ROOT/.env"
    chmod 600 "$ROOT/.env"
fi

# .gitignore — append the canonical block idempotently (never clobber).
GI="$ROOT/.gitignore"
if [[ -f "$GI" ]] && grep -q 'claude-watchman — never commit these' "$GI"; then
    say ".gitignore already carries the claude-watchman block"
else
    say "Appending claude-watchman block to .gitignore"
    cat >> "$GI" <<'EOF'

# claude-watchman — never commit these
# (install.sh (re)generates this block; the canonical copy lives in CLAUDE.md.
#  Order matters: the .env.example negation must follow the .env* glob.)
CLAUDE.md
.claude/
.env*
!.env.example
config/watchman.conf
journal/findings.db
journal/findings.db-wal
journal/findings.db-shm
journal/network-baseline.txt
journal/log-offsets.txt
journal/.write.lock

# preflight staging + scratch
.watchman-sudoers.staged
.pf.allow
.pf.dirs
.pf.sudoers
.pf.fix.allow
.pf.fix.dirs
journal/findings.db.backup-*

# editor / OS cruft
*.swp
*~
.DS_Store
EOF
fi

# journal — initialize via the single gate (additive, non-destructive).
say "Initializing journal"
# shellcheck source=lib/journal.sh
WATCHMAN_PROFILE="$PROFILE" WATCHMAN_FAMILY="$FAMILY" source "$ROOT/lib/journal.sh"
journal_init || die "journal init failed"

# --- 5. Preflight: allowlist + in-session command skills -------------------
say "Running preflight (allowlist .claude/settings.local.json + /watchman command skill)"
WATCHMAN_PROFILE="$PROFILE" WATCHMAN_FAMILY="$FAMILY" \
    bash "$ROOT/lib/preflight.sh"

# --- 6. Link the CLI --------------------------------------------------------
LINK=/usr/local/bin/watchman
chmod +x "$ROOT/bin/watchman"
if [[ -L "$LINK" || ! -e "$LINK" ]]; then
    say "Linking $LINK -> $ROOT/bin/watchman"
    if ! $SUDO ln -sfn "$ROOT/bin/watchman" "$LINK" 2>/dev/null; then
        warn "Could not create $LINK (needs sudo). Add $ROOT/bin to PATH yourself,"
        warn "or run:  sudo ln -sfn $ROOT/bin/watchman $LINK"
    fi
else
    warn "$LINK exists and is not a symlink — leaving it. Add $ROOT/bin to PATH yourself."
fi

# --- Done -------------------------------------------------------------------
cat <<EOF

$(say "claude-watchman installed.")

Next steps (run everything as root):
  1. VERIFY PLUMBING FIRST (bash only, no Claude, no tokens):
         watchman selfcheck
  2. Fill in SMTP creds in  $ROOT/.env   (leave SMTP_PASS blank to disable mail)
  3. First audit + report — these are AI features, so run them INSIDE a Claude
     Code session where you can see the work and the token use:
         claude                # launch Claude Code as root (/login once if needed)
         /watchman audit       # observe + analyze, journal findings
         /watchman report      # plain-language summary

Recurring monitoring — keep the loop in a tmux session you can re-attach to, so you
always SEE what it does and what tokens it spends (no silent background daemon):

     tmux new -s watchman       # start a persistent session
     claude                     # launch Claude Code as root (/login once)
     /loop 6h /watchman loop   # start the recurring pass inside that session
     # Ctrl-b then d            # detach — the loop keeps running, visible on re-attach
     tmux attach -t watchman    # re-attach any time to watch it / read token use

Auth is Claude Code's own login (no API keys). '/watchman fix' is always interactive —
run it in a session when you want to remediate.

Safety: the loop observes and reports only. It can never apply a review/manual fix —
the dontAsk allowlist forbids mutating actions and the deny base blocks destructive
commands even as root. Remediation happens only when YOU run '/watchman fix'.
EOF
