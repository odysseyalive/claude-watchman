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
# Usage (run as root, or via sudo):
#   Local checkout:   bash install.sh [--profile server|workstation] [--yes]
#   Remote one-liner: bash -c "$(curl -fsSL https://raw.githubusercontent.com/odysseyalive/claude-watchman/main/install.sh)"
#                     (use the bash -c "$(...)" form, NOT `curl | bash`, so the
#                      interactive prompts keep the terminal as stdin.)
#   Overridable:      WATCHMAN_REPO=<git url> WATCHMAN_REF=<branch> WATCHMAN_DIR=<dest> ...

set -euo pipefail

WATCHMAN_REPO="${WATCHMAN_REPO:-https://github.com/odysseyalive/claude-watchman}"
WATCHMAN_REF="${WATCHMAN_REF:-main}"

# Resolve our own location. Empty when piped/curled (no script file on disk).
_self="${BASH_SOURCE[0]:-}"
if [[ -n "$_self" && -f "$_self" ]]; then
    ROOT="$(cd "$(dirname "$_self")" && pwd)"
else
    ROOT="$PWD"
fi

# --- Remote bootstrap -------------------------------------------------------
# When this script runs DETACHED from the repo (its sibling lib/ is absent — the
# curl one-liner case), fetch the project, then re-exec the real installer from
# the fetched copy. A normal checkout has lib/ present and skips straight past this.
if [[ ! -f "$ROOT/lib/distro.sh" ]]; then
    dest="${WATCHMAN_DIR:-$PWD/claude-watchman}"
    echo "==> claude-watchman remote install → $dest" >&2
    if [[ -f "$dest/lib/distro.sh" ]]; then
        echo "    using existing copy at $dest" >&2
    elif command -v git >/dev/null 2>&1; then
        git clone --depth 1 --branch "$WATCHMAN_REF" "$WATCHMAN_REPO" "$dest" \
            || { echo "install: git clone failed from $WATCHMAN_REPO ($WATCHMAN_REF)" >&2; exit 1; }
    elif command -v curl >/dev/null 2>&1; then
        mkdir -p "$dest"
        # GitHub tarball nests under <repo>-<ref>/ — strip that top component.
        curl -fsSL "$WATCHMAN_REPO/archive/refs/heads/$WATCHMAN_REF.tar.gz" \
            | tar xz -C "$dest" --strip-components=1 \
            || { echo "install: tarball fetch failed from $WATCHMAN_REPO ($WATCHMAN_REF)" >&2; exit 1; }
    else
        echo "install: need git or curl to fetch claude-watchman" >&2; exit 1
    fi
    echo "==> running installer from $dest" >&2
    cd "$dest" || { echo "install: cannot enter $dest" >&2; exit 1; }
    exec bash install.sh "$@"
fi

export WATCHMAN_ROOT="$ROOT"
# shellcheck source=lib/distro.sh
source "$ROOT/lib/distro.sh"

ASSUME_YES=no
PROFILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y) ASSUME_YES=yes ;;
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
CLAUDE.md
.claude/
.env*
!.env.example
config/watchman.conf
journal/findings.db
journal/findings.db-wal
journal/findings.db-shm
journal/network-baseline.txt
journal/.write.lock
EOF
fi

# journal — initialize via the single gate (additive, non-destructive).
say "Initializing journal"
# shellcheck source=lib/journal.sh
WATCHMAN_PROFILE="$PROFILE" WATCHMAN_FAMILY="$FAMILY" source "$ROOT/lib/journal.sh"
journal_init || die "journal init failed"

# --- 5. Preflight: generate the Claude permission allowlist ----------------
say "Running preflight (generating .claude/settings.local.json)"
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
  1. VERIFY PLUMBING FIRST (no Claude needed):
         watchman selfcheck
  2. Fill in SMTP creds in  $ROOT/.env   (leave SMTP_PASS blank to disable mail)
  3. First audit (this validates the live claude->skill path):
         watchman audit && watchman report

Recurring monitoring — run the loop in a tmux session you can re-attach to, so you
always SEE what it does and what tokens it spends (no silent background daemon):

     tmux new -s watchman      # start a persistent session
     claude                    # launch Claude Code as root (log in once with /login)
     /loop 30m watchman loop   # start the recurring pass inside that session
     # Ctrl-b then d           # detach — the loop keeps running, visible on re-attach
     tmux attach -t watchman   # re-attach any time to watch it / read token use

Auth is Claude Code's own login (no API keys). 'watchman fix' is always interactive —
run it yourself when you want to remediate.

Safety: the loop observes and reports only. It can never apply a review/manual fix —
the dontAsk allowlist forbids mutating actions and the deny base blocks destructive
commands even as root. Remediation happens only when YOU run 'watchman fix'.
EOF
