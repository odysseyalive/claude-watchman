#!/usr/bin/env bash
# lib/schedule.sh — the OPTIONAL headless cadence: run one monitoring loop pass
# with no interactive session (for cron / systemd timer), and manage the recurring
# trigger that fires it.
#
# > **PRIME DIRECTIVE (outranks everything below).** Do nothing destructive. If any action
# > would delete or overwrite a file or directory, modify a database in any way, sever access
# > (firewall/SSH/auth), or stop/remove a service or package — STOP, WARN the operator in plain
# > language why it is destructive, and ASK for explicit per-action permission before proceeding.
# > In the unattended loop there is no one to ask, so the action does not happen: record it and
# > surface it instead. The only non-destructive database operation is routine create-or-update
# > through lib/journal.sh. This rule has no exceptions and no mode that overrides it.
#
# WHY THIS EXISTS. claude-watchman's PRIMARY cadence is Claude Code's built-in /loop
# inside a tmux session — visible, with a live token meter, re-attachable. But a
# /loop expires after ~7 days, so a host that must be watched indefinitely needs a
# persistent trigger that outlives any one session. This file is that SECOND method:
#   * `watchman run`             — performs ONE headless loop pass (claude -p).
#   * `watchman schedule install`— installs the recurring trigger (systemd timer
#                                  where available, else cron) that fires `run`.
#   * `watchman schedule remove` — tears the trigger back down.
#   * `watchman schedule status` — shows the trigger + the token/cost ledger.
#
# TOKEN VISIBILITY (the reason a headless scheduler was originally rejected) is
# preserved WITHOUT a live meter: every headless pass records its tokens + cost to
# journal/run-ledger.tsv from `claude -p --output-format json`, and send-report
# folds a summary of that ledger into the email — so the operator still sees, after
# the fact, exactly what each pass spent. `watchman schedule status` shows it too.
#
# SAFETY. The headless pass inherits the SAME read-only dontAsk loop profile as the
# tmux loop (auto-discovered from the repo's .claude/), so it can apply NOTHING —
# the seatbelt is unchanged. Installing/removing the trigger is a system change, so
# it is operator-confirmed (stop-warn-ask) and is NEVER reachable from the loop
# itself (lib/wm lists schedule_run/install/remove as mutators).

_SCHED_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCHMAN_ROOT="${WATCHMAN_ROOT:-$(cd "$_SCHED_LIB_DIR/.." && pwd)}"

SCHED_LEDGER="${SCHED_LEDGER:-$WATCHMAN_ROOT/journal/run-ledger.tsv}"
SCHED_RUNLOG="${SCHED_RUNLOG:-$WATCHMAN_ROOT/journal/run.log}"
SCHED_CRON_MARK="# claude-watchman loop"
SCHED_UNIT_MARK="# managed by claude-watchman"
SCHED_SYSTEMD_DIR="/etc/systemd/system"
SCHED_SERVICE="watchman-loop.service"
SCHED_TIMER="watchman-loop.timer"
SCHED_DEFAULT_INTERVAL="6h"

# --- the headless single pass (what the trigger fires) ----------------------
# Runs ONE `/watchman loop` pass headless under the auto-discovered read-only
# dontAsk loop profile, then records the pass's tokens + cost to the ledger so
# token use stays visible without a live meter. Returns claude's exit code.
schedule_run() {
    cd "$WATCHMAN_ROOT" || { echo "watchman run: cannot cd to $WATCHMAN_ROOT" >&2; return 1; }
    command -v claude >/dev/null 2>&1 || {
        echo "watchman run: the 'claude' CLI is not on PATH — install Claude Code, and make sure" >&2
        echo "              root has logged in once ('claude' then /login) so headless runs authenticate." >&2
        return 1; }

    mkdir -p "$WATCHMAN_ROOT/journal"
    local started out rc
    started="$(date -Is 2>/dev/null || date)"
    out="$(mktemp)"
    echo "[$started] watchman run: starting headless loop pass" >>"$SCHED_RUNLOG"

    # Headless single pass. Natural-language prompt on purpose: Claude Code DROPS a
    # startup positional prompt that begins with '/', so "Run /watchman loop" (no
    # leading slash) is what actually invokes the loop. No --permission-mode /
    # --settings override: claude auto-discovers the repo's .claude/ (the read-only
    # dontAsk loop profile) from the working directory, exactly like the tmux loop.
    rc=0
    claude -p "Run /watchman loop" --output-format json >"$out" 2>>"$SCHED_RUNLOG" || rc=$?

    if command -v jq >/dev/null 2>&1 && [[ -s "$out" ]]; then
        local cost intok outtok cachetok dur turns iserr
        cost=$(jq -r '.total_cost_usd // 0' "$out" 2>/dev/null || echo 0)
        intok=$(jq -r '.usage.input_tokens // 0' "$out" 2>/dev/null || echo 0)
        outtok=$(jq -r '.usage.output_tokens // 0' "$out" 2>/dev/null || echo 0)
        cachetok=$(jq -r '(.usage.cache_read_input_tokens // 0)' "$out" 2>/dev/null || echo 0)
        dur=$(jq -r '.duration_ms // 0' "$out" 2>/dev/null || echo 0)
        turns=$(jq -r '.num_turns // 0' "$out" 2>/dev/null || echo 0)
        iserr=$(jq -r '.is_error // false' "$out" 2>/dev/null || echo false)
        # Append-only TSV: started, cost_usd, in_tok, out_tok, cache_tok, duration_ms, turns, is_error.
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$started" "$cost" "$intok" "$outtok" "$cachetok" "$dur" "$turns" "$iserr" >>"$SCHED_LEDGER"
        echo "watchman run: pass complete — cost \$$cost, tokens ${intok}/${outtok} in/out, ${turns} turns (rc=$rc)" >&2
        echo "[$started] watchman run: cost \$$cost tokens ${intok}/${outtok} turns ${turns} rc=$rc" >>"$SCHED_RUNLOG"
    else
        echo "watchman run: pass complete (rc=$rc; cost not recorded — jq missing or no JSON output)." >&2
        echo "[$started] watchman run: cost not recorded (rc=$rc)" >>"$SCHED_RUNLOG"
    fi
    rm -f "$out"
    return "$rc"
}

# --- read-only ledger summary (folded into the email by send-report) --------
# Pure read: never mutates. Reachable through the dispatcher (bash lib/wm
# schedule_ledger_summary) so the report path can show what the scheduler spent.
schedule_ledger_summary() {
    if [[ ! -s "$SCHED_LEDGER" ]]; then
        echo "(no scheduled/headless runs recorded yet — token cost is shown live in the tmux /loop)"
        return 0
    fi
    awk -F'\t' '
        { n++; cost+=$2; intok+=$3; outtok+=$4; if ($8=="true" || $8=="1") err++; last=$1 }
        END {
            printf "Scheduled (headless) runs recorded: %d\n", n;
            printf "  total cost: $%.4f   tokens in/out: %d/%d   runs with errors: %d\n", cost, intok, outtok, err+0;
            printf "  most recent run: %s\n", last;
        }' "$SCHED_LEDGER"
}

# --- schedule management ----------------------------------------------------
# Default trigger mechanism: systemd timer where systemd is the live init, else cron.
_sched_default_mech() {
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        echo systemd
    else
        echo cron
    fi
}

# Confirm prompt, default No — reads the operator's TTY even when stdin is piped.
_sched_confirm() {
    local prompt="$1" ans=""
    if [[ -r /dev/tty ]]; then
        read -r -p "$prompt [y/N] " ans </dev/tty 2>/dev/null || ans=""
    else
        read -r -p "$prompt [y/N] " ans || ans=""
    fi
    [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# Validate the interval is <N>m|<N>h|<N>d (the form both back-ends accept).
_sched_validate_interval() {
    [[ "$1" =~ ^[0-9]+[mhd]$ ]] && return 0
    echo "watchman schedule: interval '$1' is invalid — use <N>m, <N>h, or <N>d (e.g. 30m, 6h, 1d)." >&2
    return 2
}

# Map an <N>m|<N>h|<N>d interval to a 5-field cron expression. cron is coarser than
# systemd: minutes must divide 60 and hours must divide 24 to map cleanly. Prints
# the expression on success; on failure prints guidance to stderr and returns 1.
_sched_cron_expr() {
    local iv="$1" n unit
    [[ "$iv" =~ ^([0-9]+)([mhd])$ ]] || { echo "watchman schedule: bad interval '$iv'." >&2; return 1; }
    n="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]}"
    case "$unit" in
        m)  if (( n >= 1 && n <= 59 && 60 % n == 0 )); then echo "*/$n * * * *"
            else echo "watchman schedule: '$iv' doesn't map to cron — minutes must divide 60 (5m,10m,12m,15m,20m,30m). Use --systemd for arbitrary intervals." >&2; return 1; fi ;;
        h)  if (( n >= 1 && n <= 23 && 24 % n == 0 )); then echo "0 */$n * * *"
            else echo "watchman schedule: '$iv' doesn't map to cron — hours must divide 24 (1h,2h,3h,4h,6h,8h,12h). Use --systemd for arbitrary intervals." >&2; return 1; fi ;;
        d)  if (( n >= 1 && n <= 31 )); then echo "0 0 */$n * *"
            else echo "watchman schedule: '$iv' out of range — use 1d..31d, or --systemd." >&2; return 1; fi ;;
    esac
}

# schedule_install [--every <interval>] [--cron|--systemd]
schedule_install() {
    local interval="$SCHED_DEFAULT_INTERVAL" mech=""
    while (($#)); do
        case "$1" in
            --every)    interval="${2:-}"; shift 2 ;;
            --every=*)  interval="${1#*=}"; shift ;;
            --cron)     mech=cron; shift ;;
            --systemd)  mech=systemd; shift ;;
            *) echo "watchman schedule install: unknown argument '$1'." >&2; return 2 ;;
        esac
    done
    _sched_validate_interval "$interval" || return 2
    [[ -n "$mech" ]] || mech="$(_sched_default_mech)"
    case "$mech" in
        systemd) _sched_install_systemd "$interval" ;;
        cron)    _sched_install_cron "$interval" ;;
        *)       echo "watchman schedule install: unknown mechanism '$mech'." >&2; return 2 ;;
    esac
}

_sched_install_systemd() {
    local interval="$1"
    command -v systemctl >/dev/null 2>&1 || {
        echo "watchman schedule: systemctl not found — this host has no systemd. Use --cron." >&2; return 1; }
    local svc="$SCHED_SYSTEMD_DIR/$SCHED_SERVICE" tmr="$SCHED_SYSTEMD_DIR/$SCHED_TIMER" f
    for f in "$svc" "$tmr"; do
        if [[ -e "$f" ]] && ! grep -q "$SCHED_UNIT_MARK" "$f" 2>/dev/null; then
            echo "watchman schedule: $f exists and is NOT a claude-watchman unit — refusing to overwrite it." >&2
            return 1
        fi
    done
    cat >&2 <<EOF

watchman schedule: this is a SYSTEM CHANGE. It will install a systemd timer that
runs a headless monitoring pass every $interval, writing two unit files and enabling
the timer:
    $svc
    $tmr
    systemctl daemon-reload && systemctl enable --now $SCHED_TIMER
It does NOT stop or alter any other service, and it is fully reversible with
'watchman schedule remove'. The headless pass is read-only (it can apply no fixes).
EOF
    _sched_confirm "Install the systemd timer now?" || { echo "watchman schedule: aborted, nothing changed." >&2; return 1; }
    [[ -w "$SCHED_SYSTEMD_DIR" ]] || { echo "watchman schedule: $SCHED_SYSTEMD_DIR is not writable — run as root." >&2; return 1; }

    cat >"$svc" <<EOF
$SCHED_UNIT_MARK — DO NOT hand-edit; managed by 'watchman schedule'.
[Unit]
Description=claude-watchman — one headless monitoring loop pass
Documentation=https://github.com/odysseyalive/claude-watchman

[Service]
Type=oneshot
WorkingDirectory=$WATCHMAN_ROOT
# Login shell so the 'claude' CLI on root's PATH (often ~/.local/bin) is found.
ExecStart=/bin/bash -lc 'exec "$WATCHMAN_ROOT/bin/watchman" run'
EOF

    cat >"$tmr" <<EOF
$SCHED_UNIT_MARK — DO NOT hand-edit; managed by 'watchman schedule'.
[Unit]
Description=claude-watchman — recurring monitoring loop (every $interval)

[Timer]
OnBootSec=5min
OnUnitActiveSec=$interval
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload || { echo "watchman schedule: systemctl daemon-reload failed." >&2; return 1; }
    systemctl enable --now "$SCHED_TIMER" || { echo "watchman schedule: failed to enable $SCHED_TIMER." >&2; return 1; }
    echo "watchman schedule: systemd timer installed and started (every $interval). Next runs:" >&2
    systemctl list-timers "$SCHED_TIMER" --no-pager 2>/dev/null | sed 's/^/    /' >&2 || true
}

_sched_install_cron() {
    local interval="$1" expr
    command -v crontab >/dev/null 2>&1 || {
        echo "watchman schedule: 'crontab' not found — install cron, or use --systemd." >&2; return 1; }
    expr="$(_sched_cron_expr "$interval")" || return 2
    local line="$expr /bin/bash -lc 'exec \"$WATCHMAN_ROOT/bin/watchman\" run' >> \"$SCHED_RUNLOG\" 2>&1 $SCHED_CRON_MARK"
    cat >&2 <<EOF

watchman schedule: this is a SYSTEM CHANGE. It will add ONE line to root's crontab,
running a headless monitoring pass every $interval:
    $line
Existing crontab entries are preserved untouched, and this is reversible with
'watchman schedule remove'. The headless pass is read-only (it can apply no fixes).
EOF
    _sched_confirm "Add this crontab entry now?" || { echo "watchman schedule: aborted, nothing changed." >&2; return 1; }
    # Drop any prior claude-watchman line (idempotent re-install), keep everything else.
    local current
    current="$(crontab -l 2>/dev/null | grep -v -F "$SCHED_CRON_MARK" || true)"
    { [[ -n "$current" ]] && printf '%s\n' "$current"; printf '%s\n' "$line"; } | crontab - || {
        echo "watchman schedule: failed to update root's crontab." >&2; return 1; }
    echo "watchman schedule: cron entry installed (every $interval). Output logs to $SCHED_RUNLOG." >&2
}

# schedule_status — read-only: report whichever trigger is installed + the ledger.
schedule_status() {
    echo "claude-watchman schedule status" >&2
    local found=0
    if command -v systemctl >/dev/null 2>&1 && [[ -f "$SCHED_SYSTEMD_DIR/$SCHED_TIMER" ]]; then
        found=1
        echo "  systemd timer: $SCHED_SYSTEMD_DIR/$SCHED_TIMER" >&2
        systemctl is-enabled "$SCHED_TIMER" >/dev/null 2>&1 && echo "    enabled" >&2 || echo "    present but not enabled" >&2
        systemctl list-timers "$SCHED_TIMER" --no-pager 2>/dev/null | sed 's/^/    /' >&2 || true
    fi
    if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$SCHED_CRON_MARK"; then
        found=1
        echo "  cron entry (root):" >&2
        crontab -l 2>/dev/null | grep -F "$SCHED_CRON_MARK" | sed 's/^/    /' >&2
    fi
    (( found )) || echo "  no headless schedule installed (the tmux /loop is the other cadence — see README)." >&2
    echo "  --- token / cost ledger (headless runs) ---" >&2
    schedule_ledger_summary >&2
}

# schedule_remove — tear down whichever trigger is installed. Stopping/disabling a
# service and deleting unit files / a crontab line are destructive, so each back-end
# is confirmed (default No) per the Prime Directive. Removes ONLY claude-watchman's
# own trigger; never touches other services or other crontab lines.
schedule_remove() {
    local did=0
    if command -v systemctl >/dev/null 2>&1 && [[ -f "$SCHED_SYSTEMD_DIR/$SCHED_TIMER" ]]; then
        cat >&2 <<EOF

watchman schedule remove: this will STOP and DISABLE the systemd timer and DELETE
its unit files (a system change — it ends the recurring headless loop):
    systemctl disable --now $SCHED_TIMER
    rm $SCHED_SYSTEMD_DIR/$SCHED_TIMER $SCHED_SYSTEMD_DIR/$SCHED_SERVICE
No other service is affected.
EOF
        if _sched_confirm "Remove the systemd timer now?"; then
            systemctl disable --now "$SCHED_TIMER" 2>/dev/null || true
            rm -f "$SCHED_SYSTEMD_DIR/$SCHED_TIMER" "$SCHED_SYSTEMD_DIR/$SCHED_SERVICE"
            systemctl daemon-reload 2>/dev/null || true
            echo "watchman schedule: systemd timer removed." >&2; did=1
        else
            echo "watchman schedule: left the systemd timer in place." >&2
        fi
    fi
    if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$SCHED_CRON_MARK"; then
        cat >&2 <<EOF

watchman schedule remove: this will delete the claude-watchman line from root's
crontab (every other crontab entry is preserved).
EOF
        if _sched_confirm "Remove the cron entry now?"; then
            crontab -l 2>/dev/null | grep -v -F "$SCHED_CRON_MARK" | crontab - || {
                echo "watchman schedule: failed to rewrite crontab." >&2; return 1; }
            echo "watchman schedule: cron entry removed." >&2; did=1
        else
            echo "watchman schedule: left the cron entry in place." >&2
        fi
    fi
    (( did )) || echo "watchman schedule: no claude-watchman schedule found to remove." >&2
}
