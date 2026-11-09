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
#   * `watchman liveness`        — the watchdog: alerts when passes stop or keep failing,
#                                  from its own trigger, spending no tokens.
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
SCHED_RUNLOCK="${SCHED_RUNLOCK:-$WATCHMAN_ROOT/journal/run.lock}"
SCHED_CRON_MARK="# claude-watchman loop"
SCHED_UNIT_MARK="# managed by claude-watchman"
SCHED_SYSTEMD_DIR="/etc/systemd/system"
SCHED_SERVICE="watchman-loop.service"
SCHED_TIMER="watchman-loop.timer"
SCHED_DEFAULT_INTERVAL="6h"
SCHED_LIVENESS_STATE="${SCHED_LIVENESS_STATE:-$WATCHMAN_ROOT/journal/liveness-alert.state}"
SCHED_LIVENESS_CRON_MARK="# claude-watchman liveness"
SCHED_LIVENESS_SERVICE="watchman-liveness.service"
SCHED_LIVENESS_TIMER="watchman-liveness.timer"
SCHED_LIVENESS_DEFAULT_INTERVAL="1h"
# Generated-trigger version. BUMP THIS whenever the shape of the systemd unit or the
# cron line changes, so an already-installed trigger can be detected as stale and the
# operator told to re-run `watchman schedule install` (an on-disk unit is machine state,
# so update/status DETECT drift but never rewrite it silently — see schedule_drift_notice).
#   v1 = pre-HOME/PATH-fix shape (no version stamp on disk — absence == v1 == broken)
#   v2 = HOME + PATH pinned into the trigger, deterministic env, self-test on install
SCHED_UNIT_VERSION=2

# --- the headless single pass (what the trigger fires) ----------------------
# Runs ONE `/watchman loop` pass headless under the auto-discovered read-only
# dontAsk loop profile, then records the pass's tokens + cost to the ledger so
# token use stays visible without a live meter, and checks the pass was healthy.
# Returns claude's exit code.
#
# OVERLAP GUARD (finding 2115). One pass at a time: a pass that outlives the interval, or a
# manual `watchman run` beside the timer, used to start a second pass that fought the first
# over journal/log-offsets.txt. The pass holds a non-blocking flock on journal/run.lock; a pass
# that cannot take it logs SKIPPED to run.log and returns 0 without starting claude. A skip
# writes no ledger row and never reaches the health gate, so it is not a failure; the liveness
# watchdog still judges the pass that holds the lock, so a hung pass still alerts as stale.
schedule_run() {
    cd "$WATCHMAN_ROOT" || { echo "watchman run: cannot cd to $WATCHMAN_ROOT" >&2; return 1; }
    mkdir -p "$WATCHMAN_ROOT/journal"

    local rc=0
    exec {_SCHED_LOCKFD}>>"$SCHED_RUNLOCK" || {
        echo "watchman run: cannot open $SCHED_RUNLOCK" >&2
        return 1
    }
    if command -v flock >/dev/null 2>&1; then
        if ! flock -n "$_SCHED_LOCKFD"; then
            exec {_SCHED_LOCKFD}>&-
            echo "[$(date -Is 2>/dev/null || date)] watchman run: SKIPPED — another pass still holds journal/run.lock" >>"$SCHED_RUNLOG"
            echo "watchman run: another pass is still running; skipping this one." >&2
            return 0
        fi
    else
        echo "[$(date -Is 2>/dev/null || date)] watchman run: flock not found — overlap guard unavailable on this host" >>"$SCHED_RUNLOG"
    fi
    _sched_run_pass || rc=$?
    exec {_SCHED_LOCKFD}>&-
    return "$rc"
}

# The pass itself, run while schedule_run holds the lock. claude is started with the lock fd
# CLOSED, so a child it leaves behind cannot keep holding the lock after the pass ends.
_sched_run_pass() {
    local started out rc since_utc
    started="$(date -Is 2>/dev/null || date)"
    # For the health gate's journal comparison. Deliberately separate from $started, whose
    # fallback format is one sqlite's datetime() cannot parse.
    since_utc="$(date -u '+%Y-%m-%d %H:%M:%S')"
    # Journal that a pass STARTED before the claude guard, so a pass that fails the
    # guard is visible in run.log AND the ledger (surfaced by `watchman schedule
    # status`) — not only in journald, where a headless failure would otherwise hide.
    echo "[$started] watchman run: starting headless loop pass (HOME=${HOME:-unset} PATH=$PATH)" >>"$SCHED_RUNLOG"

    if ! command -v claude >/dev/null 2>&1; then
        echo "watchman run: the 'claude' CLI is not on PATH — install Claude Code, and make sure" >&2
        echo "              root has logged in once ('claude' then /login) so headless runs authenticate." >&2
        echo "[$started] watchman run: FAILED — 'claude' not on PATH (HOME=${HOME:-unset} PATH=$PATH)" >>"$SCHED_RUNLOG"
        # Record the failed pass in the ledger (cost 0, is_error=true) so it shows up in
        # `watchman schedule status` instead of vanishing into journald.
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$started" "0" "0" "0" "0" "0" "0" "true" >>"$SCHED_LEDGER"
        _sched_assert_pass_healthy 1 true "" "" "" "$started" "" || true
        return 1
    fi

    out="$(mktemp)"

    # Headless single pass. Natural-language prompt on purpose: Claude Code DROPS a
    # startup positional prompt that begins with '/', so "Run /watchman loop" (no
    # leading slash) is what actually invokes the loop. No --permission-mode /
    # --settings override: claude auto-discovers the repo's .claude/ (the read-only
    # dontAsk loop profile) from the working directory, exactly like the tmux loop.
    rc=0
    claude -p "Run /watchman loop" --output-format json >"$out" 2>>"$SCHED_RUNLOG" {_SCHED_LOCKFD}>&- || rc=$?

    if command -v jq >/dev/null 2>&1 && [[ -s "$out" ]]; then
        local cost intok outtok cachetok dur turns iserr sid
        cost=$(jq -r '.total_cost_usd // 0' "$out" 2>/dev/null || echo 0)
        intok=$(jq -r '.usage.input_tokens // 0' "$out" 2>/dev/null || echo 0)
        outtok=$(jq -r '.usage.output_tokens // 0' "$out" 2>/dev/null || echo 0)
        cachetok=$(jq -r '(.usage.cache_read_input_tokens // 0)' "$out" 2>/dev/null || echo 0)
        dur=$(jq -r '.duration_ms // 0' "$out" 2>/dev/null || echo 0)
        turns=$(jq -r '.num_turns // 0' "$out" 2>/dev/null || echo 0)
        iserr=$(jq -r '.is_error // false' "$out" 2>/dev/null || echo false)
        sid=$(jq -r '.session_id // empty' "$out" 2>/dev/null || true)
        # Append-only TSV: started, cost_usd, in_tok, out_tok, cache_tok, duration_ms, turns, is_error.
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$started" "$cost" "$intok" "$outtok" "$cachetok" "$dur" "$turns" "$iserr" >>"$SCHED_LEDGER"
        echo "watchman run: pass complete — cost \$$cost, tokens ${intok}/${outtok} in/out, ${turns} turns (rc=$rc)" >&2
        echo "[$started] watchman run: cost \$$cost tokens ${intok}/${outtok} turns ${turns} rc=$rc" >>"$SCHED_RUNLOG"
        _sched_assert_pass_healthy "$rc" "$iserr" "$outtok" "$turns" "$sid" "$started" "$since_utc" || true
    else
        echo "watchman run: pass complete (rc=$rc; cost not recorded — jq missing or no JSON output)." >&2
        echo "[$started] watchman run: cost not recorded (rc=$rc)" >>"$SCHED_RUNLOG"
        # Every pass leaves a row, or the watchdog would see a working host as stopped (no jq) or
        # miss a crash. With rc=0 the tokens are simply unknown, so the floors are skipped and
        # only the journal check runs.
        local noj_err=false
        if (( rc != 0 )); then noj_err=true; fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$started" "0" "0" "0" "0" "0" "0" "$noj_err" >>"$SCHED_LEDGER"
        _sched_assert_pass_healthy "$rc" "$noj_err" "" "" "" "$started" "$since_utc" || true
    fi
    rm -f "$out"
    return "$rc"
}

# --- pass health + liveness --------------------------------------------------
# Two independent alarms for the same blind spot: the normal notify path can only report
# findings from a pass that worked. The gate runs at the end of every pass; the watchdog runs
# on its own trigger, so it still fires when passes stop altogether. Both mail regardless of
# WATCHMAN_NOTIFY_MIN_SEVERITY, because the subject is claude-watchman itself.

# Tunables: environment, then config/watchman.conf, then the default. The config is parsed,
# not sourced, so this path never executes it. Inline "# notes" are stripped.
_sched_conf_get() {
    local key="$1" def="$2" val="${!1:-}" conf="$WATCHMAN_ROOT/config/watchman.conf"
    if [[ -z "$val" && -r "$conf" ]]; then
        val="$(sed -n "s/^[[:space:]]*${key}=//p" "$conf" | tail -n1 \
                | sed -E 's/[[:space:]]+#.*$//; s/[[:space:]]+$//; s/^["'\'']//; s/["'\'']$//')"
    fi
    printf '%s\n' "${val:-$def}"
}

# As above, falling back to the default unless the value is a plain non-negative integer.
_sched_conf_int() {
    local val; val="$(_sched_conf_get "$1" "$2")"
    [[ "$val" =~ ^[0-9]+$ ]] || val="$2"
    printf '%s\n' "$val"
}

# Path of a session's transcript, or nothing. The id comes from claude's JSON envelope and
# becomes part of a find pattern, so anything but a plain id resolves to nothing.
_sched_find_transcript() {
    local sid="${1:-}" base="${CLAUDE_CONFIG_DIR:-${HOME:-/root}/.claude}/projects"
    [[ "$sid" =~ ^[A-Za-z0-9-]+$ && -d "$base" ]] || return 0
    find "$base" -maxdepth 2 -type f -name "$sid.jsonl" 2>/dev/null | head -n1
}

# The API errors recorded in a transcript, one per line. Only these records are read: the rest
# of a root session's transcript can hold log and config contents, so it never goes in a mail.
_sched_transcript_errors() {
    [[ -r "${1:-}" ]] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    tail -n 50 "$1" 2>/dev/null \
        | jq -Rr 'fromjson? | select(.isApiErrorMessage == true)
                  | "\(.error // "error"): \(((.message.content // [])[0].text) // "")"' 2>/dev/null \
        | tail -n 3 | cut -c1-300
}

# Mail an alert and log what became of it, because send_report also returns 0 when it SKIPS.
# Returns 0 only when msmtp accepted the message, which is still not proof of delivery. Logs
# "<prefix> mail: sent|skipped-unconfigured|skipped-no-msmtp|failed rc=N".
_sched_mail_alert() {
    local prefix="$1" subject="$2" body="$3" status rc=0
    declare -F send_report >/dev/null || source "$_SCHED_LIB_DIR/smtp.sh"
    if ! smtp_is_configured; then
        status="skipped-unconfigured"; rc=1
    elif ! command -v msmtp >/dev/null 2>&1; then
        status="skipped-no-msmtp"; rc=1
    elif send_report "$subject" "$body" 2>>"$SCHED_RUNLOG"; then
        status="sent"
    else
        rc=$?; status="failed rc=$rc"
    fi
    echo "[$(date -Is 2>/dev/null || date)] $prefix mail: $status" >>"$SCHED_RUNLOG"
    return "$rc"
}

# Runs closed since a UTC time, or nothing if the journal cannot answer. A missing journal
# must not be created here, and must not read as "no runs".
_sched_runs_closed_since() {
    declare -F journal_runs_closed_since >/dev/null || source "$_SCHED_LIB_DIR/journal.sh"
    [[ -f "${JOURNAL_DB:-}" ]] || return 0
    local n; n="$(journal_runs_closed_since "$1" 2>/dev/null | tail -n1)"
    [[ "$n" =~ ^[0-9]+$ ]] && printf '%s\n' "$n"
    return 0
}

# _sched_assert_pass_healthy RC IS_ERROR OUT_TOKENS TURNS SESSION_ID STARTED SINCE_UTC
# Blank OUT_TOKENS/TURNS skip the floors (unknown, not zero); blank SINCE_UTC skips the journal
# check. Never affects the pass's exit code.
#
# The closed-run check catches what the others miss: a real pass on a production host ended
# early with rc=0, is_error=false, 13471 output tokens and 38 turns, leaving its run row open.
# correlate-findings closes that row, so none closing means the pass may have stopped short.
# On that host's history it flagged 3 of 373 clean passes, so its wording is a suspicion, not a
# verdict. Known limit: an interactive session closing a row during the pass hides it, since
# both write kind='loop'.
_sched_assert_pass_healthy() {
    local rc="$1" iserr="$2" outtok="$3" turns="$4" sid="$5" started="$6" since="$7"
    local -a reasons=()
    local min_tok min_turns closed
    min_tok="$(_sched_conf_int WATCHMAN_RUN_MIN_OUTPUT_TOKENS 2000)"
    min_turns="$(_sched_conf_int WATCHMAN_RUN_MIN_TURNS 5)"

    if [[ "$rc" != 0 ]]; then reasons+=("claude exited non-zero (rc=$rc)"); fi
    if [[ "$iserr" == true ]]; then reasons+=("claude reported is_error=true"); fi
    if [[ "$outtok" =~ ^[0-9]+$ ]] && (( outtok < min_tok )); then
        reasons+=("only $outtok output tokens (floor is $min_tok)")
    fi
    if [[ "$turns" =~ ^[0-9]+$ ]] && (( turns < min_turns )); then
        reasons+=("only $turns turns (floor is $min_turns)")
    fi
    if [[ -n "$since" ]]; then
        closed="$(_sched_runs_closed_since "$since")"
        if [[ "$closed" == 0 ]]; then
            reasons+=("no journal run row closed during this pass, so it may have stopped before correlate-findings")
        fi
    fi
    (( ${#reasons[@]} )) || return 0

    local joined host transcript errors body r
    joined="$(printf '%s; ' "${reasons[@]}")"; joined="${joined%; }"
    host="${HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"
    echo "[$started] watchman run: HEALTH GATE FAILED — $joined" >>"$SCHED_RUNLOG"
    echo "watchman run: HEALTH GATE FAILED — $joined" >&2

    transcript="$(_sched_find_transcript "$sid")"
    errors="$(_sched_transcript_errors "$transcript")"
    body="$(mktemp)" || return 0
    {
        echo "A headless claude-watchman pass on $host looks unhealthy. Started: $started"
        echo
        echo "Why:"
        for r in "${reasons[@]}"; do echo "  - $r"; done
        echo
        echo "Known causes:"
        echo "  - OAuth login lapsed: run 'claude' as root and use /login."
        echo "  - Usage quota exhausted (429): passes resume when the quota resets."
        echo "  - The pass ended its turn early with rc=0: read the transcript below."
        if [[ -n "$errors" ]]; then
            echo; echo "API errors recorded by this pass:"; printf '%s\n' "$errors" | sed 's/^/  /'
        fi
        echo
        echo "Transcript on this host: ${transcript:-not found (session id: ${sid:-none})}"
        echo
        echo "Last 25 lines of run.log:"
        tail -n 25 "$SCHED_RUNLOG" 2>/dev/null | cut -c1-500
    } >"$body"
    _sched_mail_alert "watchman run: health-gate" \
        "claude-watchman: unhealthy pass on $host" "$body" || true
    rm -f "$body"
    return 0
}

# A ledger timestamp as epoch seconds, or nothing. GNU date, then BSD date (no colon in the offset).
_sched_epoch() {
    date -d "$1" +%s 2>/dev/null \
        || date -j -f '%Y-%m-%dT%H:%M:%S%z' "$(printf '%s' "$1" | sed -E 's/([+-][0-9]{2}):([0-9]{2})$/\1\2/')" +%s 2>/dev/null \
        || true
}

# The INSTALLED loop cadence as <N>m|<N>h|<N>d, read back from the live timer or cron line so
# an operator on --every 12h is not judged on a 6h yardstick. Nothing when none is installed.
_sched_installed_interval() {
    local v expr
    if [[ -f "$SCHED_SYSTEMD_DIR/$SCHED_TIMER" ]]; then
        v="$(sed -n 's/^OnUnitActiveSec=//p' "$SCHED_SYSTEMD_DIR/$SCHED_TIMER" 2>/dev/null | head -n1)"
        [[ "$v" =~ ^[0-9]+[mhd]$ ]] && { echo "$v"; return 0; }
        echo "$SCHED_DEFAULT_INTERVAL"; return 0
    fi
    command -v crontab >/dev/null 2>&1 || return 0
    expr="$(crontab -l 2>/dev/null | grep -F "$SCHED_CRON_MARK" | head -n1 | awk '{print $1,$2,$3,$4,$5}' || true)"
    [[ -n "$expr" ]] || return 0
    if   [[ "$expr" =~ ^\*/([0-9]+)\ \*\ \*\ \*\ \*$ ]];   then echo "${BASH_REMATCH[1]}m"
    elif [[ "$expr" =~ ^0\ \*/([0-9]+)\ \*\ \*\ \*$ ]];    then echo "${BASH_REMATCH[1]}h"
    elif [[ "$expr" =~ ^0\ 0\ \*/([0-9]+)\ \*\ \*$ ]];     then echo "${BASH_REMATCH[1]}d"
    else echo "$SCHED_DEFAULT_INTERVAL"; fi
}

_sched_interval_minutes() {
    local n="${1%[mhd]}"
    case "$1" in *m) echo "$n" ;; *h) echo $(( n * 60 )) ;; *d) echo $(( n * 1440 )) ;; esac
}

# Pure read. Sets LV_STATE to ok|stale|failing|none and LV_DETAIL to a sentence explaining it.
# A failed pass still writes a fresh row, so age alone cannot see an outage made of failures,
# which is why the newest rows' is_error is checked too.
_sched_liveness_verdict() {
    LV_STATE=none; LV_DETAIL=""
    local iv factor limit_min fail_limit newest ts epoch now age_min failed
    iv="$(_sched_installed_interval)"
    if [[ -z "$iv" ]]; then
        LV_DETAIL="no headless schedule is installed, so there is no cadence to judge"
        return 0
    fi
    factor="$(_sched_conf_get WATCHMAN_LIVENESS_FACTOR 1.5)"
    [[ "$factor" =~ ^[0-9]+(\.[0-9]+)?$ ]] || factor=1.5
    limit_min="$(awk -v m="$(_sched_interval_minutes "$iv")" -v f="$factor" 'BEGIN{print int(m*f)}')"
    fail_limit="$(_sched_conf_int WATCHMAN_LIVENESS_FAILED_PASSES 1)"
    (( fail_limit >= 1 )) || fail_limit=1
    now="$(date +%s)"

    newest="$(tail -n1 "$SCHED_LEDGER" 2>/dev/null || true)"
    if [[ -z "$newest" ]]; then
        # No pass has ever been recorded. Judge from when the trigger was installed, if known.
        epoch="$(stat -c %Y "$SCHED_SYSTEMD_DIR/$SCHED_TIMER" 2>/dev/null || true)"
        if [[ "$epoch" =~ ^[0-9]+$ ]] && (( (now - epoch) / 60 > limit_min )); then
            LV_STATE=stale
            LV_DETAIL="no pass has ever been recorded, and the timer was installed $(( (now - epoch) / 60 ))m ago (cadence $iv, alert at ${limit_min}m)"
        else
            LV_STATE=ok; LV_DETAIL="no pass recorded yet (cadence $iv, alert at ${limit_min}m)"
        fi
        return 0
    fi
    ts="${newest%%$'\t'*}"
    epoch="$(_sched_epoch "$ts")"
    failed="$(tail -n 200 "$SCHED_LEDGER" | awk -F'\t' '{e[NR]=$8} END{n=0; for(i=NR;i>0;i--){ if(e[i]=="true"||e[i]=="1") n++; else break } print n}')"

    if [[ -n "$epoch" ]]; then
        age_min=$(( (now - epoch) / 60 ))
        if (( age_min > limit_min )); then
            LV_STATE=stale
            LV_DETAIL="last pass $age_min minutes ago at $ts (cadence $iv, alert at ${limit_min}m)"
            return 0
        fi
    else
        age_min="?"
    fi
    if (( failed >= fail_limit )); then
        LV_STATE=failing
        LV_DETAIL="the newest $failed pass(es) failed with is_error, most recently at $ts (cadence $iv)"
        return 0
    fi
    LV_STATE=ok
    LV_DETAIL="last pass ${age_min}m ago, cadence $iv, alert at ${limit_min}m"
}

# schedule_liveness_check [--quiet] — one check. Returns 0 when healthy and 1 when not (the unit
# marks 1 as a success: detecting an outage is the watchdog working). Mails once per episode,
# remembered in the state file. The state records an episode only once mail was actually sent,
# so an alert that could not go out is retried on the next check. Only a healthy verdict clears
# it, so a fresh failed row cannot end an outage and re-arm the mail.
schedule_liveness_check() {
    local quiet=0
    while (($#)); do
        case "$1" in
            --quiet) quiet=1; shift ;;
            *) echo "watchman liveness: unknown argument '$1'." >&2; return 2 ;;
        esac
    done
    _sched_liveness_verdict
    case "$LV_STATE" in
        none)
            (( quiet )) || echo "watchman liveness: $LV_DETAIL." >&2
            return 0 ;;
        ok)
            if [[ -f "$SCHED_LIVENESS_STATE" ]]; then
                rm -f "$SCHED_LIVENESS_STATE"
                echo "[$(date -Is 2>/dev/null || date)] watchman liveness: recovered — $LV_DETAIL" >>"$SCHED_RUNLOG"
            fi
            (( quiet )) || echo "watchman liveness: OK — $LV_DETAIL." >&2
            return 0 ;;
    esac

    local prior="" host body subject
    [[ -f "$SCHED_LIVENESS_STATE" ]] && prior="$(cut -f1 "$SCHED_LIVENESS_STATE" 2>/dev/null | head -n1)"
    if [[ "$prior" == "$LV_STATE" ]]; then
        (( quiet )) || echo "watchman liveness: still $LV_STATE, already alerted — $LV_DETAIL." >&2
        return 1
    fi

    host="${HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"
    echo "[$(date -Is 2>/dev/null || date)] watchman liveness: ALERT $LV_STATE — $LV_DETAIL" >>"$SCHED_RUNLOG"
    (( quiet )) || echo "watchman liveness: ALERT $LV_STATE — $LV_DETAIL." >&2
    body="$(mktemp)" || return 1
    if [[ "$LV_STATE" == stale ]]; then
        subject="claude-watchman: monitoring stopped on $host"
    else
        subject="claude-watchman: passes failing on $host"
    fi
    {
        if [[ "$LV_STATE" == stale ]]; then
            echo "The claude-watchman monitoring loop on $host has stopped running: $LV_DETAIL."
            echo "Findings are not being checked. Start with: watchman schedule status"
        else
            echo "claude-watchman passes on $host are running but failing: $LV_DETAIL."
            echo "Findings are not being checked. Common causes: the OAuth login lapsed (run 'claude'"
            echo "as root and use /login), or the usage quota is exhausted (429)."
        fi
        echo
        echo "You will get one mail per outage. It clears after the next healthy pass."
        echo
        echo "Last 25 lines of run.log:"
        tail -n 25 "$SCHED_RUNLOG" 2>/dev/null | cut -c1-500
    } >"$body"
    if _sched_mail_alert "watchman liveness:" "$subject" "$body"; then
        mkdir -p "$(dirname "$SCHED_LIVENESS_STATE")"
        printf '%s\t%s\n' "$LV_STATE" "$(date +%s)" >"$SCHED_LIVENESS_STATE"
    fi
    rm -f "$body"
    return 1
}

# Read-only: is the watchdog installed, and what would it say right now? Never mails.
schedule_liveness_status() {
    echo "claude-watchman liveness watchdog" >&2
    local found=0
    if [[ -f "$SCHED_SYSTEMD_DIR/$SCHED_LIVENESS_TIMER" ]]; then
        found=1; echo "  systemd timer: $SCHED_SYSTEMD_DIR/$SCHED_LIVENESS_TIMER" >&2
        systemctl is-enabled "$SCHED_LIVENESS_TIMER" >/dev/null 2>&1 && echo "    enabled" >&2 || echo "    present but not enabled" >&2
    fi
    if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$SCHED_LIVENESS_CRON_MARK"; then
        found=1; echo "  cron entry (root):" >&2
        crontab -l 2>/dev/null | grep -F "$SCHED_LIVENESS_CRON_MARK" | sed 's/^/    /' >&2
    fi
    (( found )) || echo "  not installed: nothing fires this check. Run 'watchman liveness install'." >&2
    _sched_liveness_verdict
    echo "  verdict: $LV_STATE — $LV_DETAIL" >&2
    if [[ -f "$SCHED_LIVENESS_STATE" ]]; then
        echo "  already alerted for this outage: $(cut -f1 "$SCHED_LIVENESS_STATE")" >&2
    fi
    return 0
}

# schedule_liveness_install [--every <interval>] [--cron|--systemd] — the watchdog's OWN trigger,
# independent of the loop timer, because a check riding on the loop could not report it stopped.
schedule_liveness_install() {
    local interval="$SCHED_LIVENESS_DEFAULT_INTERVAL" mech=""
    while (($#)); do
        case "$1" in
            --every)    interval="${2:-}"; shift 2 ;;
            --every=*)  interval="${1#*=}"; shift ;;
            --cron)     mech=cron; shift ;;
            --systemd)  mech=systemd; shift ;;
            *) echo "watchman liveness install: unknown argument '$1'." >&2; return 2 ;;
        esac
    done
    _sched_validate_interval "$interval" || return 2
    [[ -n "$mech" ]] || mech="$(_sched_default_mech)"
    local env_home env_path msmtp_bin
    env_home="$(getent passwd root 2>/dev/null | cut -d: -f6)"; env_home="${env_home:-${HOME:-/root}}"
    env_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    msmtp_bin="$(command -v msmtp 2>/dev/null || true)"
    if [[ -n "$msmtp_bin" && ":$env_path:" != *":$(dirname "$msmtp_bin"):"* ]]; then
        env_path="$(dirname "$msmtp_bin"):$env_path"
    fi
    case "$mech" in
        systemd) _sched_liveness_install_systemd "$interval" "$env_home" "$env_path" ;;
        cron)    _sched_liveness_install_cron "$interval" "$env_home" "$env_path" ;;
        *)       echo "watchman liveness install: unknown mechanism '$mech'." >&2; return 2 ;;
    esac
}

_sched_liveness_install_systemd() {
    local interval="$1" env_home="$2" env_path="$3"
    command -v systemctl >/dev/null 2>&1 || {
        echo "watchman liveness: systemctl not found — this host has no systemd. Use --cron." >&2; return 1; }
    local svc="$SCHED_SYSTEMD_DIR/$SCHED_LIVENESS_SERVICE" tmr="$SCHED_SYSTEMD_DIR/$SCHED_LIVENESS_TIMER" f
    for f in "$svc" "$tmr"; do
        if [[ -e "$f" ]] && ! grep -q "$SCHED_UNIT_MARK" "$f" 2>/dev/null; then
            echo "watchman liveness: $f exists and is NOT a claude-watchman unit — refusing to overwrite it." >&2
            return 1
        fi
    done
    cat >&2 <<EOF

watchman liveness: this is a SYSTEM CHANGE. It will write two unit files and enable a timer
that checks every $interval that the monitoring loop is still running:
    $svc
    $tmr
    systemctl daemon-reload && systemctl enable --now $SCHED_LIVENESS_TIMER
Any existing claude-watchman liveness units at those paths are overwritten. It alters no other
service, spends no tokens, and is reversible with 'watchman liveness remove'.
EOF
    _sched_confirm "Install the liveness watchdog now?" || { echo "watchman liveness: aborted, nothing changed." >&2; return 1; }
    [[ -w "$SCHED_SYSTEMD_DIR" ]] || { echo "watchman liveness: $SCHED_SYSTEMD_DIR is not writable — run as root." >&2; return 1; }
    cat >"$svc" <<EOF
$SCHED_UNIT_MARK — DO NOT hand-edit; managed by 'watchman liveness'.
[Unit]
Description=claude-watchman — check the monitoring loop is still running

[Service]
Type=oneshot
WorkingDirectory=$WATCHMAN_ROOT
Environment=HOME=$env_home
Environment=PATH=$env_path
# SuccessExitStatus=1: the check returns 1 when it ALERTS, which is a successful
# detection, not a unit failure. Without this every real alert would also mark the
# unit failed and muddy 'systemctl status'.
SuccessExitStatus=0 1
ExecStart=/bin/bash -c 'exec "$WATCHMAN_ROOT/bin/watchman" liveness --quiet'
EOF
    cat >"$tmr" <<EOF
$SCHED_UNIT_MARK — DO NOT hand-edit; managed by 'watchman liveness'.
[Unit]
Description=claude-watchman — liveness watchdog (every $interval)

[Timer]
OnBootSec=10min
OnUnitActiveSec=$interval
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload || { echo "watchman liveness: systemctl daemon-reload failed." >&2; return 1; }
    systemctl enable --now "$SCHED_LIVENESS_TIMER" || { echo "watchman liveness: failed to enable $SCHED_LIVENESS_TIMER." >&2; return 1; }
    echo "watchman liveness: watchdog installed (every $interval)." >&2
}

_sched_liveness_install_cron() {
    local interval="$1" env_home="$2" env_path="$3" expr current
    command -v crontab >/dev/null 2>&1 || {
        echo "watchman liveness: 'crontab' not found — install cron, or use --systemd." >&2; return 1; }
    expr="$(_sched_cron_expr "$interval")" || return 2
    local line="$expr HOME=\"$env_home\" PATH=\"$env_path\" /bin/bash -c 'exec \"$WATCHMAN_ROOT/bin/watchman\" liveness --quiet' >> \"$SCHED_RUNLOG\" 2>&1 $SCHED_LIVENESS_CRON_MARK"
    cat >&2 <<EOF

watchman liveness: this is a SYSTEM CHANGE. It will add ONE line to root's crontab, checking
every $interval that the monitoring loop is still running:
    $line
Existing crontab entries are preserved, it spends no tokens, and it is reversible with
'watchman liveness remove'.
EOF
    _sched_confirm "Add this crontab entry now?" || { echo "watchman liveness: aborted, nothing changed." >&2; return 1; }
    current="$(crontab -l 2>/dev/null | grep -v -F "$SCHED_LIVENESS_CRON_MARK" || true)"
    { [[ -n "$current" ]] && printf '%s\n' "$current"; printf '%s\n' "$line"; } | crontab - || {
        echo "watchman liveness: failed to update root's crontab." >&2; return 1; }
    echo "watchman liveness: cron entry installed (every $interval)." >&2
}

# schedule_liveness_remove — stop and remove the watchdog. Confirmed per back-end, like
# schedule_remove. The monitoring loop itself is unaffected.
schedule_liveness_remove() {
    local did=0
    if [[ -f "$SCHED_SYSTEMD_DIR/$SCHED_LIVENESS_TIMER" ]]; then
        cat >&2 <<EOF

watchman liveness remove: this will STOP and DISABLE the watchdog timer and DELETE its two unit
files from $SCHED_SYSTEMD_DIR. A dead monitoring loop would then notify nobody. The loop itself
is unaffected.
EOF
        if _sched_confirm "Remove the liveness watchdog now?"; then
            systemctl disable --now "$SCHED_LIVENESS_TIMER" 2>/dev/null || true
            rm -f "${SCHED_SYSTEMD_DIR:?}/${SCHED_LIVENESS_TIMER:?}" "${SCHED_SYSTEMD_DIR:?}/${SCHED_LIVENESS_SERVICE:?}"
            systemctl daemon-reload 2>/dev/null || true
            echo "watchman liveness: watchdog timer removed." >&2; did=1
        else
            echo "watchman liveness: left the watchdog timer in place." >&2
        fi
    fi
    if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$SCHED_LIVENESS_CRON_MARK"; then
        echo >&2
        echo "watchman liveness remove: this will delete the watchdog line from root's crontab." >&2
        if _sched_confirm "Remove the cron entry now?"; then
            crontab -l 2>/dev/null | grep -v -F "$SCHED_LIVENESS_CRON_MARK" | crontab - || {
                echo "watchman liveness: failed to rewrite crontab." >&2; return 1; }
            echo "watchman liveness: cron entry removed." >&2; did=1
        else
            echo "watchman liveness: left the cron entry in place." >&2
        fi
    fi
    (( did )) || echo "watchman liveness: no installed watchdog was removed." >&2
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
# The prompt is printed explicitly (NOT via read -p): read writes its -p prompt to
# stderr, so redirecting the read's stderr to /dev/null — needed to swallow a tty
# error — would also swallow the prompt, leaving the operator staring at a blank
# hang. Print the prompt to a visible stream first, then read silently.
_sched_confirm() {
    local prompt="$1" ans=""
    if [[ -r /dev/tty ]]; then
        printf '%s [y/N] ' "$prompt" >/dev/tty
        read -r ans </dev/tty 2>/dev/null || ans=""
    else
        printf '%s [y/N] ' "$prompt" >&2
        read -r ans || ans=""
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

# Resolve the environment a headless pass needs, from the account this installer runs
# as (root, for whom 'claude' already resolves). Sets SCHED_ENV_HOME / SCHED_ENV_PATH /
# SCHED_ENV_CLAUDE. A User=-less systemd service starts with HOME unset and a bare PATH,
# and cron runs with a minimal PATH — either way ~/.local/bin/claude (the DEFAULT install
# location) is never found unless we pin HOME and PATH explicitly at install time rather
# than trusting a non-interactive login shell + root's dotfiles. Warns (does not fail) if
# 'claude' cannot be located, so the schedule still installs and the self-test flags it.
_sched_resolve_env() {
    SCHED_ENV_HOME="$(getent passwd root 2>/dev/null | cut -d: -f6)"
    SCHED_ENV_HOME="${SCHED_ENV_HOME:-${HOME:-/root}}"
    SCHED_ENV_CLAUDE="$(command -v claude 2>/dev/null || true)"
    if [[ -n "$SCHED_ENV_CLAUDE" ]]; then
        SCHED_ENV_PATH="$(dirname "$SCHED_ENV_CLAUDE"):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    else
        SCHED_ENV_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        echo "watchman schedule: WARNING — 'claude' is not on the installer's PATH. The schedule" >&2
        echo "    will be created, but scheduled passes will fail until 'claude' is installed for" >&2
        echo "    root and reachable on PATH (run 'claude' once and '/login' to authenticate headless runs)." >&2
    fi
}

# Post-install self-test: confirm 'claude' actually resolves in the CLEAN environment the
# trigger will run under (only HOME + PATH set, exactly as written into the unit / cron
# line). `env -i` reproduces that stripped environment faithfully and is portable across
# both back-ends. Returns 0 on success; the callers warn loudly on failure instead of
# reporting a false success.
_sched_selftest_env() {
    env -i HOME="$SCHED_ENV_HOME" PATH="$SCHED_ENV_PATH" /bin/bash -c 'command -v claude >/dev/null 2>&1'
}

_sched_install_systemd() {
    local interval="$1"
    command -v systemctl >/dev/null 2>&1 || {
        echo "watchman schedule: systemctl not found — this host has no systemd. Use --cron." >&2; return 1; }
    local svc="$SCHED_SYSTEMD_DIR/$SCHED_SERVICE" tmr="$SCHED_SYSTEMD_DIR/$SCHED_TIMER" f verb="install" exists=0
    for f in "$svc" "$tmr"; do
        if [[ -e "$f" ]] && ! grep -q "$SCHED_UNIT_MARK" "$f" 2>/dev/null; then
            echo "watchman schedule: $f exists and is NOT a claude-watchman unit — refusing to overwrite it." >&2
            return 1
        fi
    done
    # Re-running over an existing managed unit is the REPAIR/regenerate path (e.g. to heal a
    # stale pre-v2 trigger) — word the prompt that way so it doesn't read as a fresh install.
    if [[ -e "$svc" || -e "$tmr" ]]; then verb="regenerate"; exists=1; fi
    cat >&2 <<EOF

watchman schedule: this is a SYSTEM CHANGE. It will ${verb^^} the claude-watchman systemd
timer that runs a headless monitoring pass every $interval, $( ((exists)) && echo "rewriting" || echo "writing" ) two unit files and
(re-)enabling the timer:
    $svc
    $tmr
    systemctl daemon-reload && systemctl enable --now $SCHED_TIMER
It does NOT stop or alter any other service, and it is fully reversible with
'watchman schedule remove'. The headless pass is read-only (it can apply no fixes).
EOF
    _sched_confirm "${verb^} the systemd timer now?" || { echo "watchman schedule: aborted, nothing changed." >&2; return 1; }
    [[ -w "$SCHED_SYSTEMD_DIR" ]] || { echo "watchman schedule: $SCHED_SYSTEMD_DIR is not writable — run as root." >&2; return 1; }

    # Resolve HOME + PATH now, from the installing account, and bake them into the unit.
    # A User=-less root service starts with HOME unset, so root's ~/.bashrc PATH logic
    # (export PATH="$HOME/.local/bin:$PATH") collapses to "/.local/bin" and never finds
    # ~/.local/bin/claude — the historic 100%-failure bug. Pinning both makes the service
    # environment deterministic instead of dotfile-dependent, so we also drop the login shell.
    _sched_resolve_env

    cat >"$svc" <<EOF
$SCHED_UNIT_MARK — DO NOT hand-edit; managed by 'watchman schedule'.
# watchman-schedule-version: $SCHED_UNIT_VERSION
[Unit]
Description=claude-watchman — one headless monitoring loop pass
Documentation=https://github.com/odysseyalive/claude-watchman

[Service]
Type=oneshot
WorkingDirectory=$WATCHMAN_ROOT
# HOME + PATH resolved at install time: a User=-less service starts with HOME unset and a
# bare PATH, so headless claude (in ~/.local/bin) and its credentials would not be found.
Environment=HOME=$SCHED_ENV_HOME
Environment=PATH=$SCHED_ENV_PATH
ExecStart=/bin/bash -c 'exec "$WATCHMAN_ROOT/bin/watchman" run'
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

    # Self-test the REAL trigger environment (HOME + PATH as baked into the unit). A green
    # 'enable' does NOT prove the scheduled pass will find claude — verify it, warn loudly
    # if not, rather than reporting a success that fails silently every interval.
    if _sched_selftest_env; then
        echo "watchman schedule: self-test OK — 'claude' resolves in the timer's environment." >&2
    else
        echo "watchman schedule: WARNING — self-test FAILED: 'claude' does NOT resolve under" >&2
        echo "    HOME=$SCHED_ENV_HOME PATH=$SCHED_ENV_PATH. Every scheduled pass will fail until" >&2
        echo "    this is fixed. Ensure claude is installed for root and 'claude'/'/login' has run." >&2
    fi
}

_sched_install_cron() {
    local interval="$1" expr
    command -v crontab >/dev/null 2>&1 || {
        echo "watchman schedule: 'crontab' not found — install cron, or use --systemd." >&2; return 1; }
    expr="$(_sched_cron_expr "$interval")" || return 2
    # Parity with the systemd path: HOME is fine (cron reads it from /etc/passwd), but cron's
    # minimal PATH has the same ~/.local/bin blind spot, so pin HOME + PATH resolved at install
    # time into the command rather than trusting a login shell to reconstruct them.
    _sched_resolve_env
    # Append a version token after the base mark ("… loop v2"); grep -F on SCHED_CRON_MARK
    # still matches it, so status/remove are unaffected, while status can read the version.
    local line="$expr HOME=\"$SCHED_ENV_HOME\" PATH=\"$SCHED_ENV_PATH\" /bin/bash -c 'exec \"$WATCHMAN_ROOT/bin/watchman\" run' >> \"$SCHED_RUNLOG\" 2>&1 $SCHED_CRON_MARK v$SCHED_UNIT_VERSION"
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

    # Same post-install self-test as the systemd path: confirm claude resolves under the
    # HOME + PATH the cron line pins, and warn loudly rather than fail silently every run.
    if _sched_selftest_env; then
        echo "watchman schedule: self-test OK — 'claude' resolves in the cron job's environment." >&2
    else
        echo "watchman schedule: WARNING — self-test FAILED: 'claude' does NOT resolve under" >&2
        echo "    HOME=$SCHED_ENV_HOME PATH=$SCHED_ENV_PATH. Every scheduled pass will fail until" >&2
        echo "    this is fixed. Ensure claude is installed for root and 'claude'/'/login' has run." >&2
    fi
}

# Read the generated-trigger version stamped on the INSTALLED trigger (not on the code).
# Echoes the integer version, or 0 when a trigger IS installed but carries no stamp (a
# pre-v2 install — the HOME/PATH-broken shape); echoes nothing when none is installed.
# systemd wins if both are somehow present. Pure read; never mutates.
_sched_installed_version() {
    local v=""
    if command -v systemctl >/dev/null 2>&1 && [[ -f "$SCHED_SYSTEMD_DIR/$SCHED_SERVICE" ]]; then
        v="$(sed -n 's/^# watchman-schedule-version:[[:space:]]*//p' "$SCHED_SYSTEMD_DIR/$SCHED_SERVICE" 2>/dev/null | head -n1)"
        echo "${v:-0}"; return 0
    fi
    if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$SCHED_CRON_MARK"; then
        v="$(crontab -l 2>/dev/null | grep -F "$SCHED_CRON_MARK" | grep -oE 'v[0-9]+[[:space:]]*$' | grep -oE '[0-9]+' | head -n1)"
        echo "${v:-0}"; return 0
    fi
    return 0   # nothing installed → echo nothing
}

# schedule_drift_notice — read-only drift detector. If a trigger is installed whose stamped
# version is OLDER than this code's generator (SCHED_UNIT_VERSION) — or carries no stamp at
# all (a pre-v2, HOME/PATH-broken install) — print a loud one-line notice naming the
# one-command repair. Prints nothing when nothing is installed or it is already current.
# Always returns 0 (stderr is its whole interface). It NEVER rewrites the on-disk trigger: an
# installed unit is machine state, so healing it stays an operator-confirmed `schedule
# install` (which is idempotent and re-stamps to the current version). This is the hook
# `watchman update` calls to warn an updating operator that their LIVE trigger is now stale.
schedule_drift_notice() {
    # Always returns 0: it communicates via stderr only. A 0/1 "was there drift"
    # status would force `|| true` at every set -e call site and reintroduce the
    # exit-1-on-healthy-trigger bug the moment a caller forgets it.
    local iv label
    iv="$(_sched_installed_version)"
    [[ -z "$iv" ]] && return 0                    # nothing installed
    (( iv >= SCHED_UNIT_VERSION )) && return 0    # current — no drift
    # An unstamped trigger (iv==0) is the original pre-fix shape; call it "v1 (unstamped)".
    (( iv == 0 )) && label="v1 (unstamped, pre-fix)" || label="v${iv}"
    echo "watchman schedule: STALE TRIGGER — the installed headless schedule is ${label}, but this" >&2
    echo "    claude-watchman is v${SCHED_UNIT_VERSION}. The pre-v2 trigger carries the HOME/PATH bug and" >&2
    echo "    FAILS every run. Re-run 'watchman schedule install' to regenerate it (idempotent," >&2
    echo "    operator-confirmed) — the code update does NOT rewrite an already-installed trigger." >&2
    return 0
}

# schedule_status — read-only: report whichever trigger is installed + the ledger.
schedule_status() {
    echo "claude-watchman schedule status" >&2
    local found=0 iv vlabel
    iv="$(_sched_installed_version)"
    (( ${iv:-0} == 0 )) && vlabel="v1 pre-fix" || vlabel="v${iv}"
    if command -v systemctl >/dev/null 2>&1 && [[ -f "$SCHED_SYSTEMD_DIR/$SCHED_TIMER" ]]; then
        found=1
        echo "  systemd timer: $SCHED_SYSTEMD_DIR/$SCHED_TIMER ($vlabel)" >&2
        systemctl is-enabled "$SCHED_TIMER" >/dev/null 2>&1 && echo "    enabled" >&2 || echo "    present but not enabled" >&2
        systemctl list-timers "$SCHED_TIMER" --no-pager 2>/dev/null | sed 's/^/    /' >&2 || true
    fi
    if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$SCHED_CRON_MARK"; then
        found=1
        echo "  cron entry (root, $vlabel):" >&2
        crontab -l 2>/dev/null | grep -F "$SCHED_CRON_MARK" | sed 's/^/    /' >&2
    fi
    (( found )) || echo "  no headless schedule installed (the tmux /loop is the other cadence — see README)." >&2
    echo "  --- token / cost ledger (headless runs) ---" >&2
    schedule_ledger_summary >&2
    echo "  --- liveness ---" >&2
    schedule_liveness_status
    # Drift check last, so the STALE-TRIGGER warning + repair command are the final thing
    # the operator sees (and it sits right under any is_error runs the ledger just reported).
    if (( found )); then schedule_drift_notice; fi
    return 0
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
