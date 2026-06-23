#!/usr/bin/env bash
# lib/update.sh — the update mechanism (zero-token bash; no Claude, no git).
#
#   * update_run        — `watchman update`: re-run install.sh, which manifest-
#                         fetches the latest product into this directory and
#                         regenerates the local artifacts. Install and update are
#                         the SAME command — there is no separate update path.
#   * update_check_run  — `watchman update --check`: a MAINTAINER release-readiness
#                         check, run in the git repo before committing a feature,
#                         that asserts the update story still holds (pull-safety,
#                         manifest completeness, orchestration wiring, Prime
#                         Directive, schema sync).
#
# Update is pull-safe by construction: the manifest lists only the portable
# product, so a re-fetch overwrites product files and NEVER touches the machine
# artifacts (.env, config, journal, .claude) — they aren't in the manifest. No git
# clone, no git pull, so none of the divergence/conflict failure modes apply.
#
# > PRIME DIRECTIVE. update_run is non-destructive: install.sh fetches atomically
# > (temp dir → move only after all files succeed) and never deletes a local
# > artifact; the schema migration it triggers (journal_init) auto-applies only
# > ADDITIVE migrations — a lossy one hits the stop-warn-ask gate in journal.sh.

# --- watchman update --------------------------------------------------------
# Re-runs install.sh in --update mode. install.sh re-fetches the product from the
# manifest and runs its idempotent setup (config/journal left intact, preflight
# regenerated, additive journal migration). Safe to overwrite the running
# install.sh: the move is a rename, so this process keeps its open copy.
update_run() {
    local installer="$WATCHMAN_ROOT/install.sh"
    if [[ ! -f "$installer" ]]; then
        echo "update: $installer not found." >&2
        echo "        Re-run the install one-liner from this directory to (re)install:" >&2
        echo "        bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/odysseyalive/claude-watchman/main/install.sh)\"" >&2
        return 1
    fi
    echo "watchman update: fetching the latest product (manifest, no git) and regenerating…"
    exec bash "$installer" --update
}

# --- watchman update --sync (regenerate manifest.txt) -----------------------
# Maintainer helper: rewrite manifest.txt to list exactly the tracked product, so
# a file you just added/removed under skills/ commands/ lib/ ships (or stops
# shipping) without a hand-edit. Preserves the comment header and the hook flag on
# bin/watchman. Run it after `git add`, then `update --check`, then commit.
update_sync_run() {
    cd "$WATCHMAN_ROOT" || { echo "update --sync: cannot enter $WATCHMAN_ROOT" >&2; return 1; }
    if ! command -v git >/dev/null 2>&1 || ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "update --sync is a maintainer tool — run it inside the claude-watchman git repo." >&2
        return 1
    fi
    local m="manifest.txt" header new old p added removed
    # Preserve the leading comment/blank header (machine-format documentation).
    header=""
    [[ -f "$m" ]] && header="$(awk 'BEGIN{h=1}
        h==1 && /^[[:space:]]*#/ {print; next}
        h==1 && /^[[:space:]]*$/ {print; next}
        {h=0}' "$m")"
    [[ -n "$header" ]] || header="# manifest.txt — shipped file list. Regenerate with: watchman update --sync"
    # The product = tracked files minus .gitignore (install.sh-managed) and the manifest itself.
    new="$(git ls-files | grep -vE '^(\.gitignore|manifest\.txt)$' | sort -u)"
    old=""
    [[ -f "$m" ]] && old="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$m" | sed -E 's/^(keep|hook) //' | sort -u)"
    # Rewrite (atomic): header, then each path with its flag (only bin/watchman is +x today).
    {
        printf '%s\n\n' "$header"   # blank line between header and entries
        while IFS= read -r p; do
            [[ -n "$p" ]] || continue
            case "$p" in
                bin/watchman) printf 'hook %s\n' "$p" ;;
                *)            printf '%s\n' "$p" ;;
            esac
        done <<< "$new"
    } > "$m.tmp" && mv -f "$m.tmp" "$m"
    added="$(comm -13 <(printf '%s\n' "$old") <(printf '%s\n' "$new") | grep -v '^$' || true)"
    removed="$(comm -23 <(printf '%s\n' "$old") <(printf '%s\n' "$new") | grep -v '^$' || true)"
    if [[ -z "$added" && -z "$removed" ]]; then
        echo "update --sync: manifest.txt already in sync ($(printf '%s\n' "$new" | grep -c .) files)."
    else
        echo "update --sync: regenerated manifest.txt ($(printf '%s\n' "$new" | grep -c .) files)."
        [[ -n "$added" ]]   && { echo "  + now shipped:";   sed 's/^/      /' <<< "$added"; }
        [[ -n "$removed" ]] && { echo "  - no longer shipped:"; sed 's/^/      /' <<< "$removed"; }
        echo "Re-stage manifest.txt, run 'watchman update --check', then commit."
    fi
}

# --- watchman update --check (maintainer release-readiness) -----------------
# Deterministic guard for the maintainer: keeps the update story correct as
# features are added. Run it in the git repo before committing a new feature.
update_check_run() {
    cd "$WATCHMAN_ROOT" || { echo "update --check: cannot enter $WATCHMAN_ROOT" >&2; return 1; }
    if ! command -v git >/dev/null 2>&1 || ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "update --check is a maintainer tool — run it inside the claude-watchman git repo."
        echo "(On an installed tree there is no git pull to make unsafe; update is a manifest re-fetch.)"
        return 0
    fi
    local fail=0
    _uc_ok()   { printf '  \033[1;32m[ ok ]\033[0m %s\n' "$*"; }
    _uc_fail() { printf '  \033[1;31m[FAIL]\033[0m %s\n' "$*"; fail=1; }

    echo "claude-watchman release-readiness check (does the update story still hold?)"

    # 1. Pull-safety: every machine-specific artifact is gitignored.
    printf '\n1. Machine artifacts gitignored\n'
    local p
    for p in .env config/watchman.conf journal/findings.db journal/findings.db-wal \
             journal/findings.db-shm journal/network-baseline.txt journal/log-offsets.txt \
             journal/monitor-offsets.txt journal/monitor-state \
             journal/run-ledger.tsv journal/run.log journal/.write.lock .claude CLAUDE.md; do
        if git check-ignore -q "$p"; then _uc_ok "ignored: $p"
        else _uc_fail "NOT gitignored: $p — it could be committed or clobbered"; fi
    done

    # 2. No machine artifact is tracked.
    printf '\n2. No machine artifact tracked\n'
    local bad
    bad="$(git ls-files | grep -E '(^|/)(findings\.db|network-baseline\.txt|settings(\.local|\.fix|\.dev)?\.json|watchman\.conf)$|(^|/)\.env$' || true)"
    [[ -z "$bad" ]] && _uc_ok "no machine artifact is tracked" || _uc_fail "machine artifacts are tracked:"$'\n'"$bad"

    # 3. Manifest in lockstep with the product (no drift on feature submission).
    printf '\n3. Manifest completeness (manifest.txt ↔ tracked product)\n'
    if [[ -f manifest.txt ]]; then
        local expected manifested missing extra
        expected="$(git ls-files | grep -vE '^(\.gitignore|manifest\.txt)$' | sort -u)"
        manifested="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' manifest.txt | sed -E 's/^(keep|hook) //' | sort -u)"
        missing="$(comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$manifested"))"
        extra="$(comm -13 <(printf '%s\n' "$expected") <(printf '%s\n' "$manifested"))"
        if [[ -z "$missing" && -z "$extra" ]]; then
            _uc_ok "manifest.txt lists exactly the tracked product"
        else
            [[ -n "$missing" ]] && _uc_fail "in product but NOT in manifest.txt (won't ship to users):"$'\n'"$missing"
            [[ -n "$extra" ]]   && _uc_fail "in manifest.txt but not a tracked file (broken fetch):"$'\n'"$extra"
            printf '         fix: run '\''watchman update --sync'\'' to regenerate manifest.txt\n'
        fi
    else
        _uc_fail "manifest.txt is missing — the fetch list is gone"
    fi

    # 4. Every product SKILL.md carries the Prime Directive Preflight block.
    printf '\n4. Prime Directive present in every skill\n'
    local s missing_pd=0
    while IFS= read -r s; do
        grep -q 'PRIME DIRECTIVE (outranks everything below)' "$s" \
            || { _uc_fail "missing Prime Directive block: $s"; missing_pd=1; }
    done < <(find skills commands -name SKILL.md 2>/dev/null | sort)
    (( missing_pd == 0 )) && _uc_ok "all skills carry the Prime Directive block"

    # 5. Every observe/analyze skill is wired into the /watchman orchestration.
    printf '\n5. Orchestration wiring (observe/analyze skills in /watchman audit)\n'
    local cmd="commands/watchman/SKILL.md" d rel unwired=0
    if [[ -f "$cmd" ]]; then
        for d in skills/grammar/*/ skills/logic/*/; do
            [[ -f "${d}SKILL.md" ]] || continue
            rel="${d%/}"
            grep -qF "$rel" "$cmd" || { _uc_fail "not wired into $cmd: $rel"; unwired=1; }
        done
        (( unwired == 0 )) && _uc_ok "all observe/analyze skills wired into /watchman audit"
    else
        _uc_fail "$cmd is missing — the in-session command source is gone"
    fi

    # 6. Journal schema version in sync (journal.sh ↔ schema.sql).
    printf '\n6. Journal schema version sync\n'
    local jv sv
    jv="$(grep -oE 'JOURNAL_SCHEMA_VERSION=[0-9]+' lib/journal.sh 2>/dev/null | grep -oE '[0-9]+' | head -1)"
    sv="$(grep -oiE 'user_version[^0-9]*[0-9]+' journal/schema.sql 2>/dev/null | grep -oE '[0-9]+' | head -1)"
    if [[ -n "$jv" && "$jv" == "$sv" ]]; then _uc_ok "schema version in sync (v$jv)"
    else _uc_fail "schema version mismatch — lib/journal.sh=v${jv:-?} vs journal/schema.sql=v${sv:-?}"; fi

    printf '\n'
    if (( fail == 0 )); then
        echo "release-readiness: PASS — the update story holds; safe to commit."
        return 0
    else
        echo "release-readiness: FAIL — fix the above before committing this feature." >&2
        return 1
    fi
}
