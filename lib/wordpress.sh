#!/usr/bin/env bash
# lib/wordpress.sh — WordPress DISCOVERY engine (inventory, not remediation).
#
# > PRIME DIRECTIVE. wordpress_scan is READ-ONLY toward every site. It never writes to,
# > chmods, quarantines or deletes anything under a docroot, never runs wp-cli, never
# > touches a site database. The only file it writes is claude-watchman's OWN state file
# > journal/wp-uploads-baseline.txt, and only to CREATE a site's baseline the first time
# > that site is seen. An existing baseline is never changed by a scan, so a webshell
# > finding persists until the operator re-baselines with wordpress_rebaseline.
#
# > SECRETS. wp-config.php holds the site's database credentials. It is only ever tested
# > with `grep -q` for the PRESENCE of four constant NAMES in non-comment define() lines
# > (AUTOMATIC_UPDATER_DISABLED, WP_AUTO_UPDATE_CORE, DISALLOW_FILE_MODS,
# > DISALLOW_FILE_EDIT). No line, value or other content of the file is ever printed.
#
# > PRIVACY. Docroot paths carry Unix usernames and domain names, so no emitted field
# > ever contains one. A site is named by a stable, non-identifying label: "wp-" plus
# > the first 10 hex of sha256(canonical docroot). wordpress_sites maps labels back to
# > docroots for the OPERATOR; it is gated in lib/wm so the model cannot call it.
#
# Every finding is info / manual (discovery) EXCEPT wordpress_uploads_new_php: a
# PHP-executable file under wp-content/uploads that is new or changed against the
# baseline is security / high / manual (report only; nothing is ever removed).
#
# Overridable for fixtures: WATCHMAN_WP_DOCROOTS (read by webserver_docroots),
# WATCHMAN_WP_BASELINE, WATCHMAN_WP_NOTABLE_PLUGINS, WATCHMAN_WP_GATEWAY_PLUGINS,
# WATCHMAN_WP_UPLOADS_MAXDEPTH, WATCHMAN_WP_UPLOADS_MAX_FILES.

# Emit one finding-candidate (identical TSV to iwscan / cpscan):
#   category \t severity \t risk_tier \t check_id \t target \t title \t detail \t remediation
_wp_emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@"; }

_WP_NOTABLE_DEFAULT="code-snippets elementor elementor-pro the-plus-addons-for-elementor-page-builder wp-all-import-pro wp-all-export-pro wpai-woocommerce-add-on updraftplus wp-file-manager file-manager-advanced"
_WP_GATEWAYS_DEFAULT="woocommerce-gateway-stripe woocommerce-payments woocommerce-paypal-payments woocommerce-gateway-paypal-express-checkout woocommerce-square woocommerce-gateway-authorize-net-cim woocommerce-gateway-amazon-payments-advanced"
_WP_CONSTANTS="AUTOMATIC_UPDATER_DISABLED WP_AUTO_UPDATE_CORE DISALLOW_FILE_MODS DISALLOW_FILE_EDIT"
_WP_DISCOVERY_ONLY="None required: discovery only. claude-watchman reports this and changes nothing."

_wp_baseline_file() { printf '%s\n' "${WATCHMAN_WP_BASELINE:-${WATCHMAN_ROOT:-.}/journal/wp-uploads-baseline.txt}"; }

# Stable, non-identifying site label from a canonical docroot.
_wp_label() {
    local h; h="$(printf '%s' "$1" | sha256sum 2>/dev/null || true)"
    printf 'wp-%s\n' "${h:0:10}"
}

# Docroots that hold a WordPress install (wp-includes/version.php present), canonical.
_wp_docroots() {
    local d
    while IFS= read -r d; do
        [[ -n "$d" && -f "$d/wp-includes/version.php" ]] && printf '%s\n' "$d"
    done < <(webserver_docroots 2>/dev/null || true)
    return 0
}

# A plugin slug is a directory name a site owner (or an attacker) chose: only a plain
# lowercase slug is ever echoed.
_wp_slug_ok() { [[ "$1" =~ ^[a-z0-9._-]+$ && ${#1} -le 100 ]]; }

# A path relative to uploads, safe to show: plain characters only, bounded length.
_wp_relpath_ok() { [[ "$1" =~ ^[A-Za-z0-9._/-]+$ && ${#1} -le 200 ]]; }
_wp_label_ok() { [[ "$1" =~ ^wp-[0-9a-f]{10}$ ]]; }

# Bounded grep of a site-controlled file: only a regular file (so never a FIFO, device or
# /dev/zero symlink target), and only its first 1 MiB, so a hostile docroot cannot hang
# or balloon a scan. Usage: _wp_grep <file> <grep args...>; prints whatever grep prints.
_wp_grep() {
    local f="$1"; shift
    [[ -f "$f" ]] || return 1
    head -c 1048576 -- "$f" 2>/dev/null | grep "$@"
}

# wp-config.php location: the docroot, or (as WordPress itself allows) its parent.
_wp_config_path() {
    local d="$1"
    if [[ -f "$d/wp-config.php" ]]; then printf '%s\n' "$d/wp-config.php"
    elif [[ -f "$d/../wp-config.php" && ! -f "$d/../wp-settings.php" ]]; then printf '%s\n' "$d/../wp-config.php"
    fi
    return 0
}

# Walk uploads for PHP-executable files at the role's I/O priority under a timeout.
# Prints NUL-terminated records "size\tmtime\tsha256\tpathkey\trelpath", then a final
# "END" record only when the walk completed, or "CAP" when the file cap was hit. A walk
# killed by the timeout prints neither, so the caller can tell it is incomplete.
# pathkey = sha256(relpath), so a hostile file name never has to be stored or printed.
_wp_uploads_walk() {
    local up="$1"
    # No depth limit by default: a depth cap would let a webshell hide one level deeper.
    local maxd="${WATCHMAN_WP_UPLOADS_MAXDEPTH:-100000}" cap="${WATCHMAN_WP_UPLOADS_MAX_FILES:-5000}"
    [[ "$maxd" =~ ^[0-9]+$ ]] || maxd=100000
    [[ "$cap" =~ ^[0-9]+$ ]] || cap=5000
    local runner=()
    [[ "$(type -t io_run || true)" == function ]] && runner=(io_run)
    "${runner[@]}" bash -c '
        up=$1 maxd=$2 cap=$3 n=0 tab=$(printf "\t")
        while IFS= read -r -d "" rec; do
            n=$((n + 1))
            if (( n > cap )); then printf "CAP\0"; exit 0; fi
            sz=${rec%%"$tab"*}; rest=${rec#*"$tab"}
            mt=${rest%%"$tab"*}; f=${rest#*"$tab"}
            rel=${f#"$up"/}
            if [[ "$sz" == 0 ]]; then
                h=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            else
                h=$(sha256sum < "$f" 2>/dev/null) || h=unreadable; h=${h:0:64}
            fi
            k=$(printf "%s" "$rel" | sha256sum); k=${k:0:64}
            printf "%s\t%s\t%s\t%s\t%s\0" "$sz" "${mt%%.*}" "$h" "$k" "$rel"
        done < <(find "$up" -maxdepth "$maxd" -type f \
                    \( -iname "*.php" -o -iname "*.phtml" -o -iname "*.php[3-8]" -o -iname "*.phar" \) \
                    -printf "%s\t%T@\t%p\0" 2>/dev/null)
        printf "END\0"
    ' _ "$up" "$maxd" "$cap" 2>/dev/null || true
}

# Read a walk into the caller's arrays: W_SZ W_SHA W_REL keyed by pathkey (exempt empty
# index.php guards are dropped), and sets W_STATE (END|CAP|INCOMPLETE), W_TOTAL (every
# PHP file seen, guards included), W_NEWEST (newest mtime, epoch).
# Exemption: a file named exactly index.php with 0 bytes executes nothing. WP All
# Import/Export and Elementor create such guards in fresh dirs on every run, so they are
# neither baselined nor alerted on; one that later gains content is caught as new.
_wp_read_walk() {
    local up="$1" rec sz mt h k rel
    W_STATE=INCOMPLETE; W_TOTAL=0; W_NEWEST=0
    while IFS= read -r -d '' rec; do
        case "$rec" in END|CAP) W_STATE="$rec"; continue ;; esac
        IFS=$'\t' read -r sz mt h k rel <<<"$rec" || true
        rel="${rec#*$'\t'*$'\t'*$'\t'*$'\t'}"
        [[ "$sz" =~ ^[0-9]+$ && "$mt" =~ ^[0-9]+$ && "$k" =~ ^[0-9a-f]{64}$ ]] || continue
        W_TOTAL=$((W_TOTAL + 1))
        (( mt > W_NEWEST )) && W_NEWEST="$mt"
        [[ "${rel##*/}" == index.php && "$sz" == 0 ]] && continue
        W_SZ[$k]="$sz"; W_SHA[$k]="$h"; W_REL[$k]="$rel"
    done < <(_wp_uploads_walk "$up")
    return 0
}

# Baseline rows for one label: "label\tpathkey\tsize\tsha256\tdisplay-path", plus one
# marker row "label\t#baseline\t<count>\t<YYYY-MM-DD>\t-" that says the baseline exists
# (a site whose uploads hold only exempt guards still has a baseline: zero files).
_wp_baseline_has() {
    local f; f="$(_wp_baseline_file)"
    [[ -r "$f" ]] && grep -qF -- "$1"$'\t#baseline\t' "$f" 2>/dev/null
}

# Write a fresh baseline for $1 (label) from W_* arrays, keeping every OTHER label's rows.
# Atomic: temp file beside the baseline, then mv. Never touches a docroot.
_wp_baseline_write() {
    local label="$1" f dir tmp k shown
    _wp_label_ok "$label" || return 1
    f="$(_wp_baseline_file)"; dir="$(dirname "$f")"
    [[ -d "$dir" && -w "$dir" ]] || return 1
    tmp="$(mktemp "$f.XXXXXX" 2>/dev/null)" || return 1
    {
        [[ -r "$f" ]] && { awk -F'\t' -v l="$label" '$1 != l' "$f" 2>/dev/null || true; }
        printf '%s\t#baseline\t%s\t%s\t-\n' "$label" "${#W_SZ[@]}" "$(date +%F)"
        for k in "${!W_SZ[@]}"; do
            shown="${W_REL[$k]}"; _wp_relpath_ok "$shown" || shown="-"
            printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$k" "${W_SZ[$k]}" "${W_SHA[$k]}" "$shown"
        done
    } > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$f" 2>/dev/null || { rm -f "$tmp"; return 1; }
}

# --- per-site inventory -------------------------------------------------------
_wp_scan_site() {
    local d="$1" label="$2" defer="$3"
    local wpc="$d/wp-content" plugins="$d/wp-content/plugins" up="$d/wp-content/uploads"

    # 1. Core version: only a dotted number is ever emitted.
    local ver
    ver="$( { _wp_grep "$d/wp-includes/version.php" -m1 -E '^[[:space:]]*\$wp_version[[:space:]]*=' 2>/dev/null || true; } \
            | sed -nE "s/^[^=]*=[[:space:]]*['\"]([0-9.]+)['\"].*/\1/p" | head -1)"
    [[ "$ver" =~ ^[0-9.]+$ && ${#ver} -le 20 ]] || ver=unknown
    _wp_emit config info manual wordpress_core_version "$label" \
        "WordPress core $ver ($label)" \
        "Site $label runs WordPress core $ver (read from wp-includes/version.php). Track it against WordPress security releases." \
        "$_WP_DISCOVERY_ONLY"

    # 2. wp-config.php constants: names only, via grep -q, non-comment define() lines.
    local cfg name present="" absent=""
    cfg="$(_wp_config_path "$d")"
    if [[ -n "$cfg" ]]; then
        for name in $_WP_CONSTANTS; do
            if _wp_grep "$cfg" -qE "^[[:space:]]*define[[:space:]]*\([[:space:]]*['\"]${name}['\"]" 2>/dev/null; then
                present="${present:+$present, }$name"
            else
                absent="${absent:+$absent, }$name"
            fi
        done
        local meaning=""
        [[ "$absent" == *WP_AUTO_UPDATE_CORE* && "$absent" == *AUTOMATIC_UPDATER_DISABLED* ]] \
            && meaning+=" Core minor and security releases auto-update by default."
        [[ "$present" == *AUTOMATIC_UPDATER_DISABLED* ]] \
            && meaning+=" AUTOMATIC_UPDATER_DISABLED is defined: if it is true, every automatic update, security releases included, is off."
        [[ "$present" == *WP_AUTO_UPDATE_CORE* ]] \
            && meaning+=" WP_AUTO_UPDATE_CORE is defined, so the core auto-update policy is set explicitly (the value is not read)."
        if [[ "$absent" == *DISALLOW_FILE_MODS* && "$absent" == *DISALLOW_FILE_EDIT* ]]; then
            meaning+=" The admin plugin/theme file editor is ENABLED and admins can install plugins and themes, so a stolen admin login can run arbitrary PHP."
        elif [[ "$present" == *DISALLOW_FILE_MODS* ]]; then
            meaning+=" DISALLOW_FILE_MODS is defined: if true, the file editor and plugin/theme installs and updates from the admin are off."
        else
            meaning+=" DISALLOW_FILE_EDIT is defined: if true, the admin file editor is off (plugin/theme installs still allowed)."
        fi
        _wp_emit config info manual wordpress_config_constants "$label" \
            "wp-config update/edit constants: ${present:-none} defined ($label)" \
            "Defined in non-comment define() lines: ${present:-none}. Not defined: ${absent:-none}. Values are never read (the file holds database credentials).${meaning} Plugin and theme auto-update choices live in the database and are not checked." \
            "$_WP_DISCOVERY_ONLY"
    else
        _wp_emit config info manual wordpress_config_constants "$label" \
            "wp-config.php not found beside the docroot ($label)" \
            "No wp-config.php in the docroot or its parent, so the update/edit constants could not be checked." \
            "$_WP_DISCOVERY_ONLY"
    fi

    # 3. Plugins: count, notable slugs present, likely-custom count (heuristic).
    local -A have=()
    local p slug total=0 odd=0 custom=0
    if [[ -d "$plugins" ]]; then
        for p in "$plugins"/*/; do
            [[ -d "$p" ]] || continue
            slug="${p%/}"; slug="${slug##*/}"
            if ! _wp_slug_ok "$slug"; then odd=$((odd + 1)); continue; fi
            total=$((total + 1)); have[$slug]=1
            _wp_grep "$p/readme.txt" -qi 'Stable tag:' 2>/dev/null || custom=$((custom + 1))
        done
        local notable="" n
        for n in ${WATCHMAN_WP_NOTABLE_PLUGINS:-$_WP_NOTABLE_DEFAULT}; do
            _wp_slug_ok "$n" && [[ -n "${have[$n]:-}" ]] && notable="${notable:+$notable, }$n"
        done
        local oddnote=""
        (( odd > 0 )) && oddnote=" $odd plugin directory name(s) contain unusual characters and are not shown (worth a manual look)."
        _wp_emit config info manual wordpress_plugins "$label" \
            "$total plugin(s), notable: ${notable:-none} ($label)" \
            "Site $label has $total plugin directories. Notable or high-risk plugins present: ${notable:-none} (frequent-CVE surface, arbitrary-PHP or file import/export features, or backups that can hold database dumps). $custom plugin(s) look custom (heuristic: no readme.txt with a 'Stable tag:' line, so likely no wordpress.org update channel).${oddnote}" \
            "$_WP_DISCOVERY_ONLY Track CVEs for the notable plugins listed."
    fi

    # 4. Payment surface.
    local gw="" g
    for g in ${WATCHMAN_WP_GATEWAY_PLUGINS:-$_WP_GATEWAYS_DEFAULT}; do
        _wp_slug_ok "$g" && [[ -n "${have[$g]:-}" ]] && gw="${gw:+$gw, }$g"
    done
    if [[ -n "${have[woocommerce]:-}" || -n "$gw" ]]; then
        _wp_emit security info manual wordpress_payment_surface "$label" \
            "Payment surface: WooCommerce$([[ -n "$gw" ]] && printf ' with %s' "$gw") ($label)" \
            "Site $label is a store (WooCommerce present: $([[ -n "${have[woocommerce]:-}" ]] && echo yes || echo no); known gateway plugins: ${gw:-none}). It is PCI-relevant: checkout pages and the plugins that touch them warrant extra care and prompt patching." \
            "$_WP_DISCOVERY_ONLY"
    fi

    # 5. Wordfence WAF mode. grep -q only.
    local prepend=no mode
    if _wp_grep "$d/.user.ini" -qE '^[[:space:]]*auto_prepend_file[[:space:]]*=.*wordfence-waf\.php' 2>/dev/null \
       || _wp_grep "$d/php.ini" -qE '^[[:space:]]*auto_prepend_file[[:space:]]*=.*wordfence-waf\.php' 2>/dev/null \
       || _wp_grep "$d/.htaccess" -qiE '^[[:space:]]*php_value[[:space:]]+auto_prepend_file[[:space:]].*wordfence-waf\.php' 2>/dev/null; then
        prepend=yes
    fi
    if [[ -n "${have[wordfence]:-}" && "$prepend" == yes ]]; then
        mode="extended protection (WAF loads via auto_prepend_file before WordPress)"
    elif [[ -n "${have[wordfence]:-}" ]]; then
        mode="plugin-level only (no auto_prepend_file in the docroot .user.ini/php.ini/.htaccess, so the WAF starts after WordPress and plugins load)"
    elif [[ "$prepend" == yes ]]; then
        mode="auto_prepend_file points at wordfence-waf.php but the wordfence plugin directory is absent"
    else
        mode="absent (no wordfence plugin)"
    fi
    _wp_emit security info manual wordpress_wordfence_waf "$label" \
        "Wordfence WAF: ${mode%% (*} ($label)" \
        "Wordfence WAF on site $label: $mode." \
        "$_WP_DISCOVERY_ONLY"

    # 6. Exposure: xmlrpc.php and readme.html.
    local exp=""
    [[ -f "$d/xmlrpc.php" ]] && exp="xmlrpc.php (brute-force and pingback surface)"
    [[ -f "$d/readme.html" ]] && exp="${exp:+$exp; }readme.html (discloses the WordPress version)"
    if [[ -n "$exp" ]]; then
        _wp_emit security info manual wordpress_exposure "$label" \
            "Exposed WordPress endpoints present ($label)" \
            "Present in the docroot of site $label: $exp. Watch POST rates to xmlrpc.php and wp-login.php in the site access logs." \
            "$_WP_DISCOVERY_ONLY"
    fi

    # 7. Uploads: PHP blocking, PHP count + newest mtime, and the webshell baseline.
    [[ -d "$up" ]] || return 0
    local ht="absent"
    if [[ -f "$up/.htaccess" ]]; then
        if _wp_grep "$up/.htaccess" -qiE 'php_flag[[:space:]]+engine[[:space:]]+off|Remove(Handler|Type)[[:space:]].*php|<Files(Match)?[^>]*php' 2>/dev/null; then
            ht="present and appears to block PHP (heuristic)"
        else
            ht="present but no PHP-blocking rule recognized"
        fi
    fi
    [[ "$defer" == yes ]] && {
        _wp_emit security info manual wordpress_uploads_php "$label" \
            "Uploads PHP check deferred this pass ($label)" \
            "uploads/.htaccess: $ht. The uploads walk was skipped this pass because the host is under I/O pressure (see the diagnostic_deferred finding)." \
            "$_WP_DISCOVERY_ONLY"
        return 0
    }

    local -A W_SZ=() W_SHA=() W_REL=()
    local W_STATE W_TOTAL W_NEWEST
    _wp_read_walk "$up"
    if [[ "$W_STATE" == CAP ]]; then
        # Hitting the PHP-file cap is itself suspicious (the walk counts only PHP-executable
        # files) and must not hide a webshell: say so loudly, then still compare every file
        # that WAS seen against an existing baseline. No baseline is created from a partial walk.
        _wp_emit security high manual wordpress_uploads_php_flood "$label" \
            "Uploads holds more PHP files than the scan cap ($label)" \
            "wp-content/uploads of site $label holds more than ${WATCHMAN_WP_UPLOADS_MAX_FILES:-5000} PHP-executable files, the scan cap. Legitimate sites keep almost no PHP in uploads, so a flood of PHP there is either an unusual plugin or an attempt to bury a webshell past the scan. Files beyond the cap were not compared." \
            "Report only. From your own shell, count and inspect PHP under that site's uploads (map the label with wordpress_sites); raise WATCHMAN_WP_UPLOADS_MAX_FILES only once you know why the files are there."
        _wp_baseline_has "$label" || return 0
    elif [[ "$W_STATE" != END ]]; then
        _wp_emit capacity info manual wordpress_uploads_walk_incomplete "$label" \
            "Uploads walk incomplete for $label" \
            "The walk of wp-content/uploads for site $label timed out or failed (WATCHMAN_IO_TIMEOUT), so the PHP count and the webshell comparison were skipped this pass. No baseline is created from a partial walk." \
            "Raise WATCHMAN_WP_UPLOADS_MAX_FILES or WATCHMAN_IO_TIMEOUT if this persists."
        return 0
    fi
    if [[ "$W_STATE" == END ]]; then
    local newest="none"
    (( W_NEWEST > 0 )) && newest="$(date -d "@$W_NEWEST" +%F 2>/dev/null || echo unknown)"
    _wp_emit security info manual wordpress_uploads_php "$label" \
        "$W_TOTAL PHP file(s) under uploads ($label)" \
        "wp-content/uploads of site $label holds $W_TOTAL PHP-executable file(s) (.php, .phtml, .php3-8, .phar), newest modified $newest. uploads/.htaccess: $ht. PHP has no business in uploads; empty index.php guards are normal." \
        "$_WP_DISCOVERY_ONLY"

    if ! _wp_baseline_has "$label"; then
        if _wp_baseline_write "$label"; then
            _wp_emit security info manual wordpress_uploads_baseline "$label" \
                "Uploads PHP baseline established ($label)" \
                "First sight of site $label: recorded ${#W_SZ[@]} PHP file(s) under uploads (size and sha256) as the baseline, excluding empty index.php guards. From now on a new or changed PHP file there raises a high finding." \
                "$_WP_DISCOVERY_ONLY Re-baselining is an operator action, run from your own shell outside a Claude session (see the inspect-wordpress skill)."
        fi
        return 0
    fi
    fi   # END: count + first-sight baseline; a CAP walk with a baseline falls through to compare

    # Compare against the baseline. Unsafe names count but are never printed.
    local -A B=()
    local bl bk bsz bsha
    while IFS=$'\t' read -r bl bk bsz bsha _; do
        [[ "$bl" == "$label" && "$bk" =~ ^[0-9a-f]{64}$ ]] && B[$bk]="$bsz $bsha"
    done < "$(_wp_baseline_file)"
    local k hits=0 shown=0 list="" withheld=0 why
    # Sorted by display path so the finding text is stable run to run.
    for k in $(for k in "${!W_SZ[@]}"; do printf '%s\t%s\n' "${W_REL[$k]//[$'\t\n']/_}" "$k"; done | LC_ALL=C sort | cut -f2); do
        if [[ -z "${B[$k]:-}" ]]; then why=new
        elif [[ "${B[$k]}" != "${W_SZ[$k]} ${W_SHA[$k]}" ]]; then why=changed
        else continue; fi
        hits=$((hits + 1))
        if _wp_relpath_ok "${W_REL[$k]}"; then
            (( shown < 5 )) && { list="${list:+$list, }${W_REL[$k]} ($why, ${W_SZ[$k]} bytes)"; shown=$((shown + 1)); }
        else
            withheld=$((withheld + 1))
        fi
    done
    if (( hits > 0 )); then
        local wnote=""
        (( withheld > 0 )) && wnote=" $withheld of them have file names with unusual characters and are not shown."
        _wp_emit security high manual wordpress_uploads_new_php "$label" \
            "$hits new or changed PHP file(s) under uploads ($label)" \
            "Against the baseline, site $label has $hits PHP file(s) under wp-content/uploads that are new or whose size/hash changed: ${list:-none shown}.${wnote} A non-empty or unfamiliar PHP file in uploads is a strong webshell signal." \
            "Report only: claude-watchman does not delete, quarantine or chmod anything. From your own shell, outside a Claude session (the label-to-site map prints usernames and domains): map the label to its docroot with wordpress_sites, inspect the files by hand, check the site access logs for requests to them, and if benign re-baseline the site with wordpress_rebaseline $label (both via WM_APPLY=1 bash lib/wm)."
    fi
    return 0
}

# wordpress_scan — read every WordPress docroot, emit finding-candidates. Self-gating: no
# WordPress docroot, no output. Safe under set -euo pipefail.
wordpress_scan() {
    local roots d defer=no
    roots="$(_wp_docroots)"
    [[ -n "$roots" ]] || return 0
    if [[ "$(type -t io_should_defer_heavy || true)" == function ]] && io_should_defer_heavy; then
        defer=yes
        local why=""
        [[ "$(type -t io_pressure_reason || true)" == function ]] && why="$(io_pressure_reason 2>/dev/null || true)"
        _wp_emit capacity info safe diagnostic_deferred inspect-wordpress \
            "WordPress uploads walk deferred (host under pressure)" \
            "deferred: ${why:-host under I/O pressure}. The inventory ran; the uploads PHP walk and webshell comparison will run on a quieter pass." \
            "None: it runs again next pass."
    fi
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        _wp_scan_site "$d" "$(_wp_label "$d")" "$defer"
    done <<<"$roots"
    return 0
}

# wordpress_sites — OPERATOR ONLY: "label<TAB>docroot" so a finding's label can be mapped
# back to a site. Read-only, but it prints usernames and domains, so lib/wm gates it like
# a mutator (WM_APPLY=1) and no skill calls it.
wordpress_sites() {
    local d
    while IFS= read -r d; do
        [[ -n "$d" ]] && printf '%s\t%s\n' "$(_wp_label "$d")" "$d"
    done < <(_wp_docroots)
    return 0
}

# wordpress_rebaseline <label> — OPERATOR ONLY: replace one site's uploads baseline with
# the current state, after the operator has reviewed a wordpress_uploads_new_php finding.
# Writes only claude-watchman's own journal/wp-uploads-baseline.txt (atomic), never a
# docroot. It overwrites the evidence a high finding rests on, so lib/wm lists it in
# _WM_MUTATORS: the unattended loop cannot call it.
wordpress_rebaseline() {
    local want="${1:-}" d found=""
    [[ "$want" =~ ^wp-[0-9a-f]{10}$ ]] || { echo "wordpress_rebaseline: usage: wordpress_rebaseline wp-<10 hex>" >&2; return 2; }
    while IFS= read -r d; do
        [[ -n "$d" && "$(_wp_label "$d")" == "$want" ]] && found="$d"
    done < <(_wp_docroots)
    [[ -n "$found" ]] || { echo "wordpress_rebaseline: no WordPress docroot has label $want" >&2; return 1; }
    [[ -d "$found/wp-content/uploads" ]] || { echo "wordpress_rebaseline: $want has no uploads directory" >&2; return 1; }
    local -A W_SZ=() W_SHA=() W_REL=()
    local W_STATE W_TOTAL W_NEWEST
    _wp_read_walk "$found/wp-content/uploads"
    [[ "$W_STATE" == END ]] || { echo "wordpress_rebaseline: uploads walk incomplete ($W_STATE); baseline left unchanged" >&2; return 1; }
    _wp_baseline_write "$want" || { echo "wordpress_rebaseline: could not write $(_wp_baseline_file)" >&2; return 1; }
    echo "wordpress_rebaseline: $want re-baselined (${#W_SZ[@]} PHP file(s), empty index.php guards excluded)"
}
