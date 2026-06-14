-- claude-watchman journal schema
-- Version-controlled. The authoritative shape of findings.db.
--
-- This file is applied by lib/journal.sh, the ONLY code permitted to touch
-- findings.db. Do not open the database from any other script. Lossy migrations
-- of this schema are a destructive database operation and fall under the Prime
-- Directive: journal.sh must back up findings.db and obtain operator confirmation
-- before applying them. Additive, lossless changes may proceed automatically.

-- schema_version lets journal.sh decide whether a migration is needed and
-- whether it is additive (safe) or lossy (gated). Bump it when this file changes.
PRAGMA user_version = 1;

-- ---------------------------------------------------------------------------
-- findings: the single source of truth for what is wrong, fixed, or ignored.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Stable dedup key: hash(family + profile + category + check_id + target).
    -- The same conceptual problem on different families/profiles is a DIFFERENT
    -- finding (different remediation/urgency), so it must NOT collide. Enforced
    -- UNIQUE so create-or-update is an upsert, never a duplicate insert.
    fingerprint     TEXT    NOT NULL UNIQUE,

    -- Components that compose the fingerprint, stored for querying/explanation.
    family          TEXT    NOT NULL,                 -- debian | rhel | arch
    profile         TEXT    NOT NULL,                 -- server | workstation
    check_id        TEXT    NOT NULL,                 -- stable id of the producing check
    target          TEXT    NOT NULL DEFAULT '',      -- what the finding is about (path, port, unit, '')

    category        TEXT    NOT NULL                  -- security | capacity | config | integrity
                    CHECK (category IN ('security','capacity','config','integrity')),
    severity        TEXT    NOT NULL                  -- info | low | medium | high | critical
                    CHECK (severity IN ('info','low','medium','high','critical')),
    risk_tier       TEXT    NOT NULL DEFAULT 'manual' -- safe | review | manual  (governs the fixer)
                    CHECK (risk_tier IN ('safe','review','manual')),

    title           TEXT    NOT NULL,                 -- short human-readable name
    detail          TEXT    NOT NULL DEFAULT '',      -- what was found and why it matters
    remediation     TEXT    NOT NULL DEFAULT '',      -- the suggested fix

    status          TEXT    NOT NULL DEFAULT 'open'   -- open | in-review | fixed | ignored | regressed
                    CHECK (status IN ('open','in-review','fixed','ignored','regressed')),

    discovered_at   TEXT    NOT NULL DEFAULT (datetime('now')),  -- first seen
    last_seen_at    TEXT    NOT NULL DEFAULT (datetime('now')),  -- most recent confirming audit
    fix_applied_at  TEXT,                                        -- when the fixer acted, if it did
    notes           TEXT    NOT NULL DEFAULT ''                  -- operator notes
);

CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);

-- ---------------------------------------------------------------------------
-- metrics: trackable numbers over time (e.g. the Lynis hardening index).
-- Append-only time series; the loop uses it to chart drift, not to dedupe.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS metrics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,                 -- e.g. 'lynis_hardening_index'
    value       REAL    NOT NULL,
    recorded_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(name, recorded_at);

-- ---------------------------------------------------------------------------
-- runs: one row per observe pass, so correlate-findings can compute deltas
-- against the previous run and the loop can decide whether to email.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL DEFAULT 'audit', -- audit | loop | fix | report
    started_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    summary     TEXT    NOT NULL DEFAULT ''       -- short human note of what changed
);
