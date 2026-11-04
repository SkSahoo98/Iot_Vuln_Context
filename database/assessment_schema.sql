-- =============================================================================
-- IoT Security Framework - Assessment Schema (Phase 1)
-- =============================================================================
-- Stores evidence-driven security assessment history:
--   assessment_runs      one row per assessment of one allowlisted target
--   assessment_evidence  raw observations (Nmap, MQTT, HTTP, TLS probes)
--   assessment_findings  deterministic findings, each linked to evidence
--   risk_snapshots       IoT-RISK-v1 results calculated for the findings
--
-- Safety:
--   - Additive only: CREATE ... IF NOT EXISTS, no DROP, no ALTER of existing
--     devices / sensor_data / experiments / experiment_results tables.
--   - Not managed by Alembic. Do NOT run Alembic against this database.
--   - Safe to run multiple times.
--
-- Apply:
--   psql -U postgres -d iot_security -f database/assessment_schema.sql
--   or: python backend/scripts/apply_assessment_schema.py
-- =============================================================================

SET timezone = 'UTC';

-- -----------------------------------------------------------------------------
-- assessment_runs
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assessment_runs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Single allowlisted IP literal (never a CIDR range)
    target              VARCHAR(255) NOT NULL,

    assessment_type     VARCHAR(64)  NOT NULL DEFAULT 'MULTI_LAYER',

    status              VARCHAR(16)  NOT NULL DEFAULT 'RUNNING',

    started_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,

    -- Why the run is INCOMPLETE or FAILED (human readable)
    error_summary       TEXT,

    -- Scan parameters actually used (port list, timeouts, tool versions)
    metadata            JSONB        NOT NULL DEFAULT '{}'::jsonb,

    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_assessment_runs_status
        CHECK (status IN ('RUNNING', 'COMPLETE', 'INCOMPLETE', 'FAILED'))
);

CREATE INDEX IF NOT EXISTS idx_assessment_runs_target
    ON assessment_runs (target);

CREATE INDEX IF NOT EXISTS idx_assessment_runs_started_at
    ON assessment_runs (started_at DESC);

-- -----------------------------------------------------------------------------
-- assessment_evidence
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assessment_evidence (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    assessment_id       UUID         NOT NULL
        REFERENCES assessment_runs (id)
        ON DELETE CASCADE,

    target              VARCHAR(255) NOT NULL,
    port                INTEGER,

    -- What was checked, e.g. NMAP_SCAN, NMAP_PORT, MQTT_ANONYMOUS_CONNECT,
    -- MQTT_TLS_LISTENER, HTTP_RESPONSE, TLS_HANDSHAKE
    check_type          VARCHAR(64)  NOT NULL,

    -- Outcome of the check, e.g. OPEN, ACCEPTED, REJECTED, REFUSED, TIMEOUT
    result              VARCHAR(32)  NOT NULL,

    evidence_source     VARCHAR(32)  NOT NULL,

    -- Structured raw observation (never fabricated; tool output only)
    observation         JSONB        NOT NULL DEFAULT '{}'::jsonb,

    observed_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_assessment_evidence_source
        CHECK (evidence_source IN (
            'ACTIVE_PROBE', 'NMAP', 'HTTP_PROBE', 'TLS_PROBE',
            'MQTT_PROBE', 'DATABASE', 'CONFIGURATION'
        )),
    CONSTRAINT ck_assessment_evidence_port
        CHECK (port IS NULL OR (port BETWEEN 1 AND 65535))
);

CREATE INDEX IF NOT EXISTS idx_assessment_evidence_assessment_id
    ON assessment_evidence (assessment_id);

-- -----------------------------------------------------------------------------
-- assessment_findings
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assessment_findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    assessment_id       UUID         NOT NULL
        REFERENCES assessment_runs (id)
        ON DELETE CASCADE,

    -- Stable check ID from scanner/catalog.py, e.g. IOT-MQTT-01, NET-03
    finding_id          VARCHAR(32)  NOT NULL,
    finding_type        VARCHAR(64)  NOT NULL,
    category            VARCHAR(32)  NOT NULL,

    title               VARCHAR(255) NOT NULL,
    severity            VARCHAR(16)  NOT NULL,
    confidence          NUMERIC(4, 3),

    description         TEXT,

    target              VARCHAR(255) NOT NULL,
    port                INTEGER,

    -- The observation that justifies this finding
    evidence_reference  UUID
        REFERENCES assessment_evidence (id)
        ON DELETE SET NULL,

    remediation         TEXT,

    status              VARCHAR(16)  NOT NULL DEFAULT 'OPEN',

    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_assessment_findings_severity
        CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

CREATE INDEX IF NOT EXISTS idx_assessment_findings_assessment_id
    ON assessment_findings (assessment_id);

CREATE INDEX IF NOT EXISTS idx_assessment_findings_finding_id
    ON assessment_findings (finding_id);

-- -----------------------------------------------------------------------------
-- risk_snapshots
-- One row per risk-scored finding (finding_ref set) plus one overall row
-- (finding_ref NULL) holding the highest finding score of the run.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_snapshots (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    assessment_id         UUID         NOT NULL
        REFERENCES assessment_runs (id)
        ON DELETE CASCADE,

    finding_ref           UUID
        REFERENCES assessment_findings (id)
        ON DELETE CASCADE,

    score                 NUMERIC(5, 2) NOT NULL,
    risk_level            VARCHAR(16)  NOT NULL,
    score_version         VARCHAR(32)  NOT NULL,

    base_severity         VARCHAR(16),
    context_score         NUMERIC(6, 4),

    factor_contributions  JSONB        NOT NULL DEFAULT '{}'::jsonb,

    -- Where each context factor value came from (OBSERVED / CONFIGURATION /
    -- NOT_ASSESSED) so the score is auditable.
    context_inputs        JSONB        NOT NULL DEFAULT '{}'::jsonb,

    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_risk_snapshots_score
        CHECK (score >= 0 AND score <= 100)
);

CREATE INDEX IF NOT EXISTS idx_risk_snapshots_assessment_id
    ON risk_snapshots (assessment_id);

-- -----------------------------------------------------------------------------
-- remediation_workflows
-- Tracks the remediation and verification lifecycle for individual findings.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remediation_workflows (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    baseline_assessment_id      UUID         NOT NULL
        REFERENCES assessment_runs (id)
        ON DELETE CASCADE,

    baseline_finding_id         UUID         NOT NULL
        REFERENCES assessment_findings (id)
        ON DELETE CASCADE,

    finding_fingerprint         VARCHAR(255) NOT NULL,
    target                      VARCHAR(255) NOT NULL,

    status                      VARCHAR(32)  NOT NULL DEFAULT 'OPEN',
    guidance_version            VARCHAR(32)  NOT NULL DEFAULT '1.0',

    user_confirmed_at           TIMESTAMPTZ,

    verification_assessment_id  UUID
        REFERENCES assessment_runs (id)
        ON DELETE SET NULL,

    verification_verdict        VARCHAR(32),
    verdict_rationale           TEXT,
    coverage_summary            JSONB        NOT NULL DEFAULT '{}'::jsonb,

    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_remediation_status
        CHECK (status IN (
            'OPEN', 'GUIDANCE_VIEWED', 'REMEDIATION_IN_PROGRESS',
            'READY_FOR_VERIFICATION', 'VERIFICATION_PENDING',
            'VERIFIED_RESOLVED', 'PARTIALLY_RESOLVED', 'STILL_PRESENT',
            'VERIFICATION_FAILED', 'INCONCLUSIVE'
        )),
    CONSTRAINT ck_remediation_verdict
        CHECK (verification_verdict IS NULL OR verification_verdict IN (
            'VERIFIED_RESOLVED', 'PARTIALLY_RESOLVED', 'STILL_PRESENT',
            'VERIFICATION_FAILED', 'INCONCLUSIVE'
        ))
);

CREATE INDEX IF NOT EXISTS idx_remediation_baseline_finding_id
    ON remediation_workflows (baseline_finding_id);

CREATE INDEX IF NOT EXISTS idx_remediation_baseline_assessment_id
    ON remediation_workflows (baseline_assessment_id);

CREATE INDEX IF NOT EXISTS idx_remediation_fingerprint
    ON remediation_workflows (finding_fingerprint);

-- -----------------------------------------------------------------------------
-- remediation_verifications
-- Immutable audit log of each verification attempt run for a workflow.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remediation_verifications (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    workflow_id                 UUID         NOT NULL
        REFERENCES remediation_workflows (id)
        ON DELETE CASCADE,

    verification_assessment_id  UUID         NOT NULL
        REFERENCES assessment_runs (id)
        ON DELETE CASCADE,

    verdict                     VARCHAR(32)  NOT NULL,
    verdict_rationale           TEXT,
    coverage_equivalent         BOOLEAN      NOT NULL DEFAULT FALSE,
    baseline_finding_present    BOOLEAN      NOT NULL DEFAULT FALSE,
    evidence_references         JSONB        NOT NULL DEFAULT '[]'::jsonb,
    risk_delta                  JSONB,

    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_rem_verif_verdict
        CHECK (verdict IN (
            'VERIFIED_RESOLVED', 'PARTIALLY_RESOLVED', 'STILL_PRESENT',
            'VERIFICATION_FAILED', 'INCONCLUSIVE'
        ))
);

CREATE INDEX IF NOT EXISTS idx_rem_verif_workflow_id
    ON remediation_verifications (workflow_id);
