-- =============================================================================
-- IoT Security Framework - Experiment Schema
-- =============================================================================
-- Adds research experiment storage without modifying existing tables.
-- Safe to run multiple times.
-- =============================================================================

SET timezone = 'UTC';

-- -----------------------------------------------------------------------------
-- experiments
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS experiments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    experiment_name     VARCHAR(255) NOT NULL,

    objective           TEXT,
    hypothesis          TEXT,
    methodology         TEXT,

    dataset_version     VARCHAR(32),
    model_version       VARCHAR(32),

    parameters          JSONB,

    start_date          TIMESTAMPTZ,
    end_date            TIMESTAMPTZ,

    status              VARCHAR(32),

    conclusion          TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- experiment_results
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS experiment_results (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    experiment_id       UUID NOT NULL
        REFERENCES experiments (id)
        ON DELETE CASCADE,

    metric_name         VARCHAR(64) NOT NULL,

    metric_value        NUMERIC(12, 6),

    model_name          VARCHAR(128),

    notes               TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- Indexes
-- -----------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_experiments_status
    ON experiments (status);

CREATE INDEX IF NOT EXISTS idx_experiments_created_at
    ON experiments (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_experiment_results_experiment_id
    ON experiment_results (experiment_id);

CREATE INDEX IF NOT EXISTS idx_experiment_results_metric_name
    ON experiment_results (metric_name);