CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS programs (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    scope_reference TEXT NOT NULL,
    policy_reference TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scopes (
    id UUID PRIMARY KEY,
    program_id UUID NOT NULL REFERENCES programs(id),
    version INTEGER NOT NULL,
    definition JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(program_id, version)
);

CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY,
    program_id UUID NOT NULL REFERENCES programs(id),
    version INTEGER NOT NULL,
    definition JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(program_id, version)
);

CREATE TABLE IF NOT EXISTS workflow_definitions (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    definition JSONB NOT NULL,
    default_policy_requirements JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY,
    program_id UUID NOT NULL REFERENCES programs(id),
    objective TEXT NOT NULL,
    workflow_definition_id UUID NOT NULL REFERENCES workflow_definitions(id),
    status TEXT NOT NULL CHECK (status IN ('pending','running','paused','completed','failed','cancelled')),
    requested_by TEXT NOT NULL,
    schedule_reference TEXT,
    cancelled_at TIMESTAMPTZ,
    cancellation_reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workflow_runs (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL REFERENCES tasks(id),
    workflow_definition_id UUID NOT NULL REFERENCES workflow_definitions(id),
    workflow_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','running','paused','completed','failed','cancelled')),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    previous_run_id UUID REFERENCES workflow_runs(id),
    trigger_source TEXT NOT NULL,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS step_runs (
    id UUID PRIMARY KEY,
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id),
    step_definition_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','blocked','awaiting_approval','queued','running','succeeded','failed','retryable','skipped','cancelled')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    input JSONB NOT NULL DEFAULT '{}'::jsonb,
    output JSONB,
    error_classification TEXT NOT NULL DEFAULT '',
    error_details TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    idempotency_key TEXT NOT NULL,
    approval_state TEXT NOT NULL DEFAULT 'not_required',
    UNIQUE(workflow_run_id, step_definition_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id UUID PRIMARY KEY,
    step_run_id UUID NOT NULL REFERENCES step_runs(id),
    capability TEXT NOT NULL,
    provider TEXT NOT NULL,
    tool_version TEXT NOT NULL DEFAULT '',
    sanitized_arguments JSONB NOT NULL DEFAULT '{}'::jsonb,
    execution_environment JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    exit_code INTEGER,
    timed_out BOOLEAN NOT NULL DEFAULT false,
    stdout_artifact_id UUID,
    stderr_artifact_id UUID
);

CREATE TABLE IF NOT EXISTS artifacts (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL REFERENCES tasks(id),
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id),
    step_run_id UUID NOT NULL REFERENCES step_runs(id),
    tool_run_id UUID NOT NULL REFERENCES tool_runs(id),
    type TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size BIGINT NOT NULL CHECK (size >= 0),
    sha256 TEXT NOT NULL,
    storage_location TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    redaction_state TEXT NOT NULL,
    sensitive BOOLEAN NOT NULL DEFAULT false
);
ALTER TABLE tool_runs DROP CONSTRAINT IF EXISTS tool_runs_stdout_artifact_id_fkey;
ALTER TABLE tool_runs ADD CONSTRAINT tool_runs_stdout_artifact_id_fkey FOREIGN KEY (stdout_artifact_id) REFERENCES artifacts(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE tool_runs DROP CONSTRAINT IF EXISTS tool_runs_stderr_artifact_id_fkey;
ALTER TABLE tool_runs ADD CONSTRAINT tool_runs_stderr_artifact_id_fkey FOREIGN KEY (stderr_artifact_id) REFERENCES artifacts(id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY,
    program_id UUID NOT NULL REFERENCES programs(id),
    type TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(program_id, type, canonical_value)
);

CREATE TABLE IF NOT EXISTS asset_observations (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id),
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id),
    source_capability TEXT NOT NULL,
    observed_value TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at TIMESTAMPTZ NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    evidence_artifact_ids UUID[] NOT NULL DEFAULT '{}',
    UNIQUE(asset_id, workflow_run_id, source_capability, observed_value)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id UUID DEFAULT gen_random_uuid(),
    program_id UUID REFERENCES programs(id),
    asset_id UUID REFERENCES assets(id),
    exact_url TEXT,
    route_signature TEXT,
    method TEXT DEFAULT 'GET',
    content_type TEXT DEFAULT '',
    parameter_schema JSONB DEFAULT '[]'::jsonb,
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid();
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS program_id UUID REFERENCES programs(id);
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES assets(id);
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS exact_url TEXT;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS route_signature TEXT;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS method TEXT DEFAULT 'GET';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS content_type TEXT DEFAULT '';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS parameter_schema JSONB DEFAULT '[]'::jsonb;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='endpoints' AND column_name='url') THEN
    EXECUTE 'UPDATE endpoints SET exact_url = url WHERE exact_url IS NULL AND url IS NOT NULL';
  END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS endpoints_id_uq ON endpoints(id);
CREATE UNIQUE INDEX IF NOT EXISTS endpoints_identity_uq ON endpoints(program_id, route_signature, method, content_type, parameter_schema) NULLS NOT DISTINCT;

CREATE INDEX IF NOT EXISTS workflow_runs_task_idx ON workflow_runs(task_id, started_at DESC);
CREATE INDEX IF NOT EXISTS step_runs_run_status_idx ON step_runs(workflow_run_id, status);
CREATE INDEX IF NOT EXISTS tool_runs_step_idx ON tool_runs(step_run_id);
CREATE INDEX IF NOT EXISTS artifacts_lineage_idx ON artifacts(task_id, workflow_run_id, step_run_id, tool_run_id);
CREATE INDEX IF NOT EXISTS observations_run_idx ON asset_observations(workflow_run_id, source_capability);
