CREATE TABLE IF NOT EXISTS candidate_findings (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL REFERENCES tasks(id),
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id),
    target_asset_id UUID NOT NULL REFERENCES assets(id),
    source_capability TEXT NOT NULL,
    template_id TEXT NOT NULL,
    claimed_vulnerability TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence_artifact_ids UUID[] NOT NULL DEFAULT '{}',
    detection_confidence DOUBLE PRECISION NOT NULL CHECK (detection_confidence >= 0 AND detection_confidence <= 1),
    status TEXT NOT NULL CHECK (status IN ('new','queued_for_verification','verifying','confirmed','rejected','informational','needs_manual_review')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(workflow_run_id, target_asset_id, template_id)
);

CREATE TABLE IF NOT EXISTS verification_results (
    id UUID PRIMARY KEY,
    candidate_id UUID NOT NULL REFERENCES candidate_findings(id),
    playbook TEXT NOT NULL,
    independent_provider TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('confirmed','rejected','inconclusive','manual_review')),
    summary TEXT NOT NULL,
    evidence_artifact_ids UUID[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS verified_findings (
    id UUID PRIMARY KEY,
    candidate_id UUID UNIQUE REFERENCES candidate_findings(id),
    program_id UUID REFERENCES programs(id),
    asset_id UUID REFERENCES assets(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open','resolved','accepted_risk','duplicate','informational')),
    impact_statement TEXT NOT NULL DEFAULT '',
    first_verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    legacy_finding_id BIGINT
);

CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE,
    task_id UUID NOT NULL REFERENCES tasks(id),
    action_request_id UUID NOT NULL,
    requested_risk_level TEXT NOT NULL,
    reason TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decision TEXT NOT NULL CHECK (decision IN ('pending','approved','rejected','expired')),
    decided_by TEXT,
    decided_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type TEXT NOT NULL,
    component TEXT NOT NULL,
    actor TEXT NOT NULL,
    task_id UUID REFERENCES tasks(id),
    workflow_run_id UUID REFERENCES workflow_runs(id),
    step_run_id UUID REFERENCES step_runs(id),
    tool_run_id UUID REFERENCES tool_runs(id),
    capability TEXT,
    provider TEXT,
    safe_message TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS candidate_status_idx ON candidate_findings(status, severity);
CREATE INDEX IF NOT EXISTS verified_program_status_idx ON verified_findings(program_id, status);
CREATE INDEX IF NOT EXISTS approvals_pending_idx ON approvals(decision, requested_at);
CREATE INDEX IF NOT EXISTS audit_lineage_idx ON audit_events(task_id, workflow_run_id, occurred_at);

-- Existing findings remain untouched. If the legacy table exists, retain a
-- durable mapping shell without assuming that every historical deployment has
-- the same optional columns.
DO $$
BEGIN
  IF to_regclass('public.findings') IS NOT NULL THEN
    CREATE TABLE IF NOT EXISTS legacy_finding_migration (
      legacy_id BIGINT PRIMARY KEY,
      migrated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      note TEXT NOT NULL
    );
    INSERT INTO legacy_finding_migration(legacy_id, note)
      SELECT id, 'preserved in findings; verification required before promotion'
      FROM findings
      ON CONFLICT (legacy_id) DO NOTHING;
  END IF;
END $$;
