ALTER TABLE programs ADD COLUMN IF NOT EXISTS scope_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE programs ADD COLUMN IF NOT EXISTS include_rule_digests TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE programs ADD COLUMN IF NOT EXISTS exclude_rule_digests TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE programs ADD COLUMN IF NOT EXISTS target_plan_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE programs ADD COLUMN IF NOT EXISTS scope_plan_warnings JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS program_id UUID REFERENCES programs(id);

CREATE TABLE IF NOT EXISTS scope_versions (
    id UUID PRIMARY KEY,
    program_id UUID NOT NULL REFERENCES programs(id),
    scope_reference TEXT NOT NULL,
    scope_digest TEXT NOT NULL,
    include_rule_digests TEXT[] NOT NULL DEFAULT '{}',
    exclude_rule_digests TEXT[] NOT NULL DEFAULT '{}',
    target_plan_digest TEXT NOT NULL,
    planning_warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    target_plan JSONB NOT NULL,
    expands_scope BOOLEAN NOT NULL DEFAULT false,
    added_include_digests TEXT[] NOT NULL DEFAULT '{}',
    removed_include_digests TEXT[] NOT NULL DEFAULT '{}',
    added_exclude_digests TEXT[] NOT NULL DEFAULT '{}',
    removed_exclude_digests TEXT[] NOT NULL DEFAULT '{}',
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(program_id, target_plan_digest)
);

CREATE INDEX IF NOT EXISTS scope_versions_program_created_idx ON scope_versions(program_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_program_lineage_idx ON audit_events(program_id, occurred_at);
