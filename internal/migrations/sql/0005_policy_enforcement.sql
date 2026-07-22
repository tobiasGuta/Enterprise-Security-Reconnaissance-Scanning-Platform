ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS artifacts_expiry_idx ON artifacts(expires_at) WHERE expires_at IS NOT NULL;
