CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events are append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events;
CREATE TRIGGER audit_events_immutable
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
