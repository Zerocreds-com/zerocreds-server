-- Lease on credential values.
--
-- A credential value may carry a lease (start and end instants). The grant
-- path refuses to hand out a value whose lease has ended. The lease is
-- opt-in: a long-lived integration keeps working without a lease (NULL).
-- The journal records the lease on each granted event so "the value was
-- handed out under a lease that ended" is answerable after the fact.
--
-- SQLite takes one column per ALTER TABLE statement.
ALTER TABLE credential_values ADD COLUMN lease_started_at INTEGER;
ALTER TABLE credential_values ADD COLUMN lease_expires_at INTEGER;

ALTER TABLE credential_events ADD COLUMN lease_expires_at INTEGER;
