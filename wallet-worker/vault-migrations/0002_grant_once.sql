-- A run's grant is recorded once.
--
-- The host asks for the value on every dispatch attempt: a retry, a capacity
-- cut-over to another worker, a replacement host after the previous one died.
-- Those are the same grant — the same run consuming the same credential — so
-- the journal must not grow a second `granted` event for them.
--
-- The value version is part of the key on purpose. If the credential is
-- rotated while a run is in flight, the run consumes a genuinely different
-- value, and the journal has to say so rather than hide it behind the first
-- grant.
CREATE UNIQUE INDEX IF NOT EXISTS credential_events_grant_once
  ON credential_events (connection_id, actor, version)
  WHERE action = 'granted';
