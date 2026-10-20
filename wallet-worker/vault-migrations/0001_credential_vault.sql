CREATE TABLE IF NOT EXISTS credential_values (
  connection_id TEXT NOT NULL,
  owner_id      TEXT NOT NULL,
  profile_id    TEXT NOT NULL,
  version       INTEGER NOT NULL,
  ciphertext    TEXT NOT NULL,
  iv            TEXT NOT NULL,
  tag           TEXT NOT NULL,
  alg           TEXT NOT NULL,
  key_ref       TEXT NOT NULL,
  provider      TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  revoked_at    INTEGER,
  PRIMARY KEY (connection_id, version)
);
CREATE INDEX IF NOT EXISTS credential_values_scope
  ON credential_values (owner_id, profile_id, connection_id);
CREATE TABLE IF NOT EXISTS credential_events (
  event_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  connection_id TEXT NOT NULL,
  owner_id      TEXT NOT NULL,
  profile_id    TEXT NOT NULL,
  action        TEXT NOT NULL,
  version       INTEGER,
  actor         TEXT,
  created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS credential_events_connection
  ON credential_events (connection_id, created_at);
