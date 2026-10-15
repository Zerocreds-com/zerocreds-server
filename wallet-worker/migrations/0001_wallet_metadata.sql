-- Only non-secret wallet metadata. Provider values and OpenBao credentials never belong here.
CREATE TABLE wallet_connections (
  connection_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  request_key_hash TEXT NOT NULL,
  openbao_path TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL DEFAULT 'allocated' CHECK (state IN ('allocated', 'active', 'revoked')),
  kv_version INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (owner_id, request_key_hash)
);
CREATE INDEX wallet_connections_owner_profile ON wallet_connections(owner_id, profile_id, state);
CREATE TABLE wallet_forms (
  form_id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES wallet_connections(connection_id),
  owner_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  manifest_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'written')),
  expires_at INTEGER NOT NULL,
  kv_version INTEGER,
  receipt_ref TEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE INDEX wallet_forms_connection ON wallet_forms(connection_id, state);
CREATE TRIGGER wallet_form_version_guard BEFORE UPDATE OF state ON wallet_forms
WHEN NEW.state = 'written' AND (
  SELECT kv_version FROM wallet_connections WHERE connection_id = NEW.connection_id
) >= NEW.kv_version
BEGIN
  SELECT RAISE(ABORT, 'wallet_version_not_newer');
END;
