-- One-time host assertions: store only a digest and expiry, never the assertion.
CREATE TABLE wallet_assertions (
  jti_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX wallet_assertions_expiry ON wallet_assertions(expires_at);
