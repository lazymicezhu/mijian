CREATE TABLE IF NOT EXISTS metadata (
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  iv BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  tag BLOB NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  auth_version TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS rate_limits (
  rate_key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS rate_limit_expiry ON rate_limits(expires_at);
