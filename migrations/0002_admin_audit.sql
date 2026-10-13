CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  auth_version TEXT NOT NULL,
  visitor_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS admin_session_expiry ON admin_sessions(expires_at);

CREATE TABLE IF NOT EXISTS session_visitors (
  token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
  visitor_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS message_activity (
  message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
  visitor_id TEXT NOT NULL,
  ip TEXT,
  byte_length INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS access_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  viewed_at INTEGER NOT NULL,
  visitor_id TEXT NOT NULL,
  ip TEXT,
  actor TEXT NOT NULL CHECK (actor IN ('visitor', 'admin'))
);

CREATE INDEX IF NOT EXISTS message_creation ON messages(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS event_message ON access_events(message_id, id DESC);
