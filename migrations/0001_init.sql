CREATE TABLE IF NOT EXISTS hub_state (
  id TEXT PRIMARY KEY,
  state_json TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL,
  window_started_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hub_equipment_chunks (
  state_id TEXT NOT NULL,
  chunk_index INTEGER NOT NULL,
  chunk_b64 TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (state_id, chunk_index)
);
