import Database from "better-sqlite3";

const db = new Database("iam.db");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  client_secret_hash TEXT NOT NULL,
  allowed_scopes TEXT NOT NULL,   -- JSON array e.g. ["github:repo:read","slack:post"]
  status TEXT NOT NULL DEFAULT 'active', -- active | suspended
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS issued_tokens (
  jti TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  system TEXT NOT NULL,           -- e.g. "github", "slack", "stripe"
  issued_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT,
  action TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

export default db;