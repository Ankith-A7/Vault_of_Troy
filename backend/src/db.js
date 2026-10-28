const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');
const config = require('./config');

fs.mkdirSync(path.dirname(config.DB_FILE), { recursive: true });
for (const dir of [config.STORAGE_ROOT, config.QUARANTINE_DIR, config.APPROVED_DIR]) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}
const db = new Database(config.DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, approval_pin_hash TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
 id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 original_name TEXT NOT NULL, storage_name TEXT NOT NULL UNIQUE,
 mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
 sha256 TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('quarantined','approved','rejected')),
 created_at TEXT NOT NULL, deleted_at TEXT
);
CREATE INDEX IF NOT EXISTS documents_owner_idx ON documents(owner_id, deleted_at, created_at);
CREATE TABLE IF NOT EXISTS shares (
 id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
 download_limit INTEGER NOT NULL CHECK(download_limit > 0),
 download_count INTEGER NOT NULL DEFAULT 0,
 profile TEXT NOT NULL CHECK(profile IN ('view_only','download','one_time','verified_recipient')),
 recipient_email TEXT, revoked_at TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS shares_owner_idx ON shares(owner_id, created_at);
CREATE TABLE IF NOT EXISTS otp_challenges (
 id TEXT PRIMARY KEY, share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
 email TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, last_sent_at TEXT NOT NULL,
 verified_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_events (
 id TEXT PRIMARY KEY, actor_id TEXT, document_id TEXT, share_id TEXT,
 event_type TEXT NOT NULL, outcome TEXT NOT NULL, ip_hash TEXT,
 details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS audit_actor_idx ON audit_events(actor_id, created_at);
`);
// Backward-compatible migration for databases created by earlier project versions.
const userColumns = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
if (!userColumns.includes('approval_pin_hash')) db.exec('ALTER TABLE users ADD COLUMN approval_pin_hash TEXT');
module.exports = db;
