-- User database schema (encrypted per-user with SQLCipher)
-- Per spec.md: {user_id}.db contains user-specific data

-- Account table: user account information
CREATE TABLE IF NOT EXISTS account (
    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    google_sub TEXT,
    created_at INTEGER NOT NULL,
    subscription_status TEXT DEFAULT 'free',
    subscription_id TEXT,
    db_size_bytes INTEGER DEFAULT 0,
    last_login INTEGER
);

-- Notes table: main notes storage with 1MB content limit
CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL CHECK(length(content) <= 1048576),
    is_public INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_updated_at ON notes(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_notes_is_public ON notes(is_public);

-- FTS5 virtual table for full-text search
-- Note: sqlc doesn't fully support FTS5, so we keep this in schema but handle search queries manually
CREATE VIRTUAL TABLE IF NOT EXISTS fts_notes USING fts5(
    title,
    content,
    content='notes',
    content_rowid='rowid'
);

-- Trigger: sync FTS index on INSERT
CREATE TRIGGER IF NOT EXISTS notes_ai AFTER INSERT ON notes BEGIN
    INSERT INTO fts_notes(rowid, title, content)
    VALUES (new.rowid, new.title, new.content);
END;

-- Trigger: sync FTS index on DELETE
CREATE TRIGGER IF NOT EXISTS notes_ad AFTER DELETE ON notes BEGIN
    DELETE FROM fts_notes WHERE rowid = old.rowid;
END;

-- Trigger: sync FTS index on UPDATE
CREATE TRIGGER IF NOT EXISTS notes_au AFTER UPDATE ON notes BEGIN
    UPDATE fts_notes SET title = new.title, content = new.content
    WHERE rowid = new.rowid;
END;

-- API keys table: long-lived keys for programmatic API access
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT DEFAULT 'read_write',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_keys_token_hash ON api_keys(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at);
