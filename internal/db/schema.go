package db

// SQL schema definitions for the database layer.
// Per docs/SPEC.md, we have two types of databases:
// 1. sessions.db - Shared, unencrypted bootstrap data
// 2. {user_id}.db - Per-user, encrypted with SQLCipher

// SessionsDBSchema contains all the SQL statements for the shared sessions database.
const SessionsDBSchema = `
-- Sessions table: stores active user sessions
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- Magic tokens table: passwordless authentication tokens
CREATE TABLE IF NOT EXISTS magic_tokens (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    user_id TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_magic_tokens_email ON magic_tokens(email);

-- User keys table: encrypted DEKs for per-user databases
CREATE TABLE IF NOT EXISTS user_keys (
    user_id TEXT PRIMARY KEY,
    kek_version INTEGER NOT NULL DEFAULT 1,
    encrypted_dek BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    rotated_at INTEGER
);

-- OAuth clients table: registered OAuth 2.1 clients
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash TEXT,  -- NULL for public clients (Claude)
    client_name TEXT,
    redirect_uris TEXT NOT NULL,
    is_public INTEGER NOT NULL DEFAULT 0,  -- 1 for public clients (Claude), 0 for confidential (ChatGPT)
    token_endpoint_auth_method TEXT DEFAULT 'client_secret_post',  -- 'none' for public clients
    created_at INTEGER NOT NULL
);

-- OAuth tokens table: access and refresh tokens
CREATE TABLE IF NOT EXISTS oauth_tokens (
    access_token_hash TEXT PRIMARY KEY,  -- Store hash, not plaintext
    refresh_token_hash TEXT,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT,
    resource TEXT,  -- MCP resource identifier for aud claim
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_client ON oauth_tokens(user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh ON oauth_tokens(refresh_token_hash);

-- OAuth authorization codes table: temporary codes for token exchange
CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash TEXT PRIMARY KEY,  -- Store hash, not plaintext
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    resource TEXT,  -- MCP resource identifier
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT DEFAULT 'S256',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

-- OAuth consents table: user consent records for OAuth clients
CREATE TABLE IF NOT EXISTS oauth_consents (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,  -- space-separated scope string
    granted_at INTEGER NOT NULL,
    UNIQUE(user_id, client_id)
);
CREATE INDEX IF NOT EXISTS idx_consents_user_id ON oauth_consents(user_id);

-- Short URLs table: maps short IDs to full paths for public notes
CREATE TABLE IF NOT EXISTS short_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    short_id TEXT UNIQUE NOT NULL,
    full_path TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_short_urls_full_path ON short_urls(full_path);

-- Pending subscriptions: tracks Stripe purchases made before account creation
CREATE TABLE IF NOT EXISTS pending_subscriptions (
    email TEXT PRIMARY KEY,
    stripe_customer_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    subscription_status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL
);

-- Stripe customer map: maps Stripe customer IDs to user IDs
CREATE TABLE IF NOT EXISTS stripe_customer_map (
    stripe_customer_id TEXT PRIMARY KEY,
    user_id TEXT UNIQUE NOT NULL
);

-- Processed webhook events: idempotency guard for Stripe webhooks
CREATE TABLE IF NOT EXISTS processed_webhook_events (
    event_id TEXT PRIMARY KEY,
    processed_at INTEGER NOT NULL
);
`

// UserDBSchema contains all the SQL statements for per-user encrypted databases.
const UserDBSchema = `
-- Account table: user account information
CREATE TABLE IF NOT EXISTS account (
    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    google_sub TEXT,
    created_at INTEGER NOT NULL,
    subscription_status TEXT DEFAULT 'free',
    subscription_id TEXT,
    stripe_customer_id TEXT,
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
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_notes_updated_at ON notes(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_notes_is_public ON notes(is_public);
CREATE INDEX IF NOT EXISTS idx_notes_deleted_at ON notes(deleted_at);

-- FTS5 virtual table for full-text search
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
`

// UserDBMigrations contains idempotent ALTER TABLE statements for schema evolution.
// SQLite ADD COLUMN is idempotent-safe: duplicate column errors are caught and ignored.
const UserDBMigrations = `
ALTER TABLE notes ADD COLUMN deleted_at INTEGER;
CREATE INDEX IF NOT EXISTS idx_notes_deleted_at ON notes(deleted_at);
`
