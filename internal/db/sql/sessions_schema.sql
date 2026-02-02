-- Sessions database schema (unencrypted, shared)
-- Per spec.md: sessions.db contains bootstrap data like sessions, magic tokens, OAuth clients, etc.

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
    client_secret TEXT NOT NULL,
    client_name TEXT,
    redirect_uris TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- OAuth tokens table: access and refresh tokens
CREATE TABLE IF NOT EXISTS oauth_tokens (
    access_token TEXT PRIMARY KEY,
    refresh_token TEXT,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_client ON oauth_tokens(user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh ON oauth_tokens(refresh_token);

-- OAuth authorization codes table: temporary codes for token exchange
CREATE TABLE IF NOT EXISTS oauth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT DEFAULT 'S256',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
