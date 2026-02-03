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
