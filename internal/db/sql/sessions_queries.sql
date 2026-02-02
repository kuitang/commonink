-- Sessions queries for the shared sessions database

-- Sessions CRUD operations

-- name: CreateSession :exec
INSERT INTO sessions (session_id, user_id, expires_at, created_at)
VALUES (?, ?, ?, ?);

-- name: UpsertSession :exec
INSERT INTO sessions (session_id, user_id, expires_at, created_at)
VALUES (?, ?, ?, ?) ON CONFLICT(session_id) DO UPDATE SET expires_at = excluded.expires_at;

-- name: GetSession :one
SELECT session_id, user_id, expires_at, created_at
FROM sessions
WHERE session_id = ?;

-- name: GetValidSession :one
SELECT * FROM sessions WHERE session_id = ? AND expires_at > CAST(strftime('%s', 'now') AS INTEGER);

-- name: GetSessionsByUserID :many
SELECT session_id, user_id, expires_at, created_at
FROM sessions
WHERE user_id = ?
ORDER BY created_at DESC;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE session_id = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < ?;

-- name: DeleteExpiredSessionsNow :exec
DELETE FROM sessions WHERE expires_at <= CAST(strftime('%s', 'now') AS INTEGER);

-- name: DeleteSessionsByUserID :exec
DELETE FROM sessions WHERE user_id = ?;

-- name: CountSessions :one
SELECT COUNT(*) FROM sessions;

-- name: CountSessionsByUserID :one
SELECT COUNT(*) FROM sessions WHERE user_id = ?;

-- Magic tokens operations

-- name: CreateMagicToken :exec
INSERT INTO magic_tokens (token_hash, email, user_id, expires_at, created_at)
VALUES (?, ?, ?, ?, ?);

-- name: UpsertMagicToken :exec
INSERT INTO magic_tokens (token_hash, email, user_id, expires_at, created_at)
VALUES (?, ?, ?, ?, ?) ON CONFLICT(token_hash) DO UPDATE SET expires_at = excluded.expires_at;

-- name: GetMagicToken :one
SELECT token_hash, email, user_id, expires_at, created_at
FROM magic_tokens
WHERE token_hash = ?;

-- name: GetValidMagicToken :one
SELECT * FROM magic_tokens WHERE token_hash = ? AND expires_at > CAST(strftime('%s', 'now') AS INTEGER);

-- name: GetMagicTokensByEmail :many
SELECT token_hash, email, user_id, expires_at, created_at
FROM magic_tokens
WHERE email = ?
ORDER BY created_at DESC;

-- name: DeleteMagicToken :exec
DELETE FROM magic_tokens WHERE token_hash = ?;

-- name: DeleteExpiredMagicTokens :exec
DELETE FROM magic_tokens WHERE expires_at < ?;

-- name: DeleteExpiredMagicTokensNow :exec
DELETE FROM magic_tokens WHERE expires_at <= CAST(strftime('%s', 'now') AS INTEGER);

-- name: DeleteMagicTokensByEmail :exec
DELETE FROM magic_tokens WHERE email = ?;

-- User keys operations

-- name: CreateUserKey :exec
INSERT INTO user_keys (user_id, kek_version, encrypted_dek, created_at)
VALUES (?, ?, ?, ?);

-- name: UpsertUserKey :exec
INSERT INTO user_keys (user_id, kek_version, encrypted_dek, created_at, rotated_at)
VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET
  kek_version = excluded.kek_version, encrypted_dek = excluded.encrypted_dek, rotated_at = excluded.rotated_at;

-- name: GetUserKey :one
SELECT user_id, kek_version, encrypted_dek, created_at, rotated_at
FROM user_keys
WHERE user_id = ?;

-- name: UpdateUserKey :exec
UPDATE user_keys
SET kek_version = ?, encrypted_dek = ?, rotated_at = ?
WHERE user_id = ?;

-- name: DeleteUserKey :exec
DELETE FROM user_keys WHERE user_id = ?;

-- OAuth clients operations

-- name: CreateOAuthClient :exec
INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, is_public, token_endpoint_auth_method, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthClient :one
SELECT client_id, client_secret_hash, client_name, redirect_uris, is_public, token_endpoint_auth_method, created_at
FROM oauth_clients
WHERE client_id = ?;

-- name: ListOAuthClients :many
SELECT client_id, client_secret_hash, client_name, redirect_uris, is_public, token_endpoint_auth_method, created_at
FROM oauth_clients
ORDER BY created_at DESC;

-- name: UpdateOAuthClient :exec
UPDATE oauth_clients
SET client_secret_hash = ?, client_name = ?, redirect_uris = ?
WHERE client_id = ?;

-- name: DeleteOAuthClient :exec
DELETE FROM oauth_clients WHERE client_id = ?;

-- OAuth tokens operations

-- name: CreateOAuthToken :exec
INSERT INTO oauth_tokens (access_token_hash, refresh_token_hash, client_id, user_id, scope, resource, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthToken :one
SELECT access_token_hash, refresh_token_hash, client_id, user_id, scope, resource, expires_at, created_at
FROM oauth_tokens
WHERE access_token_hash = ?;

-- name: GetOAuthTokenByRefresh :one
SELECT access_token_hash, refresh_token_hash, client_id, user_id, scope, resource, expires_at, created_at
FROM oauth_tokens
WHERE refresh_token_hash = ?;

-- name: GetOAuthTokensByUserClient :many
SELECT access_token_hash, refresh_token_hash, client_id, user_id, scope, resource, expires_at, created_at
FROM oauth_tokens
WHERE user_id = ? AND client_id = ?
ORDER BY created_at DESC;

-- name: DeleteOAuthToken :exec
DELETE FROM oauth_tokens WHERE access_token_hash = ?;

-- name: DeleteExpiredOAuthTokens :exec
DELETE FROM oauth_tokens WHERE expires_at < ?;

-- name: DeleteOAuthTokensByUserID :exec
DELETE FROM oauth_tokens WHERE user_id = ?;

-- name: DeleteOAuthTokensByClientID :exec
DELETE FROM oauth_tokens WHERE client_id = ?;

-- OAuth authorization codes operations

-- name: CreateOAuthCode :exec
INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, scope, resource, code_challenge, code_challenge_method, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthCode :one
SELECT code_hash, client_id, user_id, redirect_uri, scope, resource, code_challenge, code_challenge_method, expires_at, created_at
FROM oauth_codes
WHERE code_hash = ?;

-- name: GetValidOAuthCode :one
SELECT code_hash, client_id, user_id, redirect_uri, scope, resource, code_challenge, code_challenge_method, expires_at, created_at
FROM oauth_codes
WHERE code_hash = ? AND expires_at > CAST(strftime('%s', 'now') AS INTEGER);

-- name: DeleteOAuthCode :exec
DELETE FROM oauth_codes WHERE code_hash = ?;

-- name: DeleteExpiredOAuthCodes :exec
DELETE FROM oauth_codes WHERE expires_at < ?;
