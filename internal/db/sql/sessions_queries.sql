-- Sessions queries for the shared sessions database

-- Sessions CRUD operations

-- name: CreateSession :exec
INSERT INTO sessions (session_id, user_id, expires_at, created_at)
VALUES (?, ?, ?, ?);

-- name: GetSession :one
SELECT session_id, user_id, expires_at, created_at
FROM sessions
WHERE session_id = ?;

-- name: GetSessionsByUserID :many
SELECT session_id, user_id, expires_at, created_at
FROM sessions
WHERE user_id = ?
ORDER BY created_at DESC;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE session_id = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < ?;

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

-- name: GetMagicToken :one
SELECT token_hash, email, user_id, expires_at, created_at
FROM magic_tokens
WHERE token_hash = ?;

-- name: GetMagicTokensByEmail :many
SELECT token_hash, email, user_id, expires_at, created_at
FROM magic_tokens
WHERE email = ?
ORDER BY created_at DESC;

-- name: DeleteMagicToken :exec
DELETE FROM magic_tokens WHERE token_hash = ?;

-- name: DeleteExpiredMagicTokens :exec
DELETE FROM magic_tokens WHERE expires_at < ?;

-- name: DeleteMagicTokensByEmail :exec
DELETE FROM magic_tokens WHERE email = ?;

-- User keys operations

-- name: CreateUserKey :exec
INSERT INTO user_keys (user_id, kek_version, encrypted_dek, created_at)
VALUES (?, ?, ?, ?);

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
INSERT INTO oauth_clients (client_id, client_secret, client_name, redirect_uris, created_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetOAuthClient :one
SELECT client_id, client_secret, client_name, redirect_uris, created_at
FROM oauth_clients
WHERE client_id = ?;

-- name: ListOAuthClients :many
SELECT client_id, client_secret, client_name, redirect_uris, created_at
FROM oauth_clients
ORDER BY created_at DESC;

-- name: UpdateOAuthClient :exec
UPDATE oauth_clients
SET client_secret = ?, client_name = ?, redirect_uris = ?
WHERE client_id = ?;

-- name: DeleteOAuthClient :exec
DELETE FROM oauth_clients WHERE client_id = ?;

-- OAuth tokens operations

-- name: CreateOAuthToken :exec
INSERT INTO oauth_tokens (access_token, refresh_token, client_id, user_id, scope, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthToken :one
SELECT access_token, refresh_token, client_id, user_id, scope, expires_at, created_at
FROM oauth_tokens
WHERE access_token = ?;

-- name: GetOAuthTokenByRefresh :one
SELECT access_token, refresh_token, client_id, user_id, scope, expires_at, created_at
FROM oauth_tokens
WHERE refresh_token = ?;

-- name: GetOAuthTokensByUserClient :many
SELECT access_token, refresh_token, client_id, user_id, scope, expires_at, created_at
FROM oauth_tokens
WHERE user_id = ? AND client_id = ?
ORDER BY created_at DESC;

-- name: DeleteOAuthToken :exec
DELETE FROM oauth_tokens WHERE access_token = ?;

-- name: DeleteExpiredOAuthTokens :exec
DELETE FROM oauth_tokens WHERE expires_at < ?;

-- name: DeleteOAuthTokensByUserID :exec
DELETE FROM oauth_tokens WHERE user_id = ?;

-- name: DeleteOAuthTokensByClientID :exec
DELETE FROM oauth_tokens WHERE client_id = ?;

-- OAuth authorization codes operations

-- name: CreateOAuthCode :exec
INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthCode :one
SELECT code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at
FROM oauth_codes
WHERE code = ?;

-- name: DeleteOAuthCode :exec
DELETE FROM oauth_codes WHERE code = ?;

-- name: DeleteExpiredOAuthCodes :exec
DELETE FROM oauth_codes WHERE expires_at < ?;
