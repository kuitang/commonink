-- User database queries (per-user encrypted database)

-- Account operations

-- name: CreateAccount :exec
INSERT INTO account (user_id, email, password_hash, google_sub, created_at, subscription_status, subscription_id, db_size_bytes, last_login)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAccount :one
SELECT user_id, email, password_hash, google_sub, created_at, subscription_status, subscription_id, db_size_bytes, last_login
FROM account
WHERE user_id = ?;

-- name: GetAccountByEmail :one
SELECT user_id, email, password_hash, google_sub, created_at, subscription_status, subscription_id, db_size_bytes, last_login
FROM account
WHERE email = ?;

-- name: GetAccountByGoogleSub :one
SELECT user_id, email, password_hash, google_sub, created_at, subscription_status, subscription_id, db_size_bytes, last_login
FROM account
WHERE google_sub = ?;

-- name: UpdateAccountEmail :exec
UPDATE account SET email = ? WHERE user_id = ?;

-- name: UpdateAccountPasswordHash :exec
UPDATE account SET password_hash = ? WHERE user_id = ?;

-- name: UpdateAccountGoogleSub :exec
UPDATE account SET google_sub = ? WHERE user_id = ?;

-- name: UpdateAccountSubscription :exec
UPDATE account SET subscription_status = ?, subscription_id = ? WHERE user_id = ?;

-- name: UpdateAccountDBSize :exec
UPDATE account SET db_size_bytes = ? WHERE user_id = ?;

-- name: UpdateAccountLastLogin :exec
UPDATE account SET last_login = ? WHERE user_id = ?;

-- name: DeleteAccount :exec
DELETE FROM account WHERE user_id = ?;

-- Notes CRUD operations

-- name: CreateNote :exec
INSERT INTO notes (id, title, content, is_public, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetNote :one
SELECT id, title, content, is_public, created_at, updated_at
FROM notes
WHERE id = ?;

-- name: ListNotes :many
SELECT id, title, content, is_public, created_at, updated_at
FROM notes
ORDER BY updated_at DESC
LIMIT ? OFFSET ?;

-- name: ListPublicNotes :many
SELECT id, title, content, is_public, created_at, updated_at
FROM notes
WHERE is_public = 1
ORDER BY updated_at DESC
LIMIT ? OFFSET ?;

-- name: UpdateNote :exec
UPDATE notes
SET title = ?, content = ?, is_public = ?, updated_at = ?
WHERE id = ?;

-- name: UpdateNoteTitle :exec
UPDATE notes SET title = ?, updated_at = ? WHERE id = ?;

-- name: UpdateNoteContent :exec
UPDATE notes SET content = ?, updated_at = ? WHERE id = ?;

-- name: UpdateNotePublic :exec
UPDATE notes SET is_public = ?, updated_at = ? WHERE id = ?;

-- name: DeleteNote :exec
DELETE FROM notes WHERE id = ?;

-- name: CountNotes :one
SELECT COUNT(*) FROM notes;

-- name: CountPublicNotes :one
SELECT COUNT(*) FROM notes WHERE is_public = 1;

-- name: NoteExists :one
SELECT EXISTS(SELECT 1 FROM notes WHERE id = ?);

-- FTS5 search operations
-- Note: FTS5 queries are handled separately in Go code due to sqlc limitations with virtual tables
-- The fts_notes table is a virtual table that sqlc cannot fully parse

-- API keys operations

-- name: CreateAPIKey :exec
INSERT INTO api_keys (key_id, key_hash, scope, created_at)
VALUES (?, ?, ?, ?);

-- name: GetAPIKey :one
SELECT key_id, key_hash, scope, created_at, last_used
FROM api_keys
WHERE key_id = ?;

-- name: GetAPIKeyByHash :one
SELECT key_id, key_hash, scope, created_at, last_used
FROM api_keys
WHERE key_hash = ?;

-- name: ListAPIKeys :many
SELECT key_id, key_hash, scope, created_at, last_used
FROM api_keys
ORDER BY created_at DESC;

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys SET last_used = ? WHERE key_id = ?;

-- name: UpdateAPIKeyScope :exec
UPDATE api_keys SET scope = ? WHERE key_id = ?;

-- name: DeleteAPIKey :exec
DELETE FROM api_keys WHERE key_id = ?;

-- name: CountAPIKeys :one
SELECT COUNT(*) FROM api_keys;
