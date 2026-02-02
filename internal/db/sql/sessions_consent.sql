-- OAuth consent queries for the shared sessions database

-- name: CreateConsent :one
INSERT INTO oauth_consents (id, user_id, client_id, scopes, granted_at)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: GetConsent :one
SELECT id, user_id, client_id, scopes, granted_at
FROM oauth_consents
WHERE user_id = ? AND client_id = ?;

-- name: DeleteConsent :exec
DELETE FROM oauth_consents WHERE user_id = ? AND client_id = ?;

-- name: ListConsentsForUser :many
SELECT id, user_id, client_id, scopes, granted_at
FROM oauth_consents
WHERE user_id = ?
ORDER BY granted_at DESC;

-- name: UpdateConsentScopes :one
UPDATE oauth_consents
SET scopes = ?, granted_at = ?
WHERE user_id = ? AND client_id = ?
RETURNING *;
