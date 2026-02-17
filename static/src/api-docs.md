# API Documentation

common.ink provides a RESTful JSON API for programmatic access to your notes.

## Table of Contents

- [Authentication](#authentication)
- [Notes API](#notes-api)
- [API Keys Management](#api-keys-management)
- [Rate Limits](#rate-limits)
- [Error Responses](#error-responses)

---

## Authentication

### Getting an API Key

API Keys are the recommended way to authenticate API requests:

1. [Sign in](/login) to your account
2. Go to [API Keys](/api-keys/new) to create a new key
3. Copy the key -- you won't see it again
4. Include it in all requests via the `Authorization` header:

```
Authorization: Bearer $COMMON_INK_API_KEY
```

**Example:**

```bash
curl -H "Authorization: Bearer $COMMON_INK_API_KEY" \
  https://common.ink/api/notes
```

API Key format: `agentnotes_key_{user_id}_{random_token}`

### OAuth 2.1

For third-party applications, common.ink supports OAuth 2.1 with PKCE. See the [OAuth 2.1 Provider](#oauth-21-provider) section below.

---

## Notes API

All endpoints require authentication via API Key or OAuth JWT.

**Base URL:** `https://common.ink/api`

### List Notes

`GET /api/notes`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | integer | 50 | Max notes to return (max: 1000) |
| offset | integer | 0 | Number of notes to skip |

```bash
curl "https://common.ink/api/notes?limit=10&offset=0" \
  -H "Authorization: Bearer $COMMON_INK_API_KEY"
```

**Response:**

```json
{
  "notes": [
    {
      "id": "b3f1a2c4-5d6e-7f89-0abc-def123456789",
      "title": "My Note",
      "content": "Note content here...",
      "is_public": false,
      "created_at": "2026-01-15T10:30:00Z",
      "updated_at": "2026-01-15T10:30:00Z"
    }
  ],
  "total_count": 42,
  "limit": 10,
  "offset": 0
}
```

---

### Create Note

`POST /api/notes`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | Yes | Note title |
| content | string | No | Note content (markdown supported) |

```bash
curl -X POST https://common.ink/api/notes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $COMMON_INK_API_KEY" \
  -d '{
    "title": "Meeting Notes",
    "content": "## Agenda\n- Item 1\n- Item 2"
  }'
```

**Response (201 Created):**

```json
{
  "id": "c4e2d1a3-6b7f-8901-2345-abcdef678901",
  "title": "Meeting Notes",
  "content": "## Agenda\n- Item 1\n- Item 2",
  "is_public": false,
  "created_at": "2026-01-15T10:35:00Z",
  "updated_at": "2026-01-15T10:35:00Z"
}
```

---

### Get Note

`GET /api/notes/{id}`

```bash
curl https://common.ink/api/notes/c4e2d1a3-6b7f-8901-2345-abcdef678901 \
  -H "Authorization: Bearer $COMMON_INK_API_KEY"
```

---

### Update Note

`PUT /api/notes/{id}`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | No | New title |
| content | string | No | New content |

```bash
curl -X PUT https://common.ink/api/notes/c4e2d1a3-6b7f-8901-2345-abcdef678901 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $COMMON_INK_API_KEY" \
  -d '{
    "title": "Updated Title",
    "content": "Updated content..."
  }'
```

---

### Delete Note

`DELETE /api/notes/{id}`

```bash
curl -X DELETE https://common.ink/api/notes/c4e2d1a3-6b7f-8901-2345-abcdef678901 \
  -H "Authorization: Bearer $COMMON_INK_API_KEY"
```

**Response:** `204 No Content`

---

### Search Notes

`POST /api/notes/search`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| query | string | Yes | Search query (FTS5 syntax supported) |

```bash
curl -X POST https://common.ink/api/notes/search \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $COMMON_INK_API_KEY" \
  -d '{"query": "meeting agenda"}'
```

**Response:**

```json
{
  "results": [
    {
      "note": {
        "id": "c4e2d1a3-6b7f-8901-2345-abcdef678901",
        "title": "Meeting Notes",
        "content": "## Agenda\n- Goal setting",
        "is_public": false,
        "created_at": "2026-01-15T10:35:00Z",
        "updated_at": "2026-01-15T10:35:00Z"
      },
      "rank": -1.5
    }
  ],
  "query": "meeting agenda",
  "total_count": 1
}
```

Uses FTS5 full-text search. Lower (more negative) rank values indicate better matches.

---

## API Keys Management

### Create an API Key

`POST /api/keys`

Requires session cookie authentication (log in via the web first) and password re-authentication.

```bash
curl -X POST https://common.ink/api/keys \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "name": "My CLI Token",
    "scope": "read_write",
    "expires_in": 2592000,
    "email": "user@example.com",
    "password": "SecurePass123"
  }'
```

**Response (201 Created):**

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "My CLI Token",
  "token": "agentnotes_key_user-xxx_YWJjZGVm...",
  "scope": "read_write",
  "expires_at": "2026-03-03T12:00:00Z",
  "created_at": "2026-02-03T12:00:00Z"
}
```

Save the `token` value -- it cannot be retrieved later.

The easiest way to create an API key is through the web UI at [/api-keys/new](/api-keys/new).

---

### List API Keys

`GET /api/keys`

```bash
curl https://common.ink/api/keys \
  -H "Authorization: Bearer $COMMON_INK_API_KEY"
```

---

### Revoke an API Key

`DELETE /api/keys/{id}`

```bash
curl -X DELETE https://common.ink/api/keys/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "Authorization: Bearer $COMMON_INK_API_KEY"
```

**Response:** `204 No Content`

---

## OAuth 2.1 Provider

For third-party integrations, common.ink supports OAuth 2.1 with PKCE.

### Discovery Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/oauth-authorization-server` | Authorization server metadata |
| `GET /.well-known/oauth-protected-resource` | Protected resource metadata |
| `GET /.well-known/jwks.json` | JSON Web Key Set |

### Dynamic Client Registration

`POST /oauth/register`

```bash
curl -X POST https://common.ink/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My AI Agent",
    "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none"
  }'
```

### Token Exchange

`POST /oauth/token`

```bash
curl -X POST https://common.ink/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=REDIRECT_URI&client_id=CLIENT_ID&code_verifier=PKCE_VERIFIER"
```

---

## Rate Limits

| Tier | Requests/Minute | Burst |
|------|-----------------|-------|
| Free | 60 | 100 |

Rate limit headers are included in all responses:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests per window |
| `X-RateLimit-Remaining` | Remaining requests in current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |

---

## Error Responses

All errors return JSON:

```json
{
  "error": "Error message description"
}
```

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 204 | No Content (successful deletion) |
| 400 | Bad Request (invalid input) |
| 401 | Unauthorized (missing or invalid authentication) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not Found |
| 429 | Too Many Requests (rate limited) |
| 500 | Internal Server Error |

---

## Health Check

`GET /health` (no authentication required)

```bash
curl https://common.ink/health
```

---

## Support

For API support, contact: api-support@common.ink
