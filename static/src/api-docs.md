# API Documentation

common.ink provides REST and MCP interfaces for persistent AI memory workflows.

## Table of Contents

- [Authentication](#authentication)
- [Notes API](#notes-api)
- [API Keys Management](#api-keys-management)
- [OAuth 2.1 Provider](#oauth-21-provider)
- [Rate Limits](#rate-limits)
- [Error Responses](#error-responses)

---

## Authentication

### Getting an API Key

API keys are the recommended authentication method for scripts and server-to-server integrations.

1. [Sign in](/login)
2. Open [API Keys](/api-keys/new)
3. Create a key and copy it immediately (it is shown once)
4. Send it in the `Authorization` header:

```
Authorization: Bearer $COMMON_INK_API_KEY
```

**Example:**

```bash
curl -H "Authorization: Bearer $COMMON_INK_API_KEY" \
  https://common.ink/api/notes
```

### OAuth 2.1

For third-party clients, common.ink supports OAuth 2.1 with PKCE. See [OAuth 2.1 Provider](#oauth-21-provider).

---

## Notes API

All endpoints require authentication via API key or OAuth bearer token.

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
  -d '{"title":"Meeting Notes","content":"## Agenda\n- Item 1"}'
```

### Get Note

`GET /api/notes/{id}`

### Update Note

`PUT /api/notes/{id}`

### Delete Note

`DELETE /api/notes/{id}`

### Search Notes

`POST /api/notes/search`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| query | string | Yes | Search query (FTS5 syntax supported) |

```bash
curl -X POST https://common.ink/api/notes/search \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $COMMON_INK_API_KEY" \
  -d '{"query":"meeting agenda"}'
```

---

## API Keys Management

### Create an API Key

`POST /api/keys`

Requires authenticated web session and password re-authentication.

### List API Keys

`GET /api/keys`

### Revoke an API Key

`DELETE /api/keys/{id}`

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
    "client_name": "My AI Client",
    "redirect_uris": ["https://example.com/oauth/callback"],
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

| Tier | Requests/Second |
|------|-----------------|
| Free | 10 |
| Pro | 1000 |

Rate limit headers:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

---

## Error Responses

Errors are JSON objects with an `error` field:

```json
{"error":"descriptive message"}
```

Common status codes:
- `400 Bad Request`
- `401 Unauthorized`
- `403 Forbidden`
- `404 Not Found`
- `409 Conflict`
- `429 Too Many Requests`
- `500 Internal Server Error`
