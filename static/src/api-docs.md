# API Documentation

common.ink provides a RESTful API for programmatic access to your notes, along with MCP (Model Context Protocol) support for AI agent integration.

## Table of Contents

- [Authentication](#authentication)
  - [Session Cookies](#session-cookies)
  - [Personal Access Tokens (PAT)](#personal-access-tokens-pat)
  - [OAuth 2.1](#oauth-21)
- [User Registration & Login](#user-registration--login)
- [Personal Access Tokens API](#personal-access-tokens-api)
- [Notes API](#notes-api)
- [MCP Server](#mcp-model-context-protocol)
- [Connecting AI Assistants](#connecting-ai-assistants)
- [OAuth 2.1 Provider](#oauth-21-provider)
- [Rate Limits](#rate-limits)
- [Error Responses](#error-responses)

---

## Authentication

common.ink supports three authentication methods:

### Session Cookies

Session cookies are automatically set when you log in via the web interface. They're valid for 30 days and use the `session_id` cookie name with `HttpOnly` and `SameSite=Lax` settings.

### Personal Access Tokens (PAT)

PATs are the recommended way to authenticate API requests programmatically:

1. Go to [Tokens](/tokens) to create a new token
2. Include the token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer agentnotes_pat_user-xxx_token..." \
  https://common.ink/api/notes
```

**PAT Format**: `agentnotes_pat_{user_id}_{random_token}`

### OAuth 2.1

For third-party applications, use OAuth 2.1 with PKCE. See the [OAuth 2.1 Provider](#oauth-21-provider) section below.

---

## User Registration & Login

### Register with Email/Password

**Endpoint**: `POST /auth/register`

**Content-Type**: `application/x-www-form-urlencoded`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Email address |
| password | string | Yes | Password (min 8 characters) |

```bash
# Register a new account (saves session cookie)
curl -X POST https://common.ink/auth/register \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=user@example.com&password=SecurePass123" \
  -c cookies.txt
```

**Response**: 303 redirect to `/notes` with session cookie set in `cookies.txt`.

---

### Login with Email/Password

**Endpoint**: `POST /auth/login`

**Content-Type**: `application/x-www-form-urlencoded`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Email address |
| password | string | Yes | Password |

```bash
# Login to existing account (saves session cookie)
curl -X POST https://common.ink/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=user@example.com&password=SecurePass123" \
  -c cookies.txt
```

**Response**: 303 redirect to `/notes` with session cookie set in `cookies.txt`.

---

### Google OIDC Sign-In

**Endpoint**: `GET /auth/google`

```bash
# Opens Google OAuth flow (use in browser)
open "https://common.ink/auth/google"
```

After Google authentication, the callback at `/auth/google/callback` sets the session cookie and redirects to `/notes`.

---

### Magic Link (Passwordless)

**Request Magic Link**:

**Endpoint**: `POST /auth/magic`

```bash
curl -X POST https://common.ink/auth/magic \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=user@example.com"
```

**Response**: 303 redirect to `/login?magic=sent`. A magic link is sent to the email. Clicking it verifies the token at `/auth/magic/verify?token=...` and logs you in.

---

### Password Reset

**Request Reset**:

**Endpoint**: `POST /auth/password-reset`

```bash
curl -X POST https://common.ink/auth/password-reset \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=user@example.com"
```

**Confirm Reset**:

**Endpoint**: `POST /auth/password-reset-confirm`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| token | string | Yes | Reset token from email |
| new_password | string | Yes | New password |

---

### Check Authentication Status

**Endpoint**: `GET /auth/whoami`

```bash
# With session cookie
curl https://common.ink/auth/whoami -b cookies.txt
```

**Note**: The `/auth/whoami` endpoint only supports session cookie authentication. For programmatic auth status checks, use the Notes API (e.g., `GET /api/notes`) with your PAT or OAuth token -- a `200` response confirms valid authentication.

**Response**:
```json
{
  "user_id": "user-550e8400-e29b-41d4-a716-446655440000",
  "authenticated": true
}
```

---

### Logout

**Endpoint**: `POST /auth/logout` or `GET /auth/logout`

```bash
curl -X POST https://common.ink/auth/logout \
  -b cookies.txt -c cookies.txt
```

**Response**: 303 redirect to `/`. The session cookie is cleared in `cookies.txt`.

---

## Personal Access Tokens API

PATs enable programmatic API access without session cookies. Ideal for:

- CLI tools and scripts
- CI/CD pipelines
- AI assistant integrations (Claude Code, ChatGPT)
- MCP server connections

### Create a PAT

Creates a new Personal Access Token. **Requires password re-authentication**.

**Note**: You can also create PATs through the web UI at [/tokens/new](/tokens/new), which is the recommended method.

**Endpoint**: `POST /api/tokens`

**Authentication**: Session cookie required

**Content-Type**: `application/json`

```json
{
  "name": "CLI Access Token",
  "scope": "read_write",
  "expires_in": 2592000,
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Descriptive name for the token |
| scope | string | No | Permission scope (default: `read_write`) |
| expires_in | integer | No | Seconds until expiry (default/max: 1 year) |
| email | string | Yes | Your email for re-authentication |
| password | string | Yes | Your password for re-authentication |

```bash
# Create a PAT (requires session cookie from login)
curl -X POST https://common.ink/api/tokens \
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

**Response** (201 Created):
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "My CLI Token",
  "token": "agentnotes_pat_user-550e8400-e29b-41d4-a716-446655440000_YWJjZGVm...",
  "scope": "read_write",
  "expires_at": "2026-03-03T12:00:00Z",
  "created_at": "2026-02-03T12:00:00Z"
}
```

**Important**: Save the `token` value securely - it cannot be retrieved later!

---

### List PATs

**Endpoint**: `GET /api/tokens`

```bash
curl https://common.ink/api/tokens -b cookies.txt
```

**Response**:
```json
{
  "tokens": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "My CLI Token",
      "scope": "read_write",
      "expires_at": "2026-03-03T12:00:00Z",
      "created_at": "2026-02-03T12:00:00Z",
      "last_used_at": "2026-02-03T14:30:00Z"
    }
  ]
}
```

---

### Revoke a PAT

**Endpoint**: `DELETE /api/tokens/{id}`

```bash
curl -X DELETE https://common.ink/api/tokens/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -b cookies.txt
```

**Response**: `204 No Content`

---

## Notes API

All notes endpoints require authentication via session cookie, PAT, or OAuth JWT.

### Base URL

```
https://common.ink/api
```

### List Notes

**Endpoint**: `GET /api/notes`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | integer | 50 | Max notes to return (max: 1000) |
| offset | integer | 0 | Number of notes to skip |

```bash
# With session cookie
curl "https://common.ink/api/notes?limit=10&offset=0" -b cookies.txt

# With PAT
curl "https://common.ink/api/notes?limit=10&offset=0" \
  -H "Authorization: Bearer agentnotes_pat_user-xxx_token..."
```

**Response**:
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

**Endpoint**: `POST /api/notes`

**Content-Type**: `application/json`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | Yes | Note title |
| content | string | No | Note content (markdown supported) |

```bash
curl -X POST https://common.ink/api/notes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer agentnotes_pat_user-xxx_token..." \
  -d '{
    "title": "Meeting Notes",
    "content": "## Agenda\n- Item 1\n- Item 2"
  }'
```

**Response** (201 Created):
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

**Endpoint**: `GET /api/notes/{id}`

```bash
curl https://common.ink/api/notes/c4e2d1a3-6b7f-8901-2345-abcdef678901 \
  -H "Authorization: Bearer agentnotes_pat_user-xxx_token..."
```

**Response**: Same format as Create Note response.

---

### Update Note

**Endpoint**: `PUT /api/notes/{id}`

**Content-Type**: `application/json`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | No | New title |
| content | string | No | New content |

```bash
curl -X PUT https://common.ink/api/notes/c4e2d1a3-6b7f-8901-2345-abcdef678901 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer agentnotes_pat_user-xxx_token..." \
  -d '{
    "title": "Updated Title",
    "content": "Updated content..."
  }'
```

---

### Delete Note

**Endpoint**: `DELETE /api/notes/{id}`

```bash
curl -X DELETE https://common.ink/api/notes/c4e2d1a3-6b7f-8901-2345-abcdef678901 \
  -H "Authorization: Bearer agentnotes_pat_user-xxx_token..."
```

**Response**: `204 No Content`

---

### Search Notes

**Endpoint**: `POST /api/notes/search`

**Content-Type**: `application/json`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| query | string | Yes | Search query (FTS5 syntax supported) |

```bash
curl -X POST https://common.ink/api/notes/search \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer agentnotes_pat_user-xxx_token..." \
  -d '{"query": "meeting agenda"}'
```

**Response**:
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

**Note**: Uses FTS5 full-text search. Lower (more negative) rank values indicate better matches. Supports standard SQLite FTS5 query syntax.

---

## MCP (Model Context Protocol)

common.ink implements the MCP 2025-03-26 specification using Streamable HTTP transport.

### Endpoint

```
POST /mcp
```

### Headers

| Header | Value | Required |
|--------|-------|----------|
| Content-Type | application/json | Yes |
| Accept | application/json, text/event-stream | Yes |
| Authorization | Bearer {token} | Yes |

### Available Tools

| Tool | Description |
|------|-------------|
| `note_list` | List notes with pagination support |
| `note_view` | Retrieve a single note by its ID |
| `note_create` | Create a new note with a title and optional content |
| `note_update` | Update an existing note's title and/or content |
| `note_search` | Search notes using full-text search (FTS5) |
| `note_delete` | Delete a note by its ID |

### List Available Tools

```bash
curl -X POST https://common.ink/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer agentnotes_pat_user-xxx_token..." \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "note_create",
        "description": "Create a new note with a title and optional content",
        "inputSchema": {
          "type": "object",
          "properties": {
            "title": {"type": "string", "description": "The title of the note (required)"},
            "content": {"type": "string", "description": "The content/body of the note (optional)"}
          },
          "required": ["title"]
        }
      },
      {
        "name": "note_delete",
        "description": "Delete a note by its ID",
        "inputSchema": {
          "type": "object",
          "properties": {
            "id": {"type": "string", "description": "The unique identifier of the note to delete"}
          },
          "required": ["id"]
        }
      },
      {
        "name": "note_list",
        "description": "List notes with pagination support",
        "inputSchema": {
          "type": "object",
          "properties": {
            "limit": {"type": "integer", "description": "Maximum number of notes to return (default: 50, max: 1000)"},
            "offset": {"type": "integer", "description": "Number of notes to skip for pagination (default: 0)"}
          }
        }
      },
      {
        "name": "note_search",
        "description": "Search notes using full-text search (FTS5)",
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": {"type": "string", "description": "The search query to match against note titles and content"}
          },
          "required": ["query"]
        }
      },
      {
        "name": "note_update",
        "description": "Update an existing note's title and/or content",
        "inputSchema": {
          "type": "object",
          "properties": {
            "id": {"type": "string", "description": "The unique identifier of the note to update"},
            "title": {"type": "string", "description": "The new title for the note (optional)"},
            "content": {"type": "string", "description": "The new content for the note (optional)"}
          },
          "required": ["id"]
        }
      },
      {
        "name": "note_view",
        "description": "Retrieve a single note by its ID",
        "inputSchema": {
          "type": "object",
          "properties": {
            "id": {"type": "string", "description": "The unique identifier of the note to retrieve"}
          },
          "required": ["id"]
        }
      }
    ]
  }
}
```

---

### Create Note via MCP

```bash
curl -X POST https://common.ink/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer agentnotes_pat_user-xxx_token..." \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "note_create",
      "arguments": {
        "title": "Created via MCP",
        "content": "This note was created by an AI assistant."
      }
    },
    "id": 2
  }'
```

---

### Search Notes via MCP

```bash
curl -X POST https://common.ink/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer agentnotes_pat_user-xxx_token..." \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "note_search",
      "arguments": {
        "query": "meeting"
      }
    },
    "id": 3
  }'
```

---

### List Notes via MCP

```bash
curl -X POST https://common.ink/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer agentnotes_pat_user-xxx_token..." \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "note_list",
      "arguments": {
        "limit": 10,
        "offset": 0
      }
    },
    "id": 4
  }'
```

---

## Connecting AI Assistants

### Claude Code

Add to your Claude Code MCP configuration (`~/.claude/mcp.json`):

```json
{
  "mcpServers": {
    "common-ink": {
      "url": "https://common.ink/mcp",
      "transport": "streamable-http",
      "headers": {
        "Authorization": "Bearer agentnotes_pat_user-xxx_token..."
      }
    }
  }
}
```

### ChatGPT (Custom GPT)

1. Create a PAT at [Tokens](/tokens)
2. In ChatGPT's custom GPT settings, add an action:
   - **Server URL**: `https://common.ink`
   - **Authentication**: API Key (Bearer Token)
   - **API Key**: Your PAT

### Other MCP Clients

Use the official MCP SDK for your language:
- [TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
- [Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [Go SDK](https://github.com/modelcontextprotocol/go-sdk)

---

## OAuth 2.1 Provider

common.ink implements an OAuth 2.1 provider for third-party integrations.

### Well-Known Metadata

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/oauth-authorization-server` | Authorization server metadata |
| `GET /.well-known/oauth-protected-resource` | Protected resource metadata |
| `GET /.well-known/jwks.json` | JSON Web Key Set for token verification |

### Dynamic Client Registration

**Endpoint**: `POST /oauth/register`

**Note**: Redirect URIs must be in the server's allowlist. Currently supported redirect URIs:
- `https://chatgpt.com/connector_platform_oauth_redirect` (ChatGPT)
- `https://platform.openai.com/apps-manage/oauth` (OpenAI platform)
- `https://claude.ai/api/mcp/auth_callback` (Claude)
- `https://claude.com/api/mcp/auth_callback` (Claude)

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

### Authorization

```
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=REDIRECT_URI&
  scope=notes:read%20notes:write&
  code_challenge=PKCE_CHALLENGE&
  code_challenge_method=S256&
  state=RANDOM_STATE
```

### Token Exchange

**Endpoint**: `POST /oauth/token`

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
| Paid | 6000 | 10000 |

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

### HTTP Status Codes

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

### 401 Unauthorized Response

When authentication fails, the response includes a `WWW-Authenticate` header:

```
WWW-Authenticate: Bearer resource_metadata="https://common.ink/.well-known/oauth-protected-resource", error="invalid_token", error_description="Invalid personal access token"
```

---

## Complete Workflow Example

```bash
#!/bin/bash
# Complete API workflow example

# 1. Register (or login if account exists)
curl -X POST https://common.ink/auth/register \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=demo@example.com&password=DemoPass123" \
  -c cookies.txt -s > /dev/null

# 2. Create a PAT for API access
PAT=$(curl -s -X POST https://common.ink/api/tokens \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "name": "Demo Token",
    "email": "demo@example.com",
    "password": "DemoPass123"
  }' | jq -r '.token')

echo "Your PAT: $PAT"

# 3. Create a note using the PAT
echo "Creating note..."
curl -X POST https://common.ink/api/notes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $PAT" \
  -d '{
    "title": "API Test Note",
    "content": "Created via REST API!"
  }'

# 4. List all notes
echo -e "\n\nListing notes..."
curl https://common.ink/api/notes \
  -H "Authorization: Bearer $PAT"

# 5. Search notes
echo -e "\n\nSearching notes..."
curl -X POST https://common.ink/api/notes/search \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $PAT" \
  -d '{"query": "API"}'

# 6. Create note via MCP
echo -e "\n\nCreating note via MCP..."
curl -X POST https://common.ink/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer $PAT" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "note_create",
      "arguments": {
        "title": "MCP Test Note",
        "content": "Created via MCP!"
      }
    },
    "id": 1
  }'
```

---

## Health Check

**Endpoint**: `GET /health`

No authentication required.

```bash
curl https://common.ink/health
```

**Response**:
```json
{
  "status": "healthy",
  "service": "remote-notes",
  "milestone": 3
}
```

---

## Support

For API support, contact: api-support@common.ink
