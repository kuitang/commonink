# Live Production Test Results -- Post-Argon2id Fix

**Date:** 2026-02-16 (updated 10:25 UTC)
**Target:** https://commonink.fly.dev/ (also https://common.ink)
**Test Users:** kuitang+curltest-*@gmail.com, kuitang+apitest-*@gmail.com
**Argon2id Params:** m=19456 KiB (19 MiB), t=2, p=1 (reduced from m=65536 / 64 MiB)
**VM:** Fly.io shared-cpu-1x, 256 MB RAM

---

## Post-Argon2id Fix: Performance Comparison

The Argon2id memory parameter was reduced from 64 MiB to 19 MiB (OWASP lighter alternative) to fix OOM kills on the 256 MB Fly.io VM.

| Operation | Before (64 MiB / bcrypt) | After (19 MiB Argon2id) | Improvement |
|-----------|--------------------------|-------------------------|-------------|
| Registration (hash) | 502 timeout or 9+ sec | **0.20-0.24s** | No more OOM/timeout |
| Login (verify) | 502 on cold start, 0.34s warm | **0.17-0.22s** | No more cold-start 502 |
| API key creation (re-auth) | Intermittent 502 | **0.17s** | Reliable |
| Second registration (warm) | N/A | **0.20s** | Consistent |

**Key result:** Zero 502 errors during the entire test session. The previous 64 MiB parameter caused the process to exceed the 256 MB VM memory limit, triggering OOM kills. At 19 MiB, Argon2id completes in ~50ms server-side (visible as TTFB ~55ms), well within limits.

---

## Summary

| Category | Tests | Pass | Fail | Notes |
|----------|-------|------|------|-------|
| Health & Discovery | 4 | 4 | 0 | All endpoints return correct JSON |
| Static Pages | 5 | 5 | 0 | All render HTML correctly |
| Auth Pages (HTML) | 3 | 3 | 0 | Login, register, password-reset all render |
| Auth API | 6 | 6 | 0 | Register, login, whoami, magic link, password-reset, logout |
| OAuth 2.1 Full Flow | 6 | 6 | 0 | Complete PKCE flow end-to-end |
| MCP Endpoint | 5 | 5 | 0 | Session, OAuth, API key auth + unauthenticated rejection |
| JSON API CRUD | 7 | 7 | 0 | Create, list, read, update, search, delete, verify 404 |
| API Keys | 4 | 4 | 0 | Create, list, use for MCP, revoke + verify revocation |
| Redirects & Misc | 3 | 3 | 0 | Root redirects, favicon, common.ink domain |
| **TOTAL** | **43** | **43** | **0** | |

### Observations (not failures)

1. **Health endpoint still says milestone:4** -- consider updating to reflect current milestone.

2. **Discovery URLs reference https://common.ink** -- correct for production; both commonink.fly.dev and common.ink resolve to the same app.

3. **Form-encoded `+` in emails** -- curl `-d` sends `+` as space per application/x-www-form-urlencoded spec. Users must use `--data-urlencode` or manually encode as `%2B`. This is correct HTTP behavior, not a server bug, but worth noting in API docs.

---

## 1. Health & Discovery

### GET /health
- **Status:** 200 OK (0.14s)
- **Response:** `{"status":"healthy","service":"commonink","milestone":4}`
- **Verdict:** PASS

### GET /.well-known/oauth-protected-resource
- **Status:** 200 OK (0.15s)
- **Response:**
```json
{
  "resource": "https://common.ink",
  "authorization_servers": ["https://common.ink"],
  "scopes_supported": ["notes:read", "notes:write"]
}
```
- **Verdict:** PASS

### GET /.well-known/oauth-authorization-server
- **Status:** 200 OK (0.15s)
- **Response:**
```json
{
  "issuer": "https://common.ink",
  "authorization_endpoint": "https://common.ink/oauth/authorize",
  "token_endpoint": "https://common.ink/oauth/token",
  "registration_endpoint": "https://common.ink/oauth/register",
  "jwks_uri": "https://common.ink/.well-known/jwks.json",
  "scopes_supported": ["notes:read", "notes:write"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"]
}
```
- **Verdict:** PASS -- Full RFC 8414 metadata with PKCE support

### GET /.well-known/jwks.json
- **Status:** 200 OK (0.14s)
- **Response:**
```json
{
  "keys": [{
    "kty": "OKP",
    "use": "sig",
    "kid": "ixctHLMHaFo",
    "alg": "EdDSA",
    "crv": "Ed25519",
    "x": "W19gf0GAZ4RRjXkYjp32P3RhaZc3kf6DWt2QiQ-DTPQ"
  }]
}
```
- **Verdict:** PASS -- Ed25519 key for JWT verification

---

## 2. Static Pages

| Page | Status | Time | Title | Verdict |
|------|--------|------|-------|---------|
| GET /login | 200 | 0.15s | Sign In - common.ink | PASS |
| GET /register | 200 | 0.22s | Create Account - common.ink | PASS |
| GET /password-reset | 200 | 0.14s | Reset Password - common.ink | PASS |
| GET /privacy | 200 | 0.16s | Privacy Policy - common.ink | PASS |
| GET /terms | 200 | 0.14s | Terms of Service - common.ink | PASS |
| GET /about | 200 | 0.16s | About - common.ink | PASS |
| GET /docs/api | 200 | 0.22s | API Documentation - common.ink | PASS |
| GET /favicon.ico | 200 | 0.15s | (1103 bytes binary) | PASS |

---

## 3. Auth API - Registration & Login (Argon2id Timing)

### POST /auth/register (first registration)
- **Email:** kuitang+curltest-1771237117@gmail.com
- **Status:** 303 See Other -> /notes
- **Total Time:** 0.232s | **TTFB:** 0.055s
- **Set-Cookie:** `session_id=S3UkW_...; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`
- **Verdict:** PASS -- Argon2id hash created in ~55ms server-side, no OOM

### POST /auth/register (second registration, warm)
- **Email:** kuitang+curltest-1771237139@gmail.com
- **Status:** 303 See Other -> /notes
- **Total Time:** 0.198s | **TTFB:** 0.053s
- **Verdict:** PASS -- Consistent timing

### POST /auth/register (third registration, with %2B encoding)
- **Email:** kuitang+apitest-1771237393@gmail.com
- **Status:** 303 See Other -> /notes
- **Total Time:** 0.199s | **TTFB:** 0.053s
- **Verdict:** PASS

### POST /auth/login
- **Status:** 303 See Other -> /notes
- **Total Time:** 0.172-0.219s | **TTFB:** 0.056s
- **Set-Cookie:** new session_id
- **Verdict:** PASS -- Argon2id verify completes reliably, no 502 on any attempt

### GET /auth/whoami (with session cookie)
- **Status:** 200 OK (0.15s)
- **Response:** `{"user_id":"user-f092965b-2497-5b6c-95a5-2127f5423a8d","authenticated":true}`
- **Verdict:** PASS

### POST /auth/magic (magic link request)
- **Email:** kuitang+magictest@gmail.com
- **Status:** 303 See Other -> /login?magic=sent
- **Time:** 0.316s (includes Resend API call)
- **Verdict:** PASS

### POST /auth/password-reset
- **Email:** kuitang+curltest@gmail.com
- **Status:** 303 See Other -> /login?reset=requested
- **Time:** 0.233s
- **Verdict:** PASS

### POST /auth/logout
- **Status:** 303 See Other -> /
- **Set-Cookie:** session_id cleared (Max-Age=0)
- **Verify:** GET /auth/whoami returns `{"authenticated":false}`
- **Verdict:** PASS

### Root path redirect behavior
- **GET / (no auth):** 302 -> /login (0.14s)
- **GET / (with session):** 302 -> /notes (0.15s)
- **Verdict:** PASS

---

## 4. OAuth 2.1 Full Flow (PKCE)

### POST /oauth/register (DCR)
- **Status:** 201 Created (0.15s)
- **Response:**
```json
{
  "client_id": "m47Vem33th0ylViLgBM5rlRfB3TSrDG-g8Z8EHAtRkY",
  "client_id_issued_at": 1771237147,
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "client_name": "CurlTest-2026-02-16"
}
```
- **Verdict:** PASS -- Public client registration works

### GET /oauth/authorize (with PKCE)
- **Status:** 200 OK (0.17s)
- **Set-Cookie:** `oauth_auth_req=<base64>; Path=/oauth; Max-Age=600; HttpOnly; Secure; SameSite=Lax`
- **Content:** HTML consent page: "Authorize CurlTest-2026-02-16 - common.ink"
- **Verdict:** PASS

### POST /oauth/consent (decision=allow)
- **Status:** 302 Found (0.15s)
- **Location:** `http://localhost:3000/callback?code=RxZYQtEV1gsyq24h1JU8iPrUCCF3aNzYGh0JLL0QkRU&state=OPLIFCYnSUs348WvEbnRrq0VAPbT3gZkpqygppFVGec`
- **State verification:** PASS (returned state matches sent state)
- **Verdict:** PASS

### POST /oauth/token (authorization_code + PKCE)
- **Status:** 200 OK (0.14s)
- **Response:**
```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<redacted>",
  "scope": "notes:read notes:write"
}
```
- **Verdict:** PASS -- EdDSA JWT access token + opaque refresh token

### POST /oauth/token (refresh_token)
- **Status:** 200 OK (0.14s)
- **Response:** New access_token and refresh_token issued (token rotation)
- **Verdict:** PASS

---

## 5. MCP Endpoint

### POST /mcp - tools/list (session cookie)
- **Status:** 200 OK (0.14s)
- **Tools:** note_create, note_delete, note_list, note_search, note_update, note_view
- **Verdict:** PASS

### POST /mcp - tools/list (OAuth Bearer)
- **Status:** 200 OK (0.16s)
- **Tools:** Same 6 tools
- **Verdict:** PASS -- OAuth JWT authentication works

### POST /mcp - tools/list (API key)
- **Status:** 200 OK (0.15s)
- **Tools:** Same 6 tools
- **Verdict:** PASS -- API key authentication works

### POST /mcp - note_create (API key)
- **Status:** 200 OK (0.15s)
- **Response:** JSON-RPC result with created note (id: 582e6328-37ec-40e5-920c-2063d0ace9cc)
- **Verdict:** PASS

### POST /mcp - unauthenticated
- **Status:** 401 Unauthorized (0.15s)
- **WWW-Authenticate:** `Bearer resource_metadata="https://common.ink/.well-known/oauth-protected-resource", error="missing_token", error_description="No valid authentication provided"`
- **Verdict:** PASS -- Correct RFC 6750 header

### POST /mcp - revoked API key
- **Status:** 401 Unauthorized (0.14s)
- **WWW-Authenticate:** `...error="invalid_token", error_description="Invalid API key"`
- **Verdict:** PASS -- Revoked keys are properly rejected

---

## 6. JSON API CRUD

### POST /api/notes (create)
- **Status:** 201 Created (0.15s)
- **Response:**
```json
{
  "id": "6986acb5-97b6-4e2d-bfb9-8c908ef79088",
  "title": "Comprehensive Test Note",
  "content": "Testing full CRUD after Argon2id fix. Memory reduced from 64 MiB to 19 MiB.",
  "is_public": false,
  "created_at": "2026-02-16T10:25:18.263320199Z",
  "updated_at": "2026-02-16T10:25:18.263320199Z"
}
```
- **Verdict:** PASS

### GET /api/notes (list)
- **Status:** 200 OK (0.15s)
- **Response:** `{"notes":[...],"total_count":3,"limit":50,"offset":0}`
- **Verdict:** PASS -- Pagination metadata included

### GET /api/notes/{id} (read)
- **Status:** 200 OK (0.15s)
- **Verdict:** PASS

### PUT /api/notes/{id} (update)
- **Status:** 200 OK (0.14s)
- **Verdict:** PASS -- Title and content updated, updated_at changed

### POST /api/notes/search
- **Status:** 200 OK (0.14-0.15s)
- **Query:** "sqlite fts5"
- **Response:** 1 result with BM25 rank score (-0.86)
- **Verdict:** PASS -- FTS5 search with ranking working in production

### DELETE /api/notes/{id}
- **Status:** 204 No Content (0.14s)
- **Verdict:** PASS

### GET /api/notes/{id} (after delete)
- **Status:** 404 Not Found (0.14s)
- **Response:** `{"error":"Note not found"}`
- **Verdict:** PASS -- Delete confirmed

---

## 7. API Keys

### POST /api/keys (create)
- **Status:** 201 Created (0.17s)
- **Response:**
```json
{
  "id": "839a013e-08d3-4864-9fc3-80c63b99174a",
  "name": "plus-test-key",
  "token": "agentnotes_key_user-f092965b-2497-5b6c-95a5-2127f5423a8d_8BaenpQD...",
  "scope": "read_write",
  "expires_at": "2026-02-17T10:23:13.825066982Z",
  "created_at": "2026-02-16T10:23:13.825066982Z"
}
```
- **Timing note:** API key creation includes Argon2id password re-verification -- completes in 0.17s (previously 502 with bcrypt/64 MiB)
- **Verdict:** PASS

### GET /api/keys (list)
- **Status:** 200 OK (0.14s)
- **Response:** `{"tokens":[{"id":"839a013e-...","name":"plus-test-key","scope":"read_write",...}]}`
- **Verdict:** PASS

### API key used for MCP (tools/list + note_create)
- **Status:** 200 OK for both
- **Verdict:** PASS

### DELETE /api/keys/{id} (revoke)
- **Status:** 204 No Content (0.15s)
- **Verify:** GET /api/keys returns `{"tokens":[]}` (empty)
- **Verify:** POST /mcp with revoked key returns 401
- **Verdict:** PASS

---

## 8. Email Endpoints

| Endpoint | Status | Time | Redirect | Verdict |
|----------|--------|------|----------|---------|
| POST /auth/magic | 303 | 0.32s | /login?magic=sent | PASS |
| POST /auth/password-reset | 303 | 0.23s | /login?reset=requested | PASS |

Both endpoints accept the request and redirect correctly. Actual email delivery not verified (would need to check inbox).

---

## Performance Summary (All Timings)

| Operation | Time (total) | TTFB | Status |
|-----------|-------------|------|--------|
| Health check | 0.14s | -- | 200 |
| Discovery endpoints | 0.14-0.15s | -- | 200 |
| Static pages (HTML) | 0.14-0.22s | -- | 200 |
| **Registration (Argon2id hash)** | **0.20-0.24s** | **0.053-0.055s** | **303** |
| **Login (Argon2id verify)** | **0.17-0.22s** | **0.056s** | **303** |
| Whoami | 0.15s | -- | 200 |
| OAuth DCR | 0.15s | -- | 201 |
| OAuth authorize | 0.17s | -- | 200 |
| OAuth consent | 0.15s | -- | 302 |
| OAuth token exchange | 0.14s | -- | 200 |
| OAuth token refresh | 0.14s | -- | 200 |
| MCP tools/list | 0.14-0.16s | -- | 200 |
| MCP note_create | 0.15s | -- | 200 |
| Note CRUD (create) | 0.15s | -- | 201 |
| Note CRUD (list) | 0.15s | -- | 200 |
| Note CRUD (read) | 0.15s | -- | 200 |
| Note CRUD (update) | 0.14s | -- | 200 |
| Note CRUD (search/FTS5) | 0.14-0.15s | -- | 200 |
| Note CRUD (delete) | 0.14s | -- | 204 |
| API key create (w/ re-auth) | 0.17s | -- | 201 |
| API key revoke | 0.15s | -- | 204 |
| Magic link request | 0.32s | -- | 303 |
| Password reset request | 0.23s | -- | 303 |
| Logout | 0.14s | -- | 303 |

**Network baseline:** ~135ms (TLS handshake + round-trip from test client to Fly.io FRA region). Server-side processing adds 15-90ms depending on operation. Argon2id hashing/verification adds ~50ms server-side.

---

## Security Observations

1. **Session cookies:** HttpOnly, Secure, SameSite=Lax, 30-day expiry -- GOOD
2. **OAuth auth_req cookie:** Scoped to /oauth path, 10-min expiry, HttpOnly, Secure -- GOOD
3. **PKCE enforcement:** S256 code_challenge_method required -- GOOD
4. **State parameter:** Returned correctly, verified to match -- GOOD
5. **401 WWW-Authenticate:** RFC 6750 compliant with resource_metadata URL -- GOOD
6. **API key format:** `agentnotes_key_{user_id}_{random}` -- allows quick user lookup
7. **API key revocation:** Immediately effective, revoked keys return 401 -- GOOD
8. **Logout:** Session cookie cleared (Max-Age=0), whoami confirms unauthenticated -- GOOD
9. **Argon2id params:** m=19456, t=2, p=1 -- meets OWASP lighter recommendation for memory-constrained environments
10. **DCR redirect URI validation:** Only allows localhost -- GOOD for development

---

## Remaining Recommendations

1. **Update health endpoint milestone** from 4 to current milestone.
2. **Document curl `+` encoding** -- API docs should note that `+` in form data must be URL-encoded as `%2B`, or use `--data-urlencode` with curl. (This is standard HTTP behavior but a common gotcha.)
3. **Verify email delivery** -- Magic link and password reset endpoints return correct redirects; actual email receipt from Resend should be verified separately.
