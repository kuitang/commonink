# Server-Side Errors Found During E2E Test Refactoring

Date: 2026-02-03

## 1. MCP Endpoint Rejects Valid OAuth Bearer Tokens (FIXED)

**Location:** `POST /mcp` endpoint

**Symptom:**
```
Expected 200, got 401: Unauthorized: no session
```

**Details:**
- OAuth flow completes successfully (access token obtained via `golang.org/x/oauth2`)
- MCP request includes valid `Authorization: Bearer <token>` header
- Server returns 401 with "no session" error

**Root Cause:**
The `RequireAuth` middleware only checked for API Key tokens and session cookies, not OAuth JWT tokens.

**Fix Applied:**
1. Added `OAuthTokenVerifier` interface to `internal/auth/middleware.go`
2. Added `WithOAuthVerifier()` method to configure JWT verification
3. Extended `RequireAuth` to validate OAuth JWT tokens:
   - Check Bearer token
   - If API Key token (starts with `agentnotes_key_`): validate as API Key
   - If OAuth JWT: verify signature/claims and extract user ID
   - Fall back to session cookie if no Bearer token
4. Created adapter in `cmd/server/main.go` to wire OAuth provider's `VerifyAccessToken`

**Files modified:**
- `cmd/server/main.go` - Added OAuthProviderVerifier adapter, wired middleware
- `internal/auth/middleware.go` - Added OAuth JWT verification support

---

## 2. Missing WWW-Authenticate Header on 401 Response (FIXED)

**Location:** `POST /mcp` endpoint (unauthorized request)

**Symptom:**
```
Expected Bearer challenge, got: (empty)
```

**Details:**
- When making an unauthenticated request to `/mcp`
- Server returns 401 but without `WWW-Authenticate: Bearer ...` header
- Per RFC 6750, 401 responses MUST include WWW-Authenticate header

**Fix Applied:**
Added `writeUnauthorized()` helper to `RequireAuth` middleware that sets proper WWW-Authenticate header:
```go
func (m *Middleware) writeUnauthorized(w http.ResponseWriter, errorType, errorDesc string) {
    challenge := fmt.Sprintf(`Bearer resource_metadata="%s", error="%s", error_description="%s"`,
        m.resourceMetadataURL, errorType, errorDesc)
    w.Header().Set("WWW-Authenticate", challenge)
    http.Error(w, "Unauthorized: "+errorDesc, http.StatusUnauthorized)
}
```

**Files modified:**
- `internal/auth/middleware.go` - Added writeUnauthorized helper

---

## 3. OAuth Cookie Secure Flag Mismatch (FIXED)

**Location:** `internal/oauth/handlers.go`

**Symptom:**
OAuth consent flow failed with "Missing authorization request" in HTTP (non-TLS) environments.

**Details:**
- OAuth `oauth_auth_req` cookie was hardcoded with `Secure: true`
- Session cookies correctly used `auth.GetSecureCookies()` which respects environment
- Cookie not sent over HTTP connections, breaking consent flow

**Fix Applied:**
Changed OAuth handlers to use `auth.GetSecureCookies()` instead of hardcoded `true`:
```go
http.SetCookie(w, &http.Cookie{
    Name:     "oauth_auth_req",
    Secure:   auth.GetSecureCookies(), // Was: true
    ...
})
```
