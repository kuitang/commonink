# Milestone 3.5: OAuth 2.1 Provider (For ChatGPT + Claude Code)

**Goal**: Implement OAuth 2.1 provider conforming to MCP authorization spec so **both ChatGPT and Claude Code** can authenticate users and access their notes via MCP.

**Prerequisites**: Milestone 3 complete (rate limiting, public notes, web UI, consent screens)

---

## ⚠️ CRITICAL: Read Before Starting

**Before implementing ANY code in this milestone, the agent MUST read the entire official OpenAI authentication specification:**

```
chatgpt-apps/auth.md (lines 1-281)
```

This file contains the authoritative specification for ChatGPT OAuth connector requirements. Every implementation detail must conform to this document. Do not rely on summaries - read the full file.

**Additional reference files:**
- `chatgpt-apps/test.md` - Testing procedures
- `chatgpt-apps/connect.md` - Connection setup
- `chatgpt-apps/deploy.md` - Deployment requirements

---

## Custom Conformance Test Client (REQUIRED)

**No third-party conformance suite exists for ChatGPT OAuth flow.** The OpenID Conformance Suite tests generic OAuth 2.0, NOT the MCP authorization spec.

This milestone requires implementing a **custom conformance test client** (`tests/conformance/chatgpt_oauth_test.go`) that simulates exactly what ChatGPT does, as specified in `chatgpt-apps/auth.md`.

### Test Flow (From auth.md lines 99-119)

The conformance client MUST test this exact 5-step flow:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ChatGPT OAuth Flow (auth.md)                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Step 1: Fetch Protected Resource Metadata                          │
│  ─────────────────────────────────────────                          │
│  GET /.well-known/oauth-protected-resource                          │
│  → Extract: resource, authorization_servers                         │
│                                                                     │
│  Step 2: Fetch Auth Server Metadata                                 │
│  ──────────────────────────────────                                 │
│  GET {authorization_server}/.well-known/oauth-authorization-server  │
│  → Extract: registration_endpoint, authorization_endpoint,          │
│             token_endpoint                                          │
│  → FAIL IF: code_challenge_methods_supported missing S256           │
│                                                                     │
│  Step 3: Dynamic Client Registration                                │
│  ───────────────────────────────────                                │
│  POST {registration_endpoint}                                       │
│  Body: { redirect_uris, client_name, grant_types, response_types }  │
│  → Extract: client_id, client_secret                                │
│                                                                     │
│  Step 4: Authorization Code + PKCE Flow                             │
│  ──────────────────────────────────────                             │
│  GET {authorization_endpoint}?                                      │
│      client_id={client_id}&                                         │
│      redirect_uri={redirect_uri}&                                   │
│      response_type=code&                                            │
│      scope={scopes}&                                                │
│      state={random}&                                                │
│      code_challenge={S256_challenge}&                               │
│      code_challenge_method=S256&                                    │
│      resource={resource}           ← CRITICAL: ChatGPT sends this   │
│  → User authenticates and consents                                  │
│  → Redirect with: code, state                                       │
│                                                                     │
│  Step 5: Token Exchange                                             │
│  ──────────────────────                                             │
│  POST {token_endpoint}                                              │
│  Body: grant_type=authorization_code&                               │
│        client_id={client_id}&                                       │
│        client_secret={client_secret}&                               │
│        code={code}&                                                 │
│        redirect_uri={redirect_uri}&                                 │
│        code_verifier={verifier}&                                    │
│        resource={resource}         ← CRITICAL: ChatGPT sends this   │
│  → Extract: access_token, refresh_token, expires_in                 │
│                                                                     │
│  Step 6: Token Verification (Your Server's Responsibility)          │
│  ─────────────────────────────────────────────────────────          │
│  For each MCP request with Authorization: Bearer {token}            │
│  → Verify signature via JWKS                                        │
│  → Verify iss matches authorization server                          │
│  → Verify aud matches resource                                      │
│  → Verify exp > now                                                 │
│  → Verify required scopes present                                   │
│                                                                     │
│  Step 7: Auth Trigger Response (When No Valid Token)                │
│  ───────────────────────────────────────────────────                │
│  Return MCP response with _meta["mcp/www_authenticate"]             │
│  (See auth.md lines 257-280)                                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Conformance Test Implementation

**File**: `tests/conformance/oauth_conformance_test.go`

> **NOTE**: The unified conformance test implementation has been moved to the actual test file at `tests/conformance/oauth_conformance_test.go`. This file contains a single unified test client that supports BOTH ChatGPT (confidential client) and Claude (public client) modes, eliminating code duplication between the two flows.
>
> The test file uses a `ClientMode` type to switch between:
> - `ClientModeChatGPT`: Confidential client with `client_secret` on token endpoint
> - `ClientModeClaude`: Public client without `client_secret` (PKCE-only)
>
> Common code for Steps 1, 2, 4, 6, and 7 is shared. Client-specific code for Step 3 (DCR) and Step 5 (Token Exchange) is handled based on mode.

**Run conformance tests:**
```bash
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)"
go test -v ./tests/conformance/...
```

---

## Claude (Code CLI + Web) MCP OAuth Conformance Test

**Claude Code CLI** and **Claude.ai web** use the **IDENTICAL OAuth flow** when connecting to remote MCP servers as MCP clients.

Both require your MCP server to support:
- **Public OAuth client** (`token_endpoint_auth_method: "none"`)
- **Dynamic Client Registration (DCR)** - RFC 7591 **REQUIRED**
- **PKCE with S256** - **REQUIRED**
- **Same callback URL**: `https://claude.ai/api/mcp/auth_callback`

Reference: [Claude Code MCP Docs](https://code.claude.com/docs/en/mcp) - "Use `/mcp` to authenticate with remote servers that require OAuth 2.0 authentication"

### Claude vs ChatGPT OAuth Differences

| Feature | Claude (Code CLI + Web) | ChatGPT |
|---------|-------------------------|---------|
| **Callback URL** | `https://claude.ai/api/mcp/auth_callback` | `https://chatgpt.com/connector_platform_oauth_redirect` |
| **Future Callback** | `https://claude.com/api/mcp/auth_callback` | `https://platform.openai.com/apps-manage/oauth` |
| **Client Name** | `"claudeai"` | `"ChatGPT"` |
| **Token Auth Method** | `"none"` (**public client**) | `client_secret_post` / `client_secret_basic` |
| **Client Secret on Token** | **NO** (PKCE only) | **YES** |
| **DCR Requirement** | **REQUIRED** | Required |
| **MCP Auth Spec** | 2025-03-26, 2025-06-18, 2025-11-25 | 2025-06-18 |
| **Custom Client ID/Secret** | Supported (fallback for non-DCR) | Not documented |

**CRITICAL DIFFERENCE**: Claude uses `token_endpoint_auth_method: "none"`, meaning it's a **public client** and does NOT send `client_secret` on the `/oauth/token` endpoint. Your server MUST support token exchange with PKCE proof only (no client_secret).

### Claude Code OAuth Flow

Reference: [Building Custom Connectors](https://support.claude.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Claude Code OAuth Flow                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Step 1: Fetch Protected Resource Metadata (same as ChatGPT)        │
│  ─────────────────────────────────────────────────────────          │
│  GET /.well-known/oauth-protected-resource                          │
│  → Extract: resource, authorization_servers                         │
│                                                                     │
│  Step 2: Fetch Auth Server Metadata (same as ChatGPT)               │
│  ────────────────────────────────────────────────────               │
│  GET {authorization_server}/.well-known/oauth-authorization-server  │
│  → FAIL IF: code_challenge_methods_supported missing S256           │
│                                                                     │
│  Step 3: Dynamic Client Registration (DIFFERENT!)                   │
│  ────────────────────────────────────────────────                   │
│  POST {registration_endpoint}                                       │
│  Body: {                                                            │
│      "client_name": "claudeai",                                     │
│      "grant_types": ["authorization_code", "refresh_token"],        │
│      "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],  │
│      "response_types": ["code"],                                    │
│      "token_endpoint_auth_method": "none"  ← PUBLIC CLIENT!         │
│  }                                                                  │
│  → Extract: client_id (NO client_secret needed for token endpoint)  │
│                                                                     │
│  Step 4: Authorization Code + PKCE Flow (same as ChatGPT)           │
│  ──────────────────────────────────────────────────────             │
│  GET {authorization_endpoint}?                                      │
│      client_id={client_id}&                                         │
│      redirect_uri=https://claude.ai/api/mcp/auth_callback&          │
│      response_type=code&                                            │
│      scope={scopes}&                                                │
│      state={random}&                                                │
│      code_challenge={S256_challenge}&                               │
│      code_challenge_method=S256&                                    │
│      resource={resource}                                            │
│                                                                     │
│  Step 5: Token Exchange (DIFFERENT - NO client_secret!)             │
│  ──────────────────────────────────────────────────────             │
│  POST {token_endpoint}                                              │
│  Body: grant_type=authorization_code&                               │
│        client_id={client_id}&                                       │
│        code={code}&                                                 │
│        redirect_uri={redirect_uri}&                                 │
│        code_verifier={verifier}                                     │
│        ↑ NO client_secret (public client with PKCE)                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Claude-specific Test Details

The Claude-specific test logic is included in the unified test file at `tests/conformance/oauth_conformance_test.go`. Key differences from ChatGPT:

- **Step 3 (DCR)**: Includes `token_endpoint_auth_method: "none"` in the registration request
- **Step 5 (Token Exchange)**: Does NOT include `client_secret` - relies on PKCE code_verifier only
- **Negative Test**: Verifies that public clients without PKCE are rejected

### Server Implementation Requirements for Both Clients

Your OAuth server MUST support BOTH client types:

```go
// internal/oauth/dcr.go

func (p *Provider) DCR(w http.ResponseWriter, r *http.Request) {
    var req struct {
        ClientName              string   `json:"client_name"`
        RedirectURIs            []string `json:"redirect_uris"`
        GrantTypes              []string `json:"grant_types"`
        ResponseTypes           []string `json:"response_types"`
        TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
    }
    json.NewDecoder(r.Body).Decode(&req)

    // Determine client type
    isPublicClient := req.TokenEndpointAuthMethod == "none"

    // Validate redirect URIs (both ChatGPT and Claude)
    allowedRedirects := []string{
        // ChatGPT
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://platform.openai.com/apps-manage/oauth",
        // Claude
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
        // Local testing
        "http://localhost:",
    }

    // Generate credentials
    clientID := generateSecureID()
    var clientSecretHash string
    var clientSecret string

    if !isPublicClient {
        // Confidential client (ChatGPT) - generate and store secret
        clientSecret = generateSecureSecret()
        clientSecretHash = hashSecret(clientSecret)
    }

    // Store client with type info
    p.store.CreateClient(ctx, &Client{
        ID:                      clientID,
        SecretHash:              clientSecretHash, // Empty for public clients
        Name:                    req.ClientName,
        RedirectURIs:            req.RedirectURIs,
        IsPublic:                isPublicClient,
        TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
    })

    // Response
    resp := map[string]any{
        "client_id":          clientID,
        "client_id_issued_at": time.Now().Unix(),
        "redirect_uris":       req.RedirectURIs,
    }

    if !isPublicClient {
        resp["client_secret"] = clientSecret // Only for confidential clients
    }

    json.NewEncoder(w).Encode(resp)
}
```

```go
// internal/oauth/handlers.go - Token endpoint

func (p *Provider) Token(w http.ResponseWriter, r *http.Request) {
    clientID := r.FormValue("client_id")
    clientSecret := r.FormValue("client_secret")
    codeVerifier := r.FormValue("code_verifier")

    client, err := p.store.GetClient(ctx, clientID)
    if err != nil {
        http.Error(w, "invalid_client", 401)
        return
    }

    // Authenticate client based on type
    if client.IsPublic {
        // Public client (Claude) - MUST have code_verifier (PKCE)
        if codeVerifier == "" {
            http.Error(w, "invalid_request: code_verifier required for public clients", 400)
            return
        }
        // No client_secret check needed
    } else {
        // Confidential client (ChatGPT) - MUST have valid client_secret
        if !verifySecret(clientSecret, client.SecretHash) {
            http.Error(w, "invalid_client", 401)
            return
        }
    }

    // Verify PKCE (required for both, but critical for public clients)
    storedChallenge := getStoredCodeChallenge(code)
    if !verifyPKCE(codeVerifier, storedChallenge) {
        http.Error(w, "invalid_grant: PKCE verification failed", 400)
        return
    }

    // Issue tokens...
}
```

### Updated Redirect URI Allowlist

```go
// Both ChatGPT and Claude redirect URIs
var allowedRedirectPatterns = []string{
    // ChatGPT
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://platform.openai.com/apps-manage/oauth",
    // Claude
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    // Local testing (MCP Inspector, etc.)
    "http://localhost:",
}
```

---

## What This Milestone Covers

| Feature | Description |
|---------|-------------|
| **OAuth 2.1 Provider** | MCP authorization spec compliant using `fosite` |
| **Dynamic Client Registration (DCR)** | Both ChatGPT and Claude register per-session |
| **Public + Confidential Clients** | Claude (public, no secret) + ChatGPT (confidential, with secret) |
| **PKCE (S256)** | Mandatory for all authorization flows |
| **Resource Parameter** | Echo throughout flow, embed in token `aud` |
| **Token Verification** | Signature, issuer, audience, expiry, scopes |
| **MCP Auth Integration** | `_meta["mcp/www_authenticate"]` responses |
| **Custom Conformance Tests** | Tests exact ChatGPT AND Claude Code flows |

---

## Implementation DAG

```
                    [Milestone 3 Complete]
                    (Consent screens ready)
                            │
                            ▼
              [READ chatgpt-apps/auth.md FIRST]
                    (lines 1-281)
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
  [OAuth Provider     [SQLC Queries]     [Token Middleware]
   Core (fosite)]          │                  │
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                    [OAuth Handlers]
                    (Wire to consent)
                            │
              ┌─────────────┼─────────────────┐
              │             │                 │
      [Protected       [DCR           [Token
       Resource         Handler]        Endpoint]
       Metadata]            │                 │
              │             │                 │
              └─────────────┼─────────────────┘
                            │
                [MCP Auth Integration]
                (_meta/www_authenticate)
                            │
                    [Wire into main.go]
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
[Custom Conformance   [MCPJam Inspector   [ChatGPT Developer
 Test Client]          (optional debug)]   Mode (final)]
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                        [Commit]
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
[Remove All               [PAT (Personal
 Unauthenticated           Access Token)
 Codepaths]                Endpoint]
        │                       │
        └───────────┬───────────┘
                    │
        [Update All Tests
         to Use Auth]
                    │
         ┌──────────┴──────────┐
         │                     │
[Unit Tests:              [MCP Tests:
 Mock Email →              Full OAuth
 Magic Login →             Flow]
 Session]
                    │
                [Final Commit]
```

---

## Tasks

### Layer 0 (MUST DO FIRST)

#### 0. Read Official Specification

**Before writing ANY code:**

```bash
# Read the full auth specification
cat chatgpt-apps/auth.md   # Lines 1-281, read completely

# Also read testing docs
cat chatgpt-apps/test.md
```

The conformance test client and all implementation details MUST match this specification exactly.

### Layer 1 (Parallel - No Dependencies)

#### 1. OAuth Provider Core (`internal/oauth/provider.go`)

See `chatgpt-apps/auth.md` lines 15-17 for component definitions.

```go
package oauth

import (
    "github.com/ory/fosite"
    "github.com/ory/fosite/compose"
)

type Provider struct {
    fosite.OAuth2Provider
    store    *SQLiteStore
    config   *fosite.Config
    issuer   string
    resource string // MCP resource identifier (auth.md line 43)
}

func NewProvider(db *sql.DB, issuer string, secret []byte) (*Provider, error) {
    config := &fosite.Config{
        AccessTokenLifespan:        time.Hour,
        RefreshTokenLifespan:       30 * 24 * time.Hour,
        AuthorizeCodeLifespan:      10 * time.Minute,
        GlobalSecret:               secret,
        SendDebugMessagesToClients: false,
    }

    store := NewSQLiteStore(db)

    provider := compose.ComposeAllEnabled(config, store,
        compose.OAuth2AuthorizeExplicitFactory,
        compose.OAuth2RefreshTokenGrantFactory,
        compose.OAuth2PKCEFactory,
    )

    return &Provider{
        OAuth2Provider: provider,
        store:          store,
        config:         config,
        issuer:         issuer,
        resource:       issuer, // Same as issuer for our setup
    }, nil
}
```

#### 2. SQLC Queries (`internal/db/sql/oauth.sql`)

Include `resource` field as required by auth.md lines 88-92:

```sql
-- name: CreateOAuthClient :exec
INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, created_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetOAuthClient :one
SELECT * FROM oauth_clients WHERE client_id = ?;

-- name: CreateOAuthCode :exec
INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, scope, resource, code_challenge, code_challenge_method, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthCode :one
SELECT * FROM oauth_codes WHERE code = ? AND expires_at > unixepoch();

-- name: DeleteOAuthCode :exec
DELETE FROM oauth_codes WHERE code = ?;

-- name: CreateOAuthToken :exec
INSERT INTO oauth_tokens (access_token, refresh_token, client_id, user_id, scope, resource, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthToken :one
SELECT * FROM oauth_tokens WHERE access_token = ? AND expires_at > unixepoch();
```

### Layer 2 (Depends on Layer 1)

#### 3. Protected Resource Metadata (`internal/oauth/metadata.go`)

**Reference**: `chatgpt-apps/auth.md` lines 28-56

```go
// ProtectedResourceMetadata serves RFC 9728 metadata
// Reference: chatgpt-apps/auth.md lines 33-46
func (p *Provider) ProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
    metadata := map[string]any{
        "resource":               p.resource,                    // REQUIRED (line 43)
        "authorization_servers":  []string{p.issuer},            // REQUIRED (line 44)
        "scopes_supported":       []string{"notes:read", "notes:write"}, // Optional (line 45)
        "resource_documentation": p.issuer + "/docs",            // Optional (line 46)
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(metadata)
}

// AuthServerMetadata serves OAuth 2.0 authorization server metadata
// Reference: chatgpt-apps/auth.md lines 58-80
func (p *Provider) AuthServerMetadata(w http.ResponseWriter, r *http.Request) {
    metadata := map[string]any{
        "issuer":                                p.issuer,
        "authorization_endpoint":                p.issuer + "/oauth/authorize",
        "token_endpoint":                        p.issuer + "/oauth/token",
        "registration_endpoint":                 p.issuer + "/oauth/register",  // REQUIRED for DCR (line 78)
        "code_challenge_methods_supported":      []string{"S256"},              // CRITICAL (line 79)
        "scopes_supported":                      []string{"notes:read", "notes:write"},
        "response_types_supported":              []string{"code"},
        "grant_types_supported":                 []string{"authorization_code", "refresh_token"},
        "token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(metadata)
}
```

#### 4. Dynamic Client Registration (`internal/oauth/dcr.go`)

**Reference**: `chatgpt-apps/auth.md` lines 82-86, 121-131

```go
// Allowed redirect URIs - only these are accepted
// Reference: chatgpt-apps/auth.md lines 84-86
var allowedRedirectPatterns = []string{
    "https://chatgpt.com/connector_platform_oauth_redirect",  // Production (line 84)
    "https://platform.openai.com/apps-manage/oauth",          // App review (line 86)
    "https://claude.ai/api/mcp/auth_callback",                // Claude
    "http://localhost:",                                       // Local testing
}

func (p *Provider) DCR(w http.ResponseWriter, r *http.Request) {
    var req DCRRequest
    json.NewDecoder(r.Body).Decode(&req)

    // Validate redirect_uris against allowlist
    for _, uri := range req.RedirectURIs {
        if !isAllowedRedirectURI(uri) {
            w.WriteHeader(http.StatusBadRequest)
            json.NewEncoder(w).Encode(map[string]string{
                "error":             "invalid_redirect_uri",
                "error_description": "redirect_uri not in allowlist",
            })
            return
        }
    }

    // Generate credentials
    clientID := generateSecureID()
    clientSecret := generateSecureSecret()

    // Store client
    p.store.CreateClient(ctx, clientID, hashSecret(clientSecret), req.ClientName, req.RedirectURIs)

    // Return credentials (auth.md implies client_secret shown once)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(DCRResponse{
        ClientID:         clientID,
        ClientSecret:     clientSecret,
        ClientIDIssuedAt: time.Now().Unix(),
        RedirectURIs:     req.RedirectURIs,
    })
}
```

#### 5. Authorization Endpoint - Must Accept `resource` Parameter

**Reference**: `chatgpt-apps/auth.md` lines 88-92

```go
func (p *Provider) Authorize(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // CRITICAL: ChatGPT sends resource parameter (auth.md lines 88-92)
    resource := r.URL.Query().Get("resource")
    if resource != "" && resource != p.resource {
        http.Error(w, "invalid_resource", http.StatusBadRequest)
        return
    }

    // Parse the authorization request (fosite handles PKCE validation)
    ar, err := p.NewAuthorizeRequest(ctx, r)
    if err != nil {
        p.WriteAuthorizeError(ctx, w, ar, err)
        return
    }

    // ... rest of authorization flow
    // Store resource in session for token endpoint
}
```

#### 6. Token Endpoint - Must Accept `resource` Parameter

**Reference**: `chatgpt-apps/auth.md` lines 88-92

```go
func (p *Provider) Token(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // CRITICAL: ChatGPT sends resource on token request too (auth.md lines 88-92)
    resource := r.FormValue("resource")
    if resource != "" && resource != p.resource {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "invalid_resource"})
        return
    }

    // Create session with resource in aud claim (auth.md line 91)
    session := &fosite.DefaultSession{
        Extra: map[string]interface{}{
            "aud": resource,  // "copy that value into the access token (commonly the aud claim)"
        },
    }

    // ... rest of token exchange
}
```

### Layer 3 (Depends on Layer 2)

#### 7. Token Verification

**Reference**: `chatgpt-apps/auth.md` lines 151-162

```go
// VerifyToken implements the checks from auth.md lines 155-160
func (v *TokenVerifier) VerifyToken(ctx context.Context, token string) (*TokenClaims, error) {
    // "Fetch the signing keys published by your authorization server (usually via JWKS)
    //  and verify the token's signature and iss." (line 157)
    claims, err := v.verifySignature(token)
    if err != nil {
        return nil, fmt.Errorf("invalid signature: %w", err)
    }

    // "Reject tokens that have expired or have not yet become valid (exp/nbf)." (line 158)
    if time.Now().After(claims.ExpiresAt) {
        return nil, errors.New("token expired")
    }
    if time.Now().Before(claims.NotBefore) {
        return nil, errors.New("token not yet valid")
    }

    // "Confirm the token was minted for your server (aud or the resource claim)
    //  and contains the scopes you marked as required." (line 159)
    if !contains(claims.Audience, v.resource) {
        return nil, errors.New("invalid audience")
    }

    return claims, nil
}
```

#### 8. MCP Auth Trigger Response

**Reference**: `chatgpt-apps/auth.md` lines 180-280

```go
// MCPAuthError returns response that triggers ChatGPT's OAuth UI
// Reference: chatgpt-apps/auth.md lines 257-280
func MCPAuthError(resourceMetadataURL string) map[string]any {
    return map[string]any{
        "jsonrpc": "2.0",
        "result": map[string]any{
            "content": []map[string]any{
                {"type": "text", "text": "Authentication required: no access token provided."},
            },
            // CRITICAL: This triggers the OAuth UI (auth.md line 257)
            "_meta": map[string]any{
                "mcp/www_authenticate": []string{
                    fmt.Sprintf(
                        `Bearer resource_metadata="%s", error="insufficient_scope", error_description="You need to login to continue"`,
                        resourceMetadataURL,
                    ),
                },
            },
            "isError": true,
        },
    }
}
```

### Layer 4: Testing

#### 9. Custom Conformance Test Client

**File**: `tests/conformance/oauth_conformance_test.go`

This is the PRIMARY testing mechanism. The unified test file supports both ChatGPT (confidential client) and Claude (public client) modes through a `ClientMode` type that determines behavior at Steps 3 and 5.

**Run conformance tests:**
```bash
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)"
go test -v ./tests/conformance/...
```

#### 10. Optional: MCPJam Inspector (GUI Debug Tool)

Only use when conformance tests pass but ChatGPT still fails:

```bash
npx @mcpjam/inspector@latest
# Connect to your server, use OAuth Debugger tab
```

#### 11. Final: ChatGPT Developer Mode

After conformance tests pass:

1. Enable Developer Mode: Settings → Connectors → Advanced → Developer Mode ON
2. Add connector with your ngrok URL
3. Test the full flow

---

## Expected File Structure

```
/home/kuitang/git/agent-notes/
├── chatgpt-apps/
│   └── auth.md              # OFFICIAL SPEC - READ FIRST (lines 1-281)
├── tests/
│   └── conformance/
│       └── oauth_conformance_test.go  # Unified OAuth conformance tests (ChatGPT + Claude)
├── internal/
│   ├── oauth/
│   │   ├── provider.go
│   │   ├── store.go
│   │   ├── metadata.go      # Both well-known endpoints
│   │   ├── dcr.go           # Dynamic Client Registration
│   │   └── handlers.go      # Authorize + Token (with resource param)
│   ├── auth/
│   │   └── oauth_middleware.go  # Token verification (auth.md lines 151-162)
│   └── mcp/
│       └── auth.go          # _meta["mcp/www_authenticate"] helper
├── scripts/
│   └── conformance-test.sh  # Run conformance tests
└── cmd/server/
    └── main.go
```

---

## Success Criteria

### Conformance Tests Must Pass

```bash
go test -v ./tests/conformance/...
```

**ChatGPT Conformance** (confidential client with client_secret):
- [ ] Step 1: Protected Resource Metadata
- [ ] Step 2: Auth Server Metadata (S256 in code_challenge_methods_supported)
- [ ] Step 3: DCR with redirect_uri `https://chatgpt.com/connector_platform_oauth_redirect`
- [ ] Step 4: Authorization with PKCE + resource parameter
- [ ] Step 5: Token Exchange WITH client_secret + resource parameter
- [ ] Step 6: Token Verification (iss, aud, exp, scopes)
- [ ] Step 7: Auth Trigger (_meta["mcp/www_authenticate"])

**Claude Code Conformance** (public client WITHOUT client_secret):
- [ ] Step 1-2: Same metadata endpoints as ChatGPT
- [ ] Step 3: DCR with `token_endpoint_auth_method: "none"` + redirect_uri `https://claude.ai/api/mcp/auth_callback`
- [ ] Step 4: Authorization with PKCE + resource parameter
- [ ] Step 5: Token Exchange WITHOUT client_secret (PKCE only)
- [ ] Step 6-7: Same as ChatGPT

**Both Clients Compatibility**:
- [ ] Server accepts BOTH ChatGPT (confidential) and Claude (public) client registrations
- [ ] Token endpoint works with client_secret (ChatGPT) AND without (Claude + PKCE)

### Negative Tests Must Pass
- [ ] Authorization without PKCE rejected
- [ ] Invalid redirect_uri rejected (not in allowlist)
- [ ] Wrong code_verifier rejected
- [ ] Public client without PKCE on token exchange rejected
- [ ] Expired token rejected
- [ ] Wrong audience rejected

### Authentication Enforcement (Layer 5)
- [ ] ALL MCP requests require Bearer token
- [ ] PAT API endpoints work (`POST/GET/DELETE /api/tokens`)
- [ ] PAT Management UI at `/settings/tokens` (create, list, revoke)
- [ ] PAT can be used as Bearer token for MCP
- [ ] Unauthenticated MCP requests return 401 + WWW-Authenticate
- [ ] No unauthenticated codepaths remain

### Test Updates (Layer 5)
- [ ] All unit tests create users via magic login or password
- [ ] All MCP tests perform full OAuth flow
- [ ] Mock email provider captures magic login tokens
- [ ] Tests do not use hardcoded user IDs

---

## Layer 5: Enforce Authentication Everywhere (After OAuth Works)

After OAuth is fully working, ALL codepaths MUST require authentication. No unauthenticated access.

### 12. Personal Access Token (PAT) Endpoint

**File**: `internal/auth/pat.go`

Users can exchange their password for a long-lived PAT for programmatic access.

**Endpoint**: `POST /api/tokens`

```go
// PAT endpoint - user exchanges password for a Personal Access Token
// Reference: spec.md § Personal Access Tokens
func (h *AuthHandler) CreatePAT(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
        Name     string `json:"name"`      // Token name/description
        Scope    string `json:"scope"`     // "read" or "read_write" (default)
    }
    json.NewDecoder(r.Body).Decode(&req)

    // Validate email/password
    user, err := h.store.ValidateCredentials(r.Context(), req.Email, req.Password)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "invalid_credentials"})
        return
    }

    // Generate PAT (long-lived, 1 year)
    token := generateSecureToken(32)
    tokenHash := hashToken(token)

    // Store in user's DB
    pat := &PAT{
        ID:        generateID(),
        Name:      req.Name,
        TokenHash: tokenHash,
        UserID:    user.ID,
        Scope:     req.Scope,
        ExpiresAt: time.Now().AddDate(1, 0, 0), // 1 year
        CreatedAt: time.Now(),
    }
    h.store.CreatePAT(r.Context(), pat)

    // Return token ONCE (never stored in plaintext)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]any{
        "token":      token,  // Only shown once
        "token_id":   pat.ID,
        "name":       pat.Name,
        "scope":      pat.Scope,
        "expires_at": pat.ExpiresAt,
        "created_at": pat.CreatedAt,
    })
}

// ListPATs returns all PATs for the current user (without token values)
func (h *AuthHandler) ListPATs(w http.ResponseWriter, r *http.Request) {
    // Requires session auth
    userID := r.Context().Value("user_id").(string)
    pats, _ := h.store.ListPATs(r.Context(), userID)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(pats)
}

// RevokePAT deletes a PAT
func (h *AuthHandler) RevokePAT(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    tokenID := r.PathValue("token_id")

    err := h.store.DeletePAT(r.Context(), userID, tokenID)
    if err != nil {
        w.WriteHeader(http.StatusNotFound)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}
```

**Database Schema** (add to `{user_id}.db` - already exists in spec.md as `api_keys`):

```sql
CREATE TABLE personal_access_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT DEFAULT 'read_write',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
```

### 12b. PAT Management UI

**File**: `web/templates/settings_tokens.html`

**Route**: `GET /settings/tokens` (session auth required)

UI calls the same backend API endpoints - no duplicate logic.

**Views**:

1. **Token List** (default view)
   - Table: name, scope, created_at, last_used_at
   - "Revoke" button per row → calls `DELETE /api/tokens/{id}`
   - "Create New Token" button

2. **Create Token Form**
   - Name (text input, required)
   - Scope (dropdown: "Read & Write" / "Read Only")
   - Password (re-authenticate)
   - Submit → calls `POST /api/tokens`

3. **Token Created Modal** (one-time display)
   - Shows token value + copy button
   - Warning: "Only shown once"
   - "Done" dismisses

4. **Revoke Confirmation**
   - "This will immediately invalidate the token"
   - Cancel / Revoke buttons

**Handler** (`cmd/server/main.go`):
```go
mux.HandleFunc("GET /settings/tokens", h.requireSession(h.renderTokensPage))
```

### 13. Remove All Unauthenticated Codepaths

**Files to modify**:
- `internal/mcp/server.go` - Remove any unauthenticated handlers
- `internal/mcp/handlers.go` - All tool calls require Bearer token
- `cmd/server/main.go` - Remove unauthenticated routes

**Requirements**:
- MCP endpoint (`/mcp`) MUST require `Authorization: Bearer <token>`
- Token can be: OAuth access token OR PAT
- Unauthenticated requests return 401 with `WWW-Authenticate` header
- No "demo mode" or "guest access"

```go
// AuthMiddleware validates Bearer token (OAuth or PAT)
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := r.Header.Get("Authorization")
        if !strings.HasPrefix(auth, "Bearer ") {
            h.writeAuthError(w, r)
            return
        }

        token := strings.TrimPrefix(auth, "Bearer ")

        // Try OAuth token first
        claims, err := h.oauthVerifier.VerifyToken(r.Context(), token)
        if err == nil {
            ctx := context.WithValue(r.Context(), "user_id", claims.Subject)
            ctx = context.WithValue(ctx, "scope", claims.Scope)
            next.ServeHTTP(w, r.WithContext(ctx))
            return
        }

        // Try PAT
        pat, err := h.store.ValidatePAT(r.Context(), hashToken(token))
        if err == nil {
            // Update last_used_at
            h.store.UpdatePATLastUsed(r.Context(), pat.ID)

            ctx := context.WithValue(r.Context(), "user_id", pat.UserID)
            ctx = context.WithValue(ctx, "scope", pat.Scope)
            next.ServeHTTP(w, r.WithContext(ctx))
            return
        }

        // Neither valid
        h.writeAuthError(w, r)
    })
}

func (h *Handler) writeAuthError(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("WWW-Authenticate", fmt.Sprintf(
        `Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`,
        h.issuer,
    ))
    w.WriteHeader(http.StatusUnauthorized)
    json.NewEncoder(w).Encode(MCPAuthError(h.issuer + "/.well-known/oauth-protected-resource"))
}
```

### 14. Update Unit Tests to Use Authentication

**All unit tests MUST authenticate**. Use mock email provider for magic login flow.

**File**: `tests/testutil/auth.go`

```go
package testutil

// CreateTestUser creates a test user via magic login and returns session cookie + user ID
func CreateTestUser(t *testing.T, server *httptest.Server) (*http.Cookie, string) {
    t.Helper()
    email := fmt.Sprintf("test-%s@example.com", generateID())

    // 1. Request magic login
    http.Post(server.URL+"/auth/magic-login", "application/json",
        strings.NewReader(fmt.Sprintf(`{"email":"%s"}`, email)))

    // 2. Get token from mock email provider
    token := GetMockEmailToken(t, email)

    // 3. Exchange token for session
    resp, _ := http.Get(server.URL + "/auth/magic-login/verify?token=" + token)
    defer resp.Body.Close()

    // 4. Extract session cookie
    for _, c := range resp.Cookies() {
        if c.Name == "session" {
            userID := GetUserIDFromSession(t, server, c)
            return c, userID
        }
    }
    t.Fatal("No session cookie returned")
    return nil, ""
}

// CreateTestUserWithPassword creates a user with email/password auth
func CreateTestUserWithPassword(t *testing.T, server *httptest.Server, email, password string) (*http.Cookie, string) {
    // Register then login
    http.Post(server.URL+"/auth/register", "application/json",
        strings.NewReader(fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)))

    resp, _ := http.Post(server.URL+"/auth/login", "application/json",
        strings.NewReader(fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)))
    defer resp.Body.Close()

    for _, c := range resp.Cookies() {
        if c.Name == "session" {
            userID := GetUserIDFromSession(t, server, c)
            return c, userID
        }
    }
    t.Fatal("No session cookie returned")
    return nil, ""
}

// CreateTestPAT creates a PAT for API/MCP testing
func CreateTestPAT(t *testing.T, server *httptest.Server, email, password string) string {
    resp, _ := http.Post(server.URL+"/api/tokens", "application/json",
        strings.NewReader(fmt.Sprintf(`{"email":"%s","password":"%s","name":"test"}`, email, password)))
    defer resp.Body.Close()

    var result struct{ Token string `json:"token"` }
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Token
}
```

**Mock Email Provider** (`tests/testutil/mock_email.go`):

```go
package testutil

var (
    mockEmails = make(map[string]string) // email -> token
    emailMu    sync.Mutex
)

type MockEmailSender struct{}

func (m *MockEmailSender) SendMagicLogin(email, token string) error {
    emailMu.Lock()
    defer emailMu.Unlock()
    mockEmails[email] = token
    return nil
}

func GetMockEmailToken(t *testing.T, email string) string {
    emailMu.Lock()
    defer emailMu.Unlock()
    token, ok := mockEmails[email]
    if !ok {
        t.Fatalf("No magic login token sent to %s", email)
    }
    delete(mockEmails, email) // One-time use
    return token
}
```

### 15. Update MCP Tests to Use Full OAuth Flow

**MCP tests MUST perform the complete OAuth flow** to obtain a Bearer token.

**File**: `tests/e2e/mcp_oauth_test.go`

```go
package e2e

// MCPTestClient performs full OAuth flow before MCP calls
type MCPTestClient struct {
    server      *httptest.Server
    accessToken string
    userID      string
}

// NewMCPTestClient creates a client with valid OAuth credentials
func NewMCPTestClient(t *testing.T, server *httptest.Server) *MCPTestClient {
    t.Helper()
    client := &MCPTestClient{server: server}

    // 1. Create test user with password
    email := fmt.Sprintf("mcp-test-%s@example.com", generateID())
    password := generateSecurePassword()
    _, userID := CreateTestUserWithPassword(t, server, email, password)
    client.userID = userID

    // 2. Perform OAuth flow (simulating ChatGPT or Claude)
    client.accessToken = performOAuthFlow(t, server, email, password)
    return client
}

// performOAuthFlow simulates the full ChatGPT/Claude OAuth connector flow
func performOAuthFlow(t *testing.T, server *httptest.Server, email, password string) string {
    // Step 1: GET /.well-known/oauth-protected-resource
    // Step 2: GET /.well-known/oauth-authorization-server
    // Step 3: POST /oauth/register (DCR)
    // Step 4: Generate PKCE, build authorization URL
    // Step 5: Login user, auto-consent, get code
    // Step 6: POST /oauth/token with code + code_verifier
    // Return access_token
}

// MCPRequest makes an authenticated MCP request
func (c *MCPTestClient) MCPRequest(t *testing.T, method string, params any) map[string]any {
    body, _ := json.Marshal(map[string]any{
        "jsonrpc": "2.0", "method": method, "params": params, "id": 1,
    })

    req, _ := http.NewRequest("POST", c.server.URL+"/mcp", bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+c.accessToken)

    resp, _ := http.DefaultClient.Do(req)
    defer resp.Body.Close()

    var result map[string]any
    json.NewDecoder(resp.Body).Decode(&result)
    return result
}
```

---

## Commands to Execute

```bash
# Initialize goenv
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)"

# FIRST: Read the spec
cat chatgpt-apps/auth.md

# Install dependencies
go get github.com/ory/fosite

# Generate SQLC
sqlc generate

# Run conformance tests
go test -v ./tests/conformance/...

# Run all tests
./scripts/ci.sh quick
```

---

## References

### ChatGPT
- **`chatgpt-apps/auth.md`** (lines 1-281) - AUTHORITATIVE SPEC, read completely
- [OpenAI Apps SDK Authentication](https://developers.openai.com/apps-sdk/build/auth/)

### Claude (Code CLI + Web) - Both Use Same OAuth Flow
- [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp) - Official Claude Code docs
- [Building Custom Connectors via Remote MCP Servers](https://support.claude.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers)
- [Claude OAuth requires DCR (Issue #2527)](https://github.com/anthropics/claude-code/issues/2527)
- Callback URL: `https://claude.ai/api/mcp/auth_callback` (same for CLI and web)
- Client type: **Public** (`token_endpoint_auth_method: "none"`)
- DCR: **REQUIRED** (RFC 7591)

### Specifications
- [MCP Authorization Spec (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [RFC 9728 - OAuth Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8414 - OAuth Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 7591 - Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
