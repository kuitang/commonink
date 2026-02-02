# Milestone 3.5: OAuth 2.1 Provider (For ChatGPT Connectors)

**Goal**: Implement OAuth 2.1 provider conforming to MCP authorization spec so ChatGPT can authenticate users and access their notes via MCP.

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

**File**: `tests/conformance/chatgpt_oauth_test.go`

```go
// Package conformance implements a custom ChatGPT OAuth conformance test client.
// This tests the EXACT flow that ChatGPT performs, as specified in chatgpt-apps/auth.md.
//
// IMPORTANT: Read chatgpt-apps/auth.md (lines 1-281) before modifying this file.
package conformance

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "pgregory.net/rapid"
)

// ChatGPTOAuthConformanceTest tests the exact OAuth flow that ChatGPT performs.
// Reference: chatgpt-apps/auth.md lines 99-119
type ChatGPTOAuthConformanceTest struct {
    t         *testing.T
    serverURL string
    client    *http.Client

    // Discovered metadata
    resourceMetadata   ResourceMetadata
    authServerMetadata AuthServerMetadata

    // Registration
    clientID     string
    clientSecret string

    // PKCE
    codeVerifier  string
    codeChallenge string

    // Tokens
    accessToken  string
    refreshToken string
}

// ResourceMetadata from /.well-known/oauth-protected-resource
// Reference: chatgpt-apps/auth.md lines 33-40
type ResourceMetadata struct {
    Resource             string   `json:"resource"`
    AuthorizationServers []string `json:"authorization_servers"`
    ScopesSupported      []string `json:"scopes_supported"`
    ResourceDocumentation string  `json:"resource_documentation,omitempty"`
}

// AuthServerMetadata from /.well-known/oauth-authorization-server
// Reference: chatgpt-apps/auth.md lines 65-74
type AuthServerMetadata struct {
    Issuer                           string   `json:"issuer"`
    AuthorizationEndpoint            string   `json:"authorization_endpoint"`
    TokenEndpoint                    string   `json:"token_endpoint"`
    RegistrationEndpoint             string   `json:"registration_endpoint"`
    CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
    ScopesSupported                  []string `json:"scopes_supported"`
}

// DCRRequest for Dynamic Client Registration
// Reference: chatgpt-apps/auth.md lines 107-109, 121-125
type DCRRequest struct {
    ClientName    string   `json:"client_name"`
    RedirectURIs  []string `json:"redirect_uris"`
    GrantTypes    []string `json:"grant_types"`
    ResponseTypes []string `json:"response_types"`
}

// DCRResponse from Dynamic Client Registration
type DCRResponse struct {
    ClientID         string   `json:"client_id"`
    ClientSecret     string   `json:"client_secret"`
    ClientIDIssuedAt int64    `json:"client_id_issued_at"`
    RedirectURIs     []string `json:"redirect_uris"`
}

// TokenResponse from token endpoint
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    RefreshToken string `json:"refresh_token"`
    Scope        string `json:"scope"`
}

// =============================================================================
// CONFORMANCE TEST: Step 1 - Protected Resource Metadata
// Reference: chatgpt-apps/auth.md lines 28-56
// =============================================================================

func (c *ChatGPTOAuthConformanceTest) Step1_FetchProtectedResourceMetadata() {
    c.t.Log("Step 1: Fetching protected resource metadata")

    resp, err := c.client.Get(c.serverURL + "/.well-known/oauth-protected-resource")
    require.NoError(c.t, err)
    defer resp.Body.Close()

    // MUST return 200
    require.Equal(c.t, http.StatusOK, resp.StatusCode,
        "Protected resource metadata endpoint must return 200")

    // MUST return JSON
    require.Equal(c.t, "application/json", resp.Header.Get("Content-Type"),
        "Protected resource metadata must be JSON")

    err = json.NewDecoder(resp.Body).Decode(&c.resourceMetadata)
    require.NoError(c.t, err, "Protected resource metadata must be valid JSON")

    // REQUIRED field: resource (auth.md line 43)
    require.NotEmpty(c.t, c.resourceMetadata.Resource,
        "Protected resource metadata MUST include 'resource' field")

    // REQUIRED field: authorization_servers (auth.md line 44)
    require.NotEmpty(c.t, c.resourceMetadata.AuthorizationServers,
        "Protected resource metadata MUST include 'authorization_servers' field")

    c.t.Logf("  ✓ resource: %s", c.resourceMetadata.Resource)
    c.t.Logf("  ✓ authorization_servers: %v", c.resourceMetadata.AuthorizationServers)
}

// =============================================================================
// CONFORMANCE TEST: Step 2 - Auth Server Metadata
// Reference: chatgpt-apps/auth.md lines 58-80
// =============================================================================

func (c *ChatGPTOAuthConformanceTest) Step2_FetchAuthServerMetadata() {
    c.t.Log("Step 2: Fetching authorization server metadata")

    authServer := c.resourceMetadata.AuthorizationServers[0]
    resp, err := c.client.Get(authServer + "/.well-known/oauth-authorization-server")
    require.NoError(c.t, err)
    defer resp.Body.Close()

    require.Equal(c.t, http.StatusOK, resp.StatusCode)

    err = json.NewDecoder(resp.Body).Decode(&c.authServerMetadata)
    require.NoError(c.t, err)

    // REQUIRED: authorization_endpoint (auth.md line 77)
    require.NotEmpty(c.t, c.authServerMetadata.AuthorizationEndpoint,
        "Auth server metadata MUST include 'authorization_endpoint'")

    // REQUIRED: token_endpoint (auth.md line 77)
    require.NotEmpty(c.t, c.authServerMetadata.TokenEndpoint,
        "Auth server metadata MUST include 'token_endpoint'")

    // REQUIRED: registration_endpoint (auth.md line 78)
    require.NotEmpty(c.t, c.authServerMetadata.RegistrationEndpoint,
        "Auth server metadata MUST include 'registration_endpoint' for DCR")

    // CRITICAL: code_challenge_methods_supported MUST include S256 (auth.md line 79)
    // "If that field is missing, ChatGPT will refuse to complete the flow"
    require.Contains(c.t, c.authServerMetadata.CodeChallengeMethodsSupported, "S256",
        "CRITICAL: code_challenge_methods_supported MUST include 'S256' or ChatGPT will refuse")

    c.t.Logf("  ✓ authorization_endpoint: %s", c.authServerMetadata.AuthorizationEndpoint)
    c.t.Logf("  ✓ token_endpoint: %s", c.authServerMetadata.TokenEndpoint)
    c.t.Logf("  ✓ registration_endpoint: %s", c.authServerMetadata.RegistrationEndpoint)
    c.t.Logf("  ✓ code_challenge_methods_supported includes S256")
}

// =============================================================================
// CONFORMANCE TEST: Step 3 - Dynamic Client Registration
// Reference: chatgpt-apps/auth.md lines 107-109, 121-125
// =============================================================================

func (c *ChatGPTOAuthConformanceTest) Step3_DynamicClientRegistration() {
    c.t.Log("Step 3: Dynamic Client Registration")

    // ChatGPT redirect URIs (auth.md lines 84-86)
    dcrReq := DCRRequest{
        ClientName:    "ChatGPT",
        RedirectURIs:  []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
        GrantTypes:    []string{"authorization_code", "refresh_token"},
        ResponseTypes: []string{"code"},
    }

    body, _ := json.Marshal(dcrReq)
    resp, err := c.client.Post(
        c.authServerMetadata.RegistrationEndpoint,
        "application/json",
        strings.NewReader(string(body)),
    )
    require.NoError(c.t, err)
    defer resp.Body.Close()

    // DCR must succeed
    require.Equal(c.t, http.StatusOK, resp.StatusCode,
        "Dynamic Client Registration must return 200 (or 201)")

    var dcrResp DCRResponse
    err = json.NewDecoder(resp.Body).Decode(&dcrResp)
    require.NoError(c.t, err)

    // MUST return client_id
    require.NotEmpty(c.t, dcrResp.ClientID,
        "DCR response MUST include 'client_id'")

    // MUST return client_secret
    require.NotEmpty(c.t, dcrResp.ClientSecret,
        "DCR response MUST include 'client_secret'")

    c.clientID = dcrResp.ClientID
    c.clientSecret = dcrResp.ClientSecret

    c.t.Logf("  ✓ client_id: %s", c.clientID)
    c.t.Logf("  ✓ client_secret: [REDACTED]")
}

// =============================================================================
// CONFORMANCE TEST: Step 4 - Authorization Code + PKCE
// Reference: chatgpt-apps/auth.md lines 88-97, 111-113
// =============================================================================

func (c *ChatGPTOAuthConformanceTest) Step4_GeneratePKCE() {
    c.t.Log("Step 4a: Generating PKCE challenge")

    // Generate code_verifier (43-128 chars)
    c.codeVerifier = generateSecureRandom(64)

    // Generate code_challenge using S256 (auth.md lines 94-97)
    h := sha256.Sum256([]byte(c.codeVerifier))
    c.codeChallenge = base64.RawURLEncoding.EncodeToString(h[:])

    c.t.Logf("  ✓ code_verifier: %s...", c.codeVerifier[:16])
    c.t.Logf("  ✓ code_challenge (S256): %s", c.codeChallenge)
}

func (c *ChatGPTOAuthConformanceTest) Step4_AuthorizationRequest(redirectURI string) string {
    c.t.Log("Step 4b: Authorization request")

    state := generateSecureRandom(32)

    // Build authorization URL exactly as ChatGPT does (auth.md lines 88-92)
    params := url.Values{
        "client_id":             {c.clientID},
        "redirect_uri":          {redirectURI},
        "response_type":         {"code"},
        "scope":                 {"notes:read notes:write"},
        "state":                 {state},
        "code_challenge":        {c.codeChallenge},
        "code_challenge_method": {"S256"},
        // CRITICAL: ChatGPT sends resource parameter (auth.md lines 88-92)
        "resource":              {c.resourceMetadata.Resource},
    }

    authURL := c.authServerMetadata.AuthorizationEndpoint + "?" + params.Encode()
    c.t.Logf("  ✓ Authorization URL: %s", authURL)

    return authURL
}

// =============================================================================
// CONFORMANCE TEST: Step 5 - Token Exchange
// Reference: chatgpt-apps/auth.md lines 115-116
// =============================================================================

func (c *ChatGPTOAuthConformanceTest) Step5_TokenExchange(code, redirectURI string) {
    c.t.Log("Step 5: Token exchange")

    // Token request exactly as ChatGPT does (auth.md lines 88-92)
    params := url.Values{
        "grant_type":    {"authorization_code"},
        "client_id":     {c.clientID},
        "client_secret": {c.clientSecret},
        "code":          {code},
        "redirect_uri":  {redirectURI},
        "code_verifier": {c.codeVerifier},
        // CRITICAL: ChatGPT sends resource parameter (auth.md lines 88-92)
        "resource":      {c.resourceMetadata.Resource},
    }

    resp, err := c.client.PostForm(c.authServerMetadata.TokenEndpoint, params)
    require.NoError(c.t, err)
    defer resp.Body.Close()

    require.Equal(c.t, http.StatusOK, resp.StatusCode,
        "Token exchange must return 200")

    var tokenResp TokenResponse
    err = json.NewDecoder(resp.Body).Decode(&tokenResp)
    require.NoError(c.t, err)

    require.NotEmpty(c.t, tokenResp.AccessToken,
        "Token response MUST include 'access_token'")
    require.Equal(c.t, "Bearer", tokenResp.TokenType,
        "Token type MUST be 'Bearer'")

    c.accessToken = tokenResp.AccessToken
    c.refreshToken = tokenResp.RefreshToken

    c.t.Logf("  ✓ access_token: [REDACTED]")
    c.t.Logf("  ✓ token_type: %s", tokenResp.TokenType)
    c.t.Logf("  ✓ expires_in: %d", tokenResp.ExpiresIn)
}

// =============================================================================
// CONFORMANCE TEST: Step 6 - Token Verification
// Reference: chatgpt-apps/auth.md lines 151-162
// =============================================================================

func (c *ChatGPTOAuthConformanceTest) Step6_VerifyTokenWorks() {
    c.t.Log("Step 6: Verify token works on MCP endpoint")

    req, _ := http.NewRequest("POST", c.serverURL+"/mcp", strings.NewReader(`{
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1
    }`))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+c.accessToken)

    resp, err := c.client.Do(req)
    require.NoError(c.t, err)
    defer resp.Body.Close()

    require.Equal(c.t, http.StatusOK, resp.StatusCode,
        "MCP request with valid token must return 200")

    c.t.Log("  ✓ MCP request with Bearer token succeeded")
}

// =============================================================================
// CONFORMANCE TEST: Step 7 - Auth Trigger (401 + _meta)
// Reference: chatgpt-apps/auth.md lines 180-280
// =============================================================================

func (c *ChatGPTOAuthConformanceTest) Step7_VerifyAuthTrigger() {
    c.t.Log("Step 7: Verify auth trigger response")

    // Request WITHOUT token
    req, _ := http.NewRequest("POST", c.serverURL+"/mcp", strings.NewReader(`{
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "create_note", "arguments": {"title": "test"}},
        "id": 1
    }`))
    req.Header.Set("Content-Type", "application/json")
    // No Authorization header

    resp, err := c.client.Do(req)
    require.NoError(c.t, err)
    defer resp.Body.Close()

    // Check for WWW-Authenticate header (auth.md lines 48-54)
    wwwAuth := resp.Header.Get("WWW-Authenticate")
    if resp.StatusCode == http.StatusUnauthorized {
        require.Contains(c.t, wwwAuth, "resource_metadata",
            "401 response MUST include WWW-Authenticate with resource_metadata")
        c.t.Log("  ✓ 401 response includes WWW-Authenticate header")
    }

    // If 200, check for _meta["mcp/www_authenticate"] (auth.md lines 257-280)
    if resp.StatusCode == http.StatusOK {
        var mcpResp map[string]interface{}
        json.NewDecoder(resp.Body).Decode(&mcpResp)

        if result, ok := mcpResp["result"].(map[string]interface{}); ok {
            if meta, ok := result["_meta"].(map[string]interface{}); ok {
                _, hasWWWAuth := meta["mcp/www_authenticate"]
                require.True(c.t, hasWWWAuth,
                    "MCP error response MUST include _meta['mcp/www_authenticate']")
                c.t.Log("  ✓ MCP response includes _meta['mcp/www_authenticate']")
            }
        }
    }
}

// =============================================================================
// CONFORMANCE TEST: Negative Tests
// =============================================================================

func (c *ChatGPTOAuthConformanceTest) TestNegative_NoPKCE() {
    c.t.Log("Negative Test: Authorization without PKCE must fail")

    params := url.Values{
        "client_id":     {c.clientID},
        "redirect_uri":  {"https://chatgpt.com/connector_platform_oauth_redirect"},
        "response_type": {"code"},
        "scope":         {"notes:read"},
        "state":         {"test"},
        // NO code_challenge - must be rejected
    }

    resp, err := c.client.Get(c.authServerMetadata.AuthorizationEndpoint + "?" + params.Encode())
    require.NoError(c.t, err)
    defer resp.Body.Close()

    require.Equal(c.t, http.StatusBadRequest, resp.StatusCode,
        "Authorization without PKCE MUST be rejected (OAuth 2.1 requirement)")

    c.t.Log("  ✓ Authorization without PKCE correctly rejected")
}

func (c *ChatGPTOAuthConformanceTest) TestNegative_WrongCodeVerifier() {
    c.t.Log("Negative Test: Token exchange with wrong code_verifier must fail")

    // This would be tested after getting a valid code
    // The token endpoint MUST reject mismatched code_verifier
}

func (c *ChatGPTOAuthConformanceTest) TestNegative_InvalidRedirectURI() {
    c.t.Log("Negative Test: DCR with invalid redirect_uri must fail")

    dcrReq := DCRRequest{
        ClientName:    "Evil Client",
        RedirectURIs:  []string{"https://evil.com/steal-tokens"},
        GrantTypes:    []string{"authorization_code"},
        ResponseTypes: []string{"code"},
    }

    body, _ := json.Marshal(dcrReq)
    resp, err := c.client.Post(
        c.authServerMetadata.RegistrationEndpoint,
        "application/json",
        strings.NewReader(string(body)),
    )
    require.NoError(c.t, err)
    defer resp.Body.Close()

    require.Equal(c.t, http.StatusBadRequest, resp.StatusCode,
        "DCR with non-allowlisted redirect_uri MUST be rejected")

    c.t.Log("  ✓ DCR with invalid redirect_uri correctly rejected")
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================

func TestChatGPTOAuthConformance(t *testing.T) {
    // Setup test server
    server := setupTestServer(t)
    defer server.Close()

    conformance := &ChatGPTOAuthConformanceTest{
        t:         t,
        serverURL: server.URL,
        client:    &http.Client{},
    }

    // Run the exact ChatGPT OAuth flow
    t.Run("Step1_ProtectedResourceMetadata", conformance.Step1_FetchProtectedResourceMetadata)
    t.Run("Step2_AuthServerMetadata", conformance.Step2_FetchAuthServerMetadata)
    t.Run("Step3_DynamicClientRegistration", conformance.Step3_DynamicClientRegistration)
    t.Run("Step4_PKCE", conformance.Step4_GeneratePKCE)

    // For full flow, we need to simulate browser auth
    // In CI, use a test user that auto-approves
    t.Run("Step7_AuthTrigger", conformance.Step7_VerifyAuthTrigger)

    // Negative tests
    t.Run("Negative_NoPKCE", conformance.TestNegative_NoPKCE)
    t.Run("Negative_InvalidRedirectURI", conformance.TestNegative_InvalidRedirectURI)
}

// Property-based conformance tests using rapid
func TestChatGPTOAuthConformance_Properties(t *testing.T) {
    rapid.Check(t, func(t *rapid.T) {
        // Property: S256 must always be in code_challenge_methods_supported
        // Property: resource parameter must be echoed
        // Property: PKCE must be enforced
        // Property: only allowlisted redirect_uris accepted
    })
}

// Helper functions
func generateSecureRandom(length int) string {
    // Implementation
    return ""
}

func setupTestServer(t *testing.T) *httptest.Server {
    // Implementation
    return nil
}
```

---

## What This Milestone Covers

| Feature | Description |
|---------|-------------|
| **OAuth 2.1 Provider** | MCP authorization spec compliant using `fosite` |
| **Dynamic Client Registration (DCR)** | ChatGPT registers itself per-session |
| **PKCE (S256)** | Mandatory for all authorization flows |
| **Resource Parameter** | Echo throughout flow, embed in token `aud` |
| **Token Verification** | Signature, issuer, audience, expiry, scopes |
| **MCP Auth Integration** | `_meta["mcp/www_authenticate"]` responses |
| **Custom Conformance Tests** | Tests exact ChatGPT flow from auth.md |

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

**File**: `tests/conformance/chatgpt_oauth_test.go`

This is the PRIMARY testing mechanism. See the complete implementation above in "Custom Conformance Test Client (REQUIRED)" section.

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
│       └── chatgpt_oauth_test.go  # Custom conformance test client
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

All steps from the ChatGPT OAuth flow (auth.md lines 99-119) must pass:
- [ ] Step 1: Protected Resource Metadata
- [ ] Step 2: Auth Server Metadata (S256 in code_challenge_methods_supported)
- [ ] Step 3: Dynamic Client Registration
- [ ] Step 4: Authorization with PKCE + resource parameter
- [ ] Step 5: Token Exchange with resource parameter
- [ ] Step 6: Token Verification (iss, aud, exp, scopes)
- [ ] Step 7: Auth Trigger (_meta["mcp/www_authenticate"])

### Negative Tests Must Pass
- [ ] Authorization without PKCE rejected
- [ ] Invalid redirect_uri rejected
- [ ] Wrong code_verifier rejected
- [ ] Expired token rejected
- [ ] Wrong audience rejected

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

- **`chatgpt-apps/auth.md`** (lines 1-281) - AUTHORITATIVE SPEC, read completely
- [MCP Authorization Spec (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [RFC 9728 - OAuth Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8414 - OAuth Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
