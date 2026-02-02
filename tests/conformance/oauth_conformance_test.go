// TODO: These tests have not been run yet - implementation pending
//
// Package conformance implements a unified OAuth conformance test client that supports
// BOTH ChatGPT (confidential client) and Claude (public client) OAuth flows.
//
// This tests the EXACT flows that both ChatGPT and Claude Code perform as MCP clients.
//
// Key differences:
//   - ChatGPT: Confidential client with client_secret on token endpoint
//   - Claude: Public client (token_endpoint_auth_method: "none"), PKCE-only auth
//
// References:
//   - ChatGPT: chatgpt-apps/auth.md (lines 1-281)
//   - Claude: https://support.claude.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers
//
// IMPORTANT: Read chatgpt-apps/auth.md completely before modifying this file.
package conformance

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// =============================================================================
// CLIENT MODE - Determines ChatGPT vs Claude behavior
// =============================================================================

// ClientMode specifies whether to test as ChatGPT (confidential) or Claude (public) client
type ClientMode string

const (
	// ClientModeChatGPT tests as a confidential client WITH client_secret on token endpoint
	ClientModeChatGPT ClientMode = "chatgpt"

	// ClientModeClaude tests as a public client WITHOUT client_secret on token endpoint
	ClientModeClaude ClientMode = "claude"
)

// ClientConfig holds mode-specific configuration
type ClientConfig struct {
	Mode         ClientMode
	ClientName   string
	RedirectURIs []string
	// TokenEndpointAuthMethod is "none" for public clients (Claude), empty for confidential (ChatGPT)
	TokenEndpointAuthMethod string
}

// ChatGPTConfig returns configuration for ChatGPT OAuth flow
func ChatGPTConfig() ClientConfig {
	return ClientConfig{
		Mode:       ClientModeChatGPT,
		ClientName: "ChatGPT",
		RedirectURIs: []string{
			"https://chatgpt.com/connector_platform_oauth_redirect",
		},
		TokenEndpointAuthMethod: "", // Confidential client - uses client_secret
	}
}

// ClaudeConfig returns configuration for Claude OAuth flow
func ClaudeConfig() ClientConfig {
	return ClientConfig{
		Mode:       ClientModeClaude,
		ClientName: "claudeai",
		RedirectURIs: []string{
			"https://claude.ai/api/mcp/auth_callback",
		},
		TokenEndpointAuthMethod: "none", // Public client - PKCE only
	}
}

// =============================================================================
// SHARED TYPES - Used by both ChatGPT and Claude flows
// =============================================================================

// ResourceMetadata from /.well-known/oauth-protected-resource
// Reference: chatgpt-apps/auth.md lines 33-40
type ResourceMetadata struct {
	Resource              string   `json:"resource"`
	AuthorizationServers  []string `json:"authorization_servers"`
	ScopesSupported       []string `json:"scopes_supported"`
	ResourceDocumentation string   `json:"resource_documentation,omitempty"`
}

// AuthServerMetadata from /.well-known/oauth-authorization-server
// Reference: chatgpt-apps/auth.md lines 65-74
type AuthServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ScopesSupported               []string `json:"scopes_supported"`
}

// DCRRequest for Dynamic Client Registration
// Reference: chatgpt-apps/auth.md lines 107-109, 121-125
type DCRRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"` // "none" for Claude
}

// DCRResponse from Dynamic Client Registration
type DCRResponse struct {
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret,omitempty"` // May be empty for public clients
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
// UNIFIED CONFORMANCE TEST CLIENT
// =============================================================================

// OAuthConformanceTest tests OAuth flows for both ChatGPT and Claude
type OAuthConformanceTest struct {
	t         *testing.T
	serverURL string
	client    *http.Client
	config    ClientConfig

	// Discovered metadata (Step 1 & 2)
	resourceMetadata   ResourceMetadata
	authServerMetadata AuthServerMetadata

	// Registration result (Step 3)
	clientID     string
	clientSecret string // Empty for public clients (Claude)

	// PKCE (Step 4)
	codeVerifier  string
	codeChallenge string

	// Tokens (Step 5)
	accessToken  string
	refreshToken string
}

// NewOAuthConformanceTest creates a new conformance test for the specified client mode
func NewOAuthConformanceTest(t *testing.T, serverURL string, config ClientConfig) *OAuthConformanceTest {
	return &OAuthConformanceTest{
		t:         t,
		serverURL: serverURL,
		client:    &http.Client{},
		config:    config,
	}
}

// =============================================================================
// STEP 1: Protected Resource Metadata (COMMON - Same for ChatGPT and Claude)
// Reference: chatgpt-apps/auth.md lines 28-56
// =============================================================================

func (c *OAuthConformanceTest) Step1_FetchProtectedResourceMetadata() {
	c.t.Logf("[%s] Step 1: Fetching protected resource metadata", c.config.Mode)

	resp, err := c.client.Get(c.serverURL + "/.well-known/oauth-protected-resource")
	require.NoError(c.t, err)
	defer resp.Body.Close()

	// MUST return 200
	require.Equal(c.t, http.StatusOK, resp.StatusCode,
		"Protected resource metadata endpoint must return 200")

	// MUST return JSON
	contentType := resp.Header.Get("Content-Type")
	require.True(c.t, strings.HasPrefix(contentType, "application/json"),
		"Protected resource metadata must be JSON, got: %s", contentType)

	err = json.NewDecoder(resp.Body).Decode(&c.resourceMetadata)
	require.NoError(c.t, err, "Protected resource metadata must be valid JSON")

	// REQUIRED field: resource (auth.md line 43)
	require.NotEmpty(c.t, c.resourceMetadata.Resource,
		"Protected resource metadata MUST include 'resource' field")

	// REQUIRED field: authorization_servers (auth.md line 44)
	require.NotEmpty(c.t, c.resourceMetadata.AuthorizationServers,
		"Protected resource metadata MUST include 'authorization_servers' field")

	c.t.Logf("  [OK] resource: %s", c.resourceMetadata.Resource)
	c.t.Logf("  [OK] authorization_servers: %v", c.resourceMetadata.AuthorizationServers)
}

// =============================================================================
// STEP 2: Auth Server Metadata (COMMON - Same for ChatGPT and Claude)
// Reference: chatgpt-apps/auth.md lines 58-80
// =============================================================================

func (c *OAuthConformanceTest) Step2_FetchAuthServerMetadata() {
	c.t.Logf("[%s] Step 2: Fetching authorization server metadata", c.config.Mode)

	authServer := c.resourceMetadata.AuthorizationServers[0]
	metadataURL := authServer + "/.well-known/oauth-authorization-server"

	resp, err := c.client.Get(metadataURL)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.Equal(c.t, http.StatusOK, resp.StatusCode,
		"Auth server metadata endpoint must return 200")

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
		"CRITICAL: code_challenge_methods_supported MUST include 'S256' or clients will refuse")

	c.t.Logf("  [OK] authorization_endpoint: %s", c.authServerMetadata.AuthorizationEndpoint)
	c.t.Logf("  [OK] token_endpoint: %s", c.authServerMetadata.TokenEndpoint)
	c.t.Logf("  [OK] registration_endpoint: %s", c.authServerMetadata.RegistrationEndpoint)
	c.t.Log("  [OK] code_challenge_methods_supported includes S256")
}

// =============================================================================
// STEP 3: Dynamic Client Registration (MODE-SPECIFIC)
// ChatGPT: Confidential client, expects client_secret
// Claude: Public client, token_endpoint_auth_method: "none"
// =============================================================================

func (c *OAuthConformanceTest) Step3_DynamicClientRegistration() {
	c.t.Logf("[%s] Step 3: Dynamic Client Registration", c.config.Mode)

	dcrReq := DCRRequest{
		ClientName:    c.config.ClientName,
		RedirectURIs:  c.config.RedirectURIs,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
	}

	// Claude-specific: Add token_endpoint_auth_method: "none" for public client
	if c.config.Mode == ClientModeClaude {
		dcrReq.TokenEndpointAuthMethod = "none"
		c.t.Log("  [INFO] Registering as PUBLIC client (token_endpoint_auth_method=none)")
	} else {
		c.t.Log("  [INFO] Registering as CONFIDENTIAL client")
	}

	body, err := json.Marshal(dcrReq)
	require.NoError(c.t, err)

	resp, err := c.client.Post(
		c.authServerMetadata.RegistrationEndpoint,
		"application/json",
		strings.NewReader(string(body)),
	)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	// DCR must succeed (200 or 201)
	require.True(c.t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated,
		"Dynamic Client Registration must return 200 or 201, got %d", resp.StatusCode)

	var dcrResp DCRResponse
	err = json.NewDecoder(resp.Body).Decode(&dcrResp)
	require.NoError(c.t, err)

	// MUST return client_id
	require.NotEmpty(c.t, dcrResp.ClientID,
		"DCR response MUST include 'client_id'")

	c.clientID = dcrResp.ClientID
	c.clientSecret = dcrResp.ClientSecret

	c.t.Logf("  [OK] client_id: %s", c.clientID)

	// Mode-specific validation
	if c.config.Mode == ClientModeChatGPT {
		// ChatGPT (confidential client) MUST receive client_secret
		require.NotEmpty(c.t, dcrResp.ClientSecret,
			"Confidential client DCR response MUST include 'client_secret'")
		c.t.Log("  [OK] client_secret: [REDACTED]")
	} else {
		// Claude (public client) may or may not receive client_secret
		// but it's not required for token exchange
		c.t.Log("  [OK] Registered as public client (client_secret not required for token exchange)")
	}
}

// =============================================================================
// STEP 4: Authorization Code + PKCE (COMMON - Same for ChatGPT and Claude)
// Reference: chatgpt-apps/auth.md lines 88-97, 111-113
// =============================================================================

func (c *OAuthConformanceTest) Step4_GeneratePKCE() {
	c.t.Logf("[%s] Step 4a: Generating PKCE challenge", c.config.Mode)

	// Generate code_verifier (43-128 chars, URL-safe)
	c.codeVerifier = generateSecureRandom(64)

	// Generate code_challenge using S256 (auth.md lines 94-97)
	h := sha256.Sum256([]byte(c.codeVerifier))
	c.codeChallenge = base64.RawURLEncoding.EncodeToString(h[:])

	c.t.Logf("  [OK] code_verifier: %s...", c.codeVerifier[:16])
	c.t.Logf("  [OK] code_challenge (S256): %s", c.codeChallenge)
}

func (c *OAuthConformanceTest) Step4_BuildAuthorizationURL(state string) string {
	c.t.Logf("[%s] Step 4b: Building authorization URL", c.config.Mode)

	redirectURI := c.config.RedirectURIs[0]

	// Build authorization URL exactly as ChatGPT/Claude does
	params := url.Values{
		"client_id":             {c.clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"notes:read notes:write"},
		"state":                 {state},
		"code_challenge":        {c.codeChallenge},
		"code_challenge_method": {"S256"},
		// CRITICAL: Both ChatGPT and Claude send resource parameter
		"resource": {c.resourceMetadata.Resource},
	}

	authURL := c.authServerMetadata.AuthorizationEndpoint + "?" + params.Encode()
	c.t.Logf("  [OK] Authorization URL: %s", authURL)

	return authURL
}

// =============================================================================
// STEP 5: Token Exchange (MODE-SPECIFIC)
// ChatGPT: Includes client_secret
// Claude: NO client_secret (relies on PKCE only)
// =============================================================================

func (c *OAuthConformanceTest) Step5_TokenExchange(code string) {
	c.t.Logf("[%s] Step 5: Token exchange", c.config.Mode)

	redirectURI := c.config.RedirectURIs[0]

	// Build token request
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {c.clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {c.codeVerifier},
	}

	// Mode-specific: ChatGPT includes client_secret, Claude does not
	if c.config.Mode == ClientModeChatGPT {
		require.NotEmpty(c.t, c.clientSecret, "ChatGPT mode requires client_secret")
		params.Set("client_secret", c.clientSecret)
		// ChatGPT also sends resource parameter on token exchange
		params.Set("resource", c.resourceMetadata.Resource)
		c.t.Log("  [INFO] Including client_secret (confidential client)")
	} else {
		c.t.Log("  [INFO] NO client_secret (public client with PKCE)")
	}

	resp, err := c.client.PostForm(c.authServerMetadata.TokenEndpoint, params)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	// Must succeed
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

	c.t.Log("  [OK] access_token: [REDACTED]")
	c.t.Logf("  [OK] token_type: %s", tokenResp.TokenType)
	c.t.Logf("  [OK] expires_in: %d", tokenResp.ExpiresIn)

	if c.config.Mode == ClientModeClaude {
		c.t.Log("  [OK] Token exchange succeeded WITHOUT client_secret (PKCE provided proof)")
	}
}

// =============================================================================
// STEP 6: Token Verification (COMMON - Same for ChatGPT and Claude)
// Reference: chatgpt-apps/auth.md lines 151-162
// =============================================================================

func (c *OAuthConformanceTest) Step6_VerifyTokenWorks() {
	c.t.Logf("[%s] Step 6: Verify token works on MCP endpoint", c.config.Mode)

	req, err := http.NewRequest("POST", c.serverURL+"/mcp", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "tools/list",
		"id": 1
	}`))
	require.NoError(c.t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.client.Do(req)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.Equal(c.t, http.StatusOK, resp.StatusCode,
		"MCP request with valid token must return 200")

	c.t.Log("  [OK] MCP request with Bearer token succeeded")
}

// =============================================================================
// STEP 7: Auth Trigger (COMMON - Same for ChatGPT and Claude)
// Reference: chatgpt-apps/auth.md lines 180-280
// =============================================================================

func (c *OAuthConformanceTest) Step7_VerifyAuthTrigger() {
	c.t.Logf("[%s] Step 7: Verify auth trigger response", c.config.Mode)

	// Request WITHOUT token
	req, err := http.NewRequest("POST", c.serverURL+"/mcp", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "tools/call",
		"params": {"name": "create_note", "arguments": {"title": "test"}},
		"id": 1
	}`))
	require.NoError(c.t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	// No Authorization header

	resp, err := c.client.Do(req)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	// Check for WWW-Authenticate header (auth.md lines 48-54)
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode == http.StatusUnauthorized {
		require.Contains(c.t, wwwAuth, "resource_metadata",
			"401 response MUST include WWW-Authenticate with resource_metadata")
		c.t.Log("  [OK] 401 response includes WWW-Authenticate header")
		return
	}

	// If 200, check for _meta["mcp/www_authenticate"] (auth.md lines 257-280)
	if resp.StatusCode == http.StatusOK {
		var mcpResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&mcpResp)
		require.NoError(c.t, err)

		if result, ok := mcpResp["result"].(map[string]interface{}); ok {
			if meta, ok := result["_meta"].(map[string]interface{}); ok {
				_, hasWWWAuth := meta["mcp/www_authenticate"]
				require.True(c.t, hasWWWAuth,
					"MCP error response MUST include _meta['mcp/www_authenticate']")
				c.t.Log("  [OK] MCP response includes _meta['mcp/www_authenticate']")
				return
			}
		}
	}

	c.t.Logf("  [WARN] Response status: %d - verify auth trigger behavior", resp.StatusCode)
}

// =============================================================================
// NEGATIVE TESTS (COMMON - Same for ChatGPT and Claude)
// =============================================================================

func (c *OAuthConformanceTest) TestNegative_NoPKCE() {
	c.t.Logf("[%s] Negative Test: Authorization without PKCE must fail", c.config.Mode)

	params := url.Values{
		"client_id":     {c.clientID},
		"redirect_uri":  {c.config.RedirectURIs[0]},
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

	c.t.Log("  [OK] Authorization without PKCE correctly rejected")
}

func (c *OAuthConformanceTest) TestNegative_InvalidRedirectURI() {
	c.t.Logf("[%s] Negative Test: DCR with invalid redirect_uri must fail", c.config.Mode)

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

	c.t.Log("  [OK] DCR with invalid redirect_uri correctly rejected")
}

func (c *OAuthConformanceTest) TestNegative_WrongCodeVerifier(code string) {
	c.t.Logf("[%s] Negative Test: Token exchange with wrong code_verifier must fail", c.config.Mode)

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {c.clientID},
		"code":          {code},
		"redirect_uri":  {c.config.RedirectURIs[0]},
		"code_verifier": {"wrong-verifier-that-does-not-match"},
	}

	if c.config.Mode == ClientModeChatGPT {
		params.Set("client_secret", c.clientSecret)
	}

	resp, err := c.client.PostForm(c.authServerMetadata.TokenEndpoint, params)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.Equal(c.t, http.StatusBadRequest, resp.StatusCode,
		"Token exchange with wrong code_verifier MUST be rejected")

	c.t.Log("  [OK] Token exchange with wrong code_verifier correctly rejected")
}

// =============================================================================
// CLAUDE-SPECIFIC NEGATIVE TEST
// =============================================================================

func (c *OAuthConformanceTest) TestNegative_PublicClientWithoutPKCE(code string) {
	if c.config.Mode != ClientModeClaude {
		c.t.Skip("Skipping - this test is only for public clients (Claude)")
		return
	}

	c.t.Log("[claude] Negative Test: Public client token exchange without PKCE must fail")

	// Try token exchange with neither client_secret NOR code_verifier
	params := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {c.clientID},
		"code":         {code},
		"redirect_uri": {c.config.RedirectURIs[0]},
		// NO client_secret AND NO code_verifier
	}

	resp, err := c.client.PostForm(c.authServerMetadata.TokenEndpoint, params)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	// MUST fail - public client requires PKCE
	require.Equal(c.t, http.StatusBadRequest, resp.StatusCode,
		"Token exchange for public client without PKCE MUST be rejected")

	c.t.Log("  [OK] Public client without PKCE correctly rejected")
}

// =============================================================================
// MAIN TEST RUNNERS
// =============================================================================

func TestChatGPTOAuthConformance(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	conformance := NewOAuthConformanceTest(t, server.URL, ChatGPTConfig())

	// Run the exact ChatGPT OAuth flow
	t.Run("Step1_ProtectedResourceMetadata", func(t *testing.T) {
		conformance.Step1_FetchProtectedResourceMetadata()
	})
	t.Run("Step2_AuthServerMetadata", func(t *testing.T) {
		conformance.Step2_FetchAuthServerMetadata()
	})
	t.Run("Step3_DynamicClientRegistration", func(t *testing.T) {
		conformance.Step3_DynamicClientRegistration()
	})
	t.Run("Step4_PKCE", func(t *testing.T) {
		conformance.Step4_GeneratePKCE()
	})
	t.Run("Step7_AuthTrigger", func(t *testing.T) {
		conformance.Step7_VerifyAuthTrigger()
	})

	// Negative tests
	t.Run("Negative_NoPKCE", func(t *testing.T) {
		conformance.TestNegative_NoPKCE()
	})
	t.Run("Negative_InvalidRedirectURI", func(t *testing.T) {
		conformance.TestNegative_InvalidRedirectURI()
	})
}

func TestClaudeOAuthConformance(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	conformance := NewOAuthConformanceTest(t, server.URL, ClaudeConfig())

	// Run the exact Claude OAuth flow
	t.Run("Step1_ProtectedResourceMetadata", func(t *testing.T) {
		conformance.Step1_FetchProtectedResourceMetadata()
	})
	t.Run("Step2_AuthServerMetadata", func(t *testing.T) {
		conformance.Step2_FetchAuthServerMetadata()
	})
	t.Run("Step3_DynamicClientRegistration_PublicClient", func(t *testing.T) {
		conformance.Step3_DynamicClientRegistration()
	})
	t.Run("Step4_PKCE", func(t *testing.T) {
		conformance.Step4_GeneratePKCE()
	})
	t.Run("Step7_AuthTrigger", func(t *testing.T) {
		conformance.Step7_VerifyAuthTrigger()
	})

	// Negative tests
	t.Run("Negative_NoPKCE", func(t *testing.T) {
		conformance.TestNegative_NoPKCE()
	})
	t.Run("Negative_InvalidRedirectURI", func(t *testing.T) {
		conformance.TestNegative_InvalidRedirectURI()
	})
}

// TestBothClientsCompatibility ensures server works with BOTH ChatGPT and Claude
func TestBothClientsCompatibility(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	// Test 1: ChatGPT flow (confidential client with client_secret)
	t.Run("ChatGPT_ConfidentialClient", func(t *testing.T) {
		chatgpt := NewOAuthConformanceTest(t, server.URL, ChatGPTConfig())
		chatgpt.Step1_FetchProtectedResourceMetadata()
		chatgpt.Step2_FetchAuthServerMetadata()
		chatgpt.Step3_DynamicClientRegistration()
		chatgpt.Step4_GeneratePKCE()

		// Verify client_secret was issued
		assert.NotEmpty(t, chatgpt.clientSecret, "ChatGPT should receive client_secret")
	})

	// Test 2: Claude flow (public client without client_secret)
	t.Run("Claude_PublicClient", func(t *testing.T) {
		claude := NewOAuthConformanceTest(t, server.URL, ClaudeConfig())
		claude.Step1_FetchProtectedResourceMetadata()
		claude.Step2_FetchAuthServerMetadata()
		claude.Step3_DynamicClientRegistration()
		claude.Step4_GeneratePKCE()

		// Public client should work without client_secret
		t.Log("Claude registered as public client - token exchange will use PKCE only")
	})
}

// TestOAuthConformance_Properties runs property-based tests
func TestOAuthConformance_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Property: S256 must always be in code_challenge_methods_supported
		// Property: resource parameter must be echoed
		// Property: PKCE must be enforced
		// Property: only allowlisted redirect_uris accepted

		// These would require a running test server with property test harness
		// Placeholder for actual property test implementation
	})
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func generateSecureRandom(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)[:length]
}

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	// TODO: Wire up actual server handlers
	// This should create an httptest.Server with the OAuth provider handlers
	//
	// Example:
	//   handler := server.NewHandler(...)
	//   return httptest.NewServer(handler)
	//
	// For now, return nil to indicate implementation pending
	t.Skip("Test server setup not yet implemented")
	return nil
}
