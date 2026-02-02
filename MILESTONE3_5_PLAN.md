# Milestone 3.5: OAuth 2.1 Provider (For ChatGPT + Claude Code)

**Goal**: Maintain OAuth 2.1 provider conforming to MCP authorization spec so **both ChatGPT and Claude Code** can authenticate users and access their notes via MCP.

**Status**: ✅ Core Implementation Complete (Custom Provider)

---

## Research Findings: Fosite vs Custom Implementation

### Fosite Library Evaluation

The `github.com/ory/fosite` library was evaluated for potential adoption. **Conclusion: Keep custom implementation.**

| Feature | Fosite Support | Current Custom Implementation |
|---------|----------------|------------------------------|
| **RFC 7591 DCR** | ❌ Not supported | ✅ Full support |
| **RFC 8414 Auth Server Metadata** | ❌ Manual implementation needed | ✅ Full support |
| **RFC 9728 Protected Resource Metadata** | ❌ Not supported | ✅ Full support |
| **Ed25519/EdDSA JWT Signing** | ⚠️ Limited (requires custom strategy) | ✅ Full support via go-jose |
| **PKCE S256** | ✅ Supported | ✅ Full support |
| **Public Client Support** | ✅ Supported | ✅ Full support |
| **Confidential Client Support** | ✅ Supported | ✅ Full support |

**Rationale for keeping custom implementation:**
1. Fosite would require custom implementations for DCR, metadata endpoints, and Ed25519 anyway
2. Current implementation already handles all MCP/ChatGPT/Claude requirements
3. No benefit to adding fosite as a dependency when custom code is needed regardless
4. Current implementation is ~918 lines - manageable and well-tested

### Current Implementation Files

- `internal/oauth/provider.go` - Core OAuth provider with Ed25519 JWT signing
- `internal/oauth/handlers.go` - Authorization and Token endpoints with PKCE
- `internal/oauth/dcr.go` - Dynamic Client Registration (public + confidential clients)
- `internal/auth/oauth_middleware.go` - Token verification middleware

---

## Test Strategy Evaluation

### Current Test Coverage

| Test File | Type | Coverage | Assessment |
|-----------|------|----------|------------|
| `tests/e2e/oauth_auth_test.go` | Property-based | Externally observable behavior | ✅ Keep |
| `tests/e2e/integration_test.go` | Property-based | Full OAuth + MCP flow | ✅ Keep |
| `tests/e2e/openai/conformance_test.go` | E2E with real API | **OAuth + Function calling** | ✅ **Updated** |
| `tests/e2e/claude/conformance_test.go` | E2E with CLI | **OAuth + MCP flow** | ✅ **Updated** |

### Tests That Cover Externally Observable Behavior (KEEP)

These tests simulate actual client behavior (ChatGPT/Claude) and test the public API contract:

1. **`TestChatGPTOAuthConformance`** - 7-step ChatGPT flow simulation
   - Protected Resource Metadata discovery
   - Auth Server Metadata discovery
   - Dynamic Client Registration (confidential client)
   - Authorization Code + PKCE
   - Token Exchange with client_secret
   - Token Verification (iss, aud, exp, scopes)
   - Auth Trigger response (`_meta["mcp/www_authenticate"]`)

2. **`TestClaudeOAuthConformance`** - 7-step Claude flow simulation
   - Same as ChatGPT but with `token_endpoint_auth_method=none` (public client)
   - Token Exchange WITHOUT client_secret (PKCE only)

3. **`testIntegration_OAuthMCP_Properties`** - Full OAuth + MCP CRUD
   - OAuth authentication → MCP session → Note CRUD operations
   - Property: roundtrip, idempotence, isolation

### Tests to Simplify

The current tests are well-structured around externally observable behavior. No significant simplification needed.

### Gap: Real OAuth in Conformance Tests - ✅ RESOLVED

**Previous Problem**: Conformance tests bypassed OAuth with hardcoded user IDs.

**Solution Implemented**:
- `tests/e2e/openai/conformance_test.go` - Updated with full OAuth authentication
- `tests/e2e/claude/conformance_test.go` - Updated with full OAuth authentication

**Current flow (both OpenAI and Claude)**:
```
AI API → DCR → PKCE auth → Token exchange → Bearer token → Notes API/MCP
```

**New Test Functions**:
- `TestOpenAI_OAuth_Integration` - Tests OAuth + OpenAI function calling
- `TestClaude_OAuth_Integration` - Tests OAuth + MCP (parity with OpenAI)

Both tests verify:
1. OAuth token works for authenticated requests
2. Unauthenticated requests return 401 + WWW-Authenticate
3. Metadata endpoints work correctly
4. Public client DCR works (Claude-style)

---

## Remaining Work

### Phase 1: ✅ OAuth Flow Added to Conformance Tests - COMPLETE

The `tests/e2e/openai/conformance_test.go` and `tests/e2e/claude/conformance_test.go` now include full OAuth authentication flow:

**Implementation approach**: Create OAuth-enabled test server, perform full DCR → PKCE → token exchange flow, use access token for all API calls.

**Note**: The original simple test environments are still available for basic CRUD testing without OAuth overhead. The new OAuth tests provide parity between OpenAI and Claude testing.

**Test coverage improvement**: The tests now verify the complete production flow including OAuth token validation.
- Generate PAT for that user
- Use PAT as Bearer token in function calls

**Option B: Full OAuth flow in test setup**
- Perform DCR → Authorization → Token Exchange
- Use access_token for MCP requests

Recommended: **Option A** for simplicity in e2e tests. The OAuth flow itself is already tested by `TestChatGPTOAuthConformance` and `TestClaudeOAuthConformance`.

### Phase 2: Real Client Testing (Manual/CI Integration)

For production validation, test with actual Claude Code CLI:
```bash
# 1. Start server with ngrok
ngrok http 8080

# 2. In Claude Code, connect to MCP server
/mcp add https://<ngrok-url>/mcp

# 3. Claude Code will:
#    - Discover protected resource metadata
#    - Perform DCR (public client)
#    - Open browser for authorization
#    - Exchange code for token
#    - Use token for MCP calls
```

---

## Architecture (Implemented)

### OAuth Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OAuth Flow (ChatGPT + Claude)                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Step 1: Fetch Protected Resource Metadata                          │
│  GET /.well-known/oauth-protected-resource                          │
│  → Returns: resource, authorization_servers                         │
│                                                                     │
│  Step 2: Fetch Auth Server Metadata                                 │
│  GET /.well-known/oauth-authorization-server                        │
│  → Returns: endpoints, code_challenge_methods_supported: ["S256"]   │
│                                                                     │
│  Step 3: Dynamic Client Registration                                │
│  POST /oauth/register                                               │
│  → ChatGPT: confidential client (gets client_secret)                │
│  → Claude: public client (token_endpoint_auth_method=none)          │
│                                                                     │
│  Step 4: Authorization Code + PKCE                                  │
│  GET /oauth/authorize?code_challenge=...&code_challenge_method=S256 │
│  → User consents → Redirect with code                               │
│                                                                     │
│  Step 5: Token Exchange                                             │
│  POST /oauth/token                                                  │
│  → ChatGPT: code + code_verifier + client_secret                    │
│  → Claude: code + code_verifier (no secret)                         │
│  → Returns: access_token (JWT signed with Ed25519)                  │
│                                                                     │
│  Step 6: MCP Requests with Bearer Token                             │
│  POST /mcp with Authorization: Bearer <token>                       │
│  → Token verified: signature, iss, aud, exp, scopes                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Client Type Differences

| Feature | Claude (Public) | ChatGPT (Confidential) |
|---------|-----------------|------------------------|
| **DCR Request** | `token_endpoint_auth_method: "none"` | (default) |
| **Client Secret** | Not issued | Issued and required |
| **Token Exchange** | PKCE only | PKCE + client_secret |
| **Redirect URI** | `https://claude.ai/api/mcp/auth_callback` | `https://chatgpt.com/connector_platform_oauth_redirect` |

---

## Success Criteria

### Property-Based Tests (MUST PASS)

```bash
./scripts/ci.sh quick
```

- [x] `TestChatGPTOAuthConformance` - All 7 steps pass
- [x] `TestClaudeOAuthConformance` - All 7 steps pass (public client)
- [x] `testIntegration_OAuthMCP_Properties` - OAuth + MCP CRUD roundtrip
- [x] `testIntegration_MCPFullCRUD_Properties` - MCP operations via OAuth tokens

### Negative Tests (MUST PASS)

- [x] Authorization without PKCE rejected
- [x] Invalid redirect_uri rejected (not in allowlist)
- [x] Wrong code_verifier rejected
- [x] Public client without PKCE on token exchange rejected
- [x] Expired token rejected
- [x] Wrong audience rejected

### OpenAI Conformance Tests (REQUIRES UPDATE)

- [ ] Add OAuth flow or PAT authentication to `tests/e2e/openai/conformance_test.go`
- [ ] Remove hardcoded `TestUserID`
- [ ] Test full: OpenAI API → OAuth → MCP → Note CRUD

---

## File Structure (Implemented)

```
internal/
├── oauth/
│   ├── provider.go      # Core provider, Ed25519 JWT signing
│   ├── handlers.go      # /oauth/authorize, /oauth/token
│   ├── dcr.go           # Dynamic Client Registration
│   └── metadata.go      # Well-known endpoints (RFC 8414, RFC 9728)
├── auth/
│   └── oauth_middleware.go  # Token verification middleware
tests/
├── e2e/
│   ├── oauth_auth_test.go      # ChatGPT + Claude conformance
│   ├── integration_test.go     # OAuth + MCP property tests
│   └── openai/
│       └── conformance_test.go # OpenAI function calling (needs OAuth)
```

---

## Commands

```bash
# Run quick tests (before every commit)
./scripts/ci.sh quick

# Run full tests with coverage
./scripts/ci.sh full

# Test specific OAuth conformance
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)" && \
CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5" CGO_LDFLAGS="-lm" \
go test -v -run "TestChatGPTOAuthConformance|TestClaudeOAuthConformance" ./tests/e2e/...
```

---

## References

### Specifications
- [MCP Authorization Spec (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [RFC 9728 - OAuth Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8414 - OAuth Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 7591 - Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)

### Client Documentation
- `chatgpt-apps/auth.md` - OpenAI/ChatGPT OAuth requirements
- [Claude Code MCP Docs](https://code.claude.com/docs/en/mcp)
- [Building Custom Connectors](https://support.claude.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers)
