# Conformance Testing Quick Reference

Quick command reference for MCP and OAuth 2.1 conformance testing.

---

## MCP Conformance Testing

### Test a Server

```bash
# Test all scenarios
npx @modelcontextprotocol/conformance server --url http://localhost:8080/mcp

# Test specific scenario
npx @modelcontextprotocol/conformance server \
  --url http://localhost:8080/mcp \
  --scenario server-initialize

# With verbose output
npx @modelcontextprotocol/conformance server \
  --url http://localhost:8080/mcp \
  --verbose
```

### Test a Client

```bash
# Test initialization
npx @modelcontextprotocol/conformance client \
  --command "go run ./cmd/mcp-client" \
  --scenario initialize

# Test auth suite
npx @modelcontextprotocol/conformance client \
  --command "go run ./cmd/mcp-client" \
  --suite auth
```

### List Available Scenarios

```bash
npx @modelcontextprotocol/conformance list
```

---

## OAuth 2.1 Conformance Testing

### Quick Test with OpenID Suite

```bash
# Clone and setup
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
git checkout release-v5.1.35

# Build and run
MAVEN_CACHE=./m2 docker-compose -f builder-compose.yml run builder
docker-compose up

# Access at: https://localhost:8443/
```

### Automated Testing

```bash
# Basic test plan execution
python scripts/run-test-plan.py \
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
  ./config.json

# With expected failures
python scripts/run-test-plan.py \
  --expected-failures-file ./failures.json \
  --expected-skips-file ./skips.json \
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
  ./config.json
```

---

## Go Testing

### PKCE Testing with golang.org/x/oauth2

```go
import "golang.org/x/oauth2"

// Generate verifier
verifier := oauth2.GenerateVerifier()

// Create auth URL with S256 challenge
authURL := config.AuthCodeURL("state", oauth2.S256ChallengeOption(verifier))

// Exchange with verifier
token, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
```

### Integration Testing with oauth2test

```go
import "github.com/256dpi/oauth2/v2/oauth2test"

spec := &oauth2test.Spec{
    Handler:                    handler,
    TokenEndpoint:              "http://localhost:8080/oauth/token",
    AuthorizeEndpoint:          "http://localhost:8080/oauth/authorize",
    PKCESupport:               true,
}

oauth2test.AuthorizationCodeGrantTest(t, spec)
```

---

## CI/CD Integration

### MCP - GitHub Actions

```yaml
- name: Run MCP conformance
  uses: modelcontextprotocol/conformance@v0.1.11
  with:
    mode: server
    url: http://localhost:8080/mcp
```

### OAuth - GitHub Actions

```yaml
- name: Run OAuth conformance
  run: |
    cd conformance-suite
    python scripts/run-test-plan.py \
      "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
      ../config.json
```

---

## Quick Debug

### Test MCP with curl

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "initialize",
    "id": 1,
    "params": {
      "protocolVersion": "2024-11-05",
      "clientInfo": {"name": "test", "version": "1.0"}
    }
  }'
```

### Test OAuth Authorization

```bash
# Generate PKCE values (using openssl)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '+/' '-_')
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | openssl base64 | tr -d '=' | tr '+/' '-_')

# Authorization request
curl "http://localhost:8080/oauth/authorize?response_type=code&client_id=test&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"
```

---

## Docker Network Config for localhost Testing

### OAuth Config (conformance-config.json)

```json
{
  "server": {
    "discoveryUrl": "http://host.docker.internal:8080/.well-known/openid-configuration"
  },
  "client": {
    "client_id": "test-client",
    "client_secret": "test-secret"
  }
}
```

**Note:** Use `host.docker.internal` instead of `localhost` when testing from Docker containers.

---

## Result Interpretation

### MCP - Success
```
✓ server-initialize
  ✓ All checks passed
```

### MCP - Failure
```
✗ server-initialize
  ✗ Server returns valid capabilities
    Expected: capabilities.tools = true
    Received: capabilities.tools = undefined
```

### OAuth - Success
```
Test Plan: oidcc-basic-certification-test-plan
Status: PASSED
Tests Run: 45 | Passed: 45 | Failed: 0
```

### OAuth - Failure
```
Test Plan: oidcc-basic-certification-test-plan
Status: FAILED
Tests Run: 45 | Passed: 42 | Failed: 3

Failed Tests:
- oidcc-ensure-request-object-signature-alg-is-not-none
```

---

## Common Issues

### MCP: Connection Refused
- Ensure server is running on specified port
- Check firewall rules
- Verify endpoint path (/mcp)

### OAuth: Redirect URI Mismatch
- Add suite redirect URIs to your OAuth config:
  - `https://localhost:8443/callback`
  - `https://staging.certification.openid.net/callback`

### Docker: Cannot Connect to localhost
- Use `host.docker.internal` on Mac/Windows
- Use `172.17.0.1` on Linux
- Or run on same Docker network

---

## Key Resources

| Tool | URL | Purpose |
|------|-----|---------|
| MCP Conformance | https://github.com/modelcontextprotocol/conformance | Official MCP tests |
| OpenID Suite | https://gitlab.com/openid/conformance-suite | OAuth/OIDC tests |
| Public OpenID | https://www.certification.openid.net/ | Hosted testing |
| oauth2test | https://github.com/256dpi/oauth2 | Go OAuth testing |

---

**Quick Start:**
1. Start your server: `go run ./cmd/server`
2. Run MCP tests: `npx @modelcontextprotocol/conformance server --url http://localhost:8080/mcp`
3. Run OAuth tests: Start Docker suite and use web UI at https://localhost:8443/

For detailed documentation, see CONFORMANCE_TESTING.md
