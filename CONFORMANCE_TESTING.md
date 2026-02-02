# Conformance Testing Guide

This guide documents conformance test suites for MCP (Model Context Protocol) and OAuth 2.1, including installation, usage, and CI/CD integration.

## Table of Contents
- [MCP Conformance Testing](#mcp-conformance-testing)
- [OAuth 2.1 Conformance Testing](#oauth-21-conformance-testing)
- [Go-Native Testing Alternatives](#go-native-testing-alternatives)

---

## MCP Conformance Testing

### Official MCP Conformance Test Suite

**Package:** `@modelcontextprotocol/conformance`
**Repository:** https://github.com/modelcontextprotocol/conformance
**Status:** Work in progress (v0.1.9 as of January 2026)

### Installation

No installation required - the suite runs directly via npx:

```bash
# Check available scenarios
npx @modelcontextprotocol/conformance list
```

### Test Scenarios Covered

#### Server-Side Scenarios
- `server-initialize` - Initialization and capabilities validation
- `tools-list` - Tool listing endpoint verification
- `tools-call-*` - Various tool invocation patterns
- `resources-*` - Resource management operations
- `prompts-*` - Prompt handling functionality

#### Client-Side Scenarios
- `initialize` - Handshake protocol validation
- `tools-call` - Tool invocation testing
- `auth/basic-dcr` - OAuth Dynamic Client Registration
- `auth/basic-metadata-var1` - OAuth with authorization metadata

### Running Tests Against a Go Server

#### Testing a Server (localhost:8080)

```bash
# Run all server scenarios
npx @modelcontextprotocol/conformance server --url http://localhost:8080/mcp

# Run a specific scenario
npx @modelcontextprotocol/conformance server \
  --url http://localhost:8080/mcp \
  --scenario server-initialize

# Run with verbose output
npx @modelcontextprotocol/conformance server \
  --url http://localhost:8080/mcp \
  --verbose

# Run with custom timeout (milliseconds)
npx @modelcontextprotocol/conformance server \
  --url http://localhost:8080/mcp \
  --timeout 60000
```

#### Testing a Client

```bash
# Run a specific client scenario
npx @modelcontextprotocol/conformance client \
  --command "go run ./cmd/mcp-client" \
  --scenario initialize

# Run an entire test suite
npx @modelcontextprotocol/conformance client \
  --command "go run ./cmd/mcp-client" \
  --suite auth

# Run with expected failures baseline
npx @modelcontextprotocol/conformance client \
  --command "go run ./cmd/mcp-client" \
  --scenario initialize \
  --expected-failures ./conformance-baseline.yml
```

### Expected Output

Results are saved to `results/server-<scenario>-<timestamp>/checks.json` with pass/fail status for each test.

**Success Example:**
```
✓ server-initialize
  ✓ Server responds to initialize request
  ✓ Server returns valid capabilities
  ✓ Protocol version matches specification
```

**Failure Example:**
```
✗ server-initialize
  ✓ Server responds to initialize request
  ✗ Server returns valid capabilities
    Expected: capabilities.tools = true
    Received: capabilities.tools = undefined
```

### CI/CD Integration

#### GitHub Actions Example (Official Composite Action)

For testing servers:

```yaml
name: MCP Conformance Tests

on: [push, pull_request]

jobs:
  conformance:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Build server
        run: go build -o mcp-server ./cmd/server

      - name: Start server
        run: |
          ./mcp-server &
          sleep 2

      - name: Run MCP conformance tests
        uses: modelcontextprotocol/conformance@v0.1.11
        with:
          mode: server
          url: http://localhost:8080/mcp
          expected-failures: ./conformance-baseline.yml
```

For testing clients:

```yaml
      - name: Run MCP conformance tests
        uses: modelcontextprotocol/conformance@v0.1.11
        with:
          mode: client
          command: 'go run ./cmd/mcp-client'
          expected-failures: ./conformance-baseline.yml
```

#### Manual GitHub Actions Setup (Without Composite Action)

```yaml
name: MCP Conformance Tests (Manual)

on: [push, pull_request]

jobs:
  conformance:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Build and start server
        run: |
          go build -o mcp-server ./cmd/server
          ./mcp-server &
          sleep 2

      - name: Run conformance tests
        run: |
          npx @modelcontextprotocol/conformance server \
            --url http://localhost:8080/mcp \
            --verbose

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: conformance-results
          path: results/
```

### Configuration for Go Servers

The conformance framework automatically:
- Appends server URL as a command argument
- Sets `MCP_CONFORMANCE_SCENARIO` environment variable
- Provides `MCP_CONFORMANCE_CONTEXT` with scenario-specific JSON data

Your Go server should:
1. Listen on the specified port (e.g., 8080)
2. Implement the MCP JSON-RPC protocol
3. Handle all required MCP methods

Example Go server setup:
```go
package main

import (
    "log"
    "net/http"
    "os"

    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
    server := mcp.NewServer()

    // Register handlers
    server.HandleInitialize(func(req *mcp.InitializeRequest) (*mcp.InitializeResponse, error) {
        return &mcp.InitializeResponse{
            ProtocolVersion: "2024-11-05",
            Capabilities: mcp.ServerCapabilities{
                Tools: &mcp.ToolsCapability{},
                Resources: &mcp.ResourcesCapability{},
            },
        }, nil
    })

    http.HandleFunc("/mcp", server.ServeHTTP)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Testing with MCP Inspector

For manual testing during development:

```bash
# Install MCP Inspector
npm install -g @modelcontextprotocol/inspector

# Test your server
npx @modelcontextprotocol/inspector
```

Then configure with:
- Transport: HTTP
- URL: http://localhost:8080/mcp

Or use curl for quick tests:
```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "initialize",
    "id": 1,
    "params": {
      "protocolVersion": "2024-11-05",
      "clientInfo": {
        "name": "test-client",
        "version": "1.0.0"
      }
    }
  }'
```

---

## OAuth 2.1 Conformance Testing

### Current Status

**Important:** OAuth 2.1 is still a draft specification (draft-ietf-oauth-v2-1-14) with an expiration date of April 23, 2026. There is no dedicated OAuth 2.1 conformance test suite from the OpenID Foundation as of February 2026.

### OpenID Foundation Conformance Suite

The OpenID Foundation provides a comprehensive conformance suite for OpenID Connect and FAPI profiles, which include OAuth 2.0 features like PKCE.

**Repository:** https://gitlab.com/openid/conformance-suite
**License:** MIT
**Production Instance:** https://www.certification.openid.net/
**Staging Instance:** https://staging.certification.openid.net/

### Installation Methods

#### Option 1: Use Public Instance

Access the hosted version at https://www.certification.openid.net/ (no installation required).

#### Option 2: Docker Installation (Recommended for Local Testing)

```bash
# Clone the repository
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite

# Checkout a stable release
git checkout release-v5.1.35

# Build with Docker Compose
MAVEN_CACHE=./m2 docker-compose -f builder-compose.yml run builder

# Start the suite
docker-compose up

# Alternative: Use development compose file
docker-compose -f docker-compose-dev.yml up
```

After starting, access the suite at: **https://localhost:8443/**

### Test Scenarios Covered

The suite includes comprehensive testing for:

#### OAuth 2.0 Core Features
- Authorization Code Flow
- PKCE (Proof Key for Code Exchange)
  - Code verifier length and entropy validation
  - Code challenge method validation (S256)
  - Verifier uniqueness per request
- Token endpoint validation
- Authorization endpoint validation
- Token introspection
- Token revocation

#### OpenID Connect Profiles
- Basic Profile
- Implicit Profile
- Hybrid Profile
- Dynamic Client Registration

#### FAPI (Financial-grade API)
- FAPI 1.0 Advanced Final
- FAPI 2.0 Security Profile
- FAPI 2.0 Message Signing

### How to Test OAuth Provider Endpoints

#### Prerequisites

1. **Network Configuration:** Your OAuth provider must be accessible from the conformance suite
2. **Redirect URIs:** Configure your provider to accept redirects from the suite
3. **Test Configuration:** Prepare a JSON configuration file

#### Example: Testing Against localhost:8080

**Configuration File (conformance-config.json):**

```json
{
  "alias": "My OAuth Provider",
  "description": "Testing local OAuth 2.0 implementation",
  "server": {
    "discoveryUrl": "http://host.docker.internal:8080/.well-known/openid-configuration"
  },
  "client": {
    "client_id": "test-client",
    "client_secret": "test-secret"
  },
  "client2": {
    "client_id": "test-client-2",
    "client_secret": "test-secret-2"
  },
  "browser": [
    {
      "match": "https://localhost:8443/.*",
      "tasks": [
        {
          "task": "Initial",
          "match": "http://host.docker.internal:8080/authorize.*",
          "commands": [
            ["text", "name=username", "testuser"],
            ["text", "name=password", "testpass"],
            ["click", "name=submit"]
          ]
        }
      ]
    }
  ]
}
```

**Note:** Use `host.docker.internal` instead of `localhost` when running the suite in Docker to access services on the host machine.

#### Running Tests via Web Interface

1. Navigate to https://localhost:8443/
2. Click "Create a new test plan"
3. Select test plan (e.g., "OpenID Connect Core: Basic Certification Profile")
4. Upload your configuration JSON
5. Click "Start Test Plan"
6. Follow browser automation prompts

### PKCE Validation Tests

The conformance suite validates:
- **Code Verifier:** Length (43-128 characters), entropy, uniqueness
- **Code Challenge:** Proper S256 transformation
- **Challenge Method:** Supports plain and S256
- **Flow Integration:** PKCE correctly integrated in authorization code flow

PKCE testing is applied across:
- OIDCC (OpenID Connect Core)
- FAPI1ADV (FAPI 1.0 Advanced)
- FAPIRWID2 (FAPI Read/Write ID2)

### CI/CD Integration

#### Using run-test-plan.py Script

The suite provides a Python automation script for CI/CD:

```bash
# Basic usage
python scripts/run-test-plan.py \
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
  ./conformance-config.json

# With expected failures and skips
python scripts/run-test-plan.py \
  --expected-failures-file ./expected-failures.json \
  --expected-skips-file ./expected-skips.json \
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
  ./conformance-config.json
```

#### GitHub Actions Example

```yaml
name: OAuth Conformance Tests

on: [push, pull_request]

jobs:
  conformance:
    runs-on: ubuntu-latest

    services:
      conformance-suite:
        image: ghcr.io/openid/conformance-suite:latest
        ports:
          - 8443:8443

      mongodb:
        image: mongo:5.0
        ports:
          - 27017:27017

    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Build OAuth server
        run: go build -o oauth-server ./cmd/oauth

      - name: Start OAuth server
        run: |
          ./oauth-server &
          sleep 5

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Clone conformance suite
        run: |
          git clone https://gitlab.com/openid/conformance-suite.git
          cd conformance-suite
          pip install -r scripts/requirements.txt

      - name: Run conformance tests
        run: |
          cd conformance-suite
          python scripts/run-test-plan.py \
            --expected-failures-file ../oauth-expected-failures.json \
            "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
            ../oauth-conformance-config.json
```

#### Docker Compose for CI Testing

**docker-compose-ci.yml:**

```yaml
version: '3'

services:
  oauth-server:
    build: .
    ports:
      - "8080:8080"
    networks:
      - test-network

  conformance-suite:
    image: ghcr.io/openid/conformance-suite:latest
    ports:
      - "8443:8443"
    depends_on:
      - mongodb
      - oauth-server
    networks:
      - test-network

  mongodb:
    image: mongo:5.0
    ports:
      - "27017:27017"
    networks:
      - test-network

networks:
  test-network:
    driver: bridge
```

Run with:
```bash
docker-compose -f docker-compose-ci.yml up --abort-on-container-exit
```

### Expected Output / Pass Criteria

#### Success Output
```
Test Plan: oidcc-basic-certification-test-plan
Status: PASSED

Tests Run: 45
Passed: 45
Failed: 0
Skipped: 0
Warnings: 0

Result: PASS
```

#### Failure Output
```
Test Plan: oidcc-basic-certification-test-plan
Status: FAILED

Tests Run: 45
Passed: 42
Failed: 3
Skipped: 0
Warnings: 1

Failed Tests:
- oidcc-ensure-request-object-signature-alg-is-not-none
- oidcc-server-rotate-keys
- oidcc-userinfo-endpoint-works

Result: FAIL
```

### Manual vs Automated Testing

**Automated Capabilities:**
- ✅ Full automation possible with `run-test-plan.py`
- ✅ Browser interaction can be scripted in config JSON
- ✅ Can run in CI/CD pipelines
- ✅ Headless browser support
- ✅ Parallel test execution

**Manual Steps May Be Required For:**
- Some advanced FAPI tests requiring specific user interactions
- Dynamic client registration with out-of-band verification
- Certificate-bound access tokens with custom PKI

### Limitations for OAuth 2.1

Since OAuth 2.1 is still in draft:
- No dedicated OAuth 2.1 test suite exists
- Use OpenID Connect suite with PKCE tests as proxy
- Focus on these test plans:
  - `oidcc-basic-certification-test-plan` (includes PKCE)
  - `fapi2-security-profile` (OAuth 2.1-aligned)
  - `fapi-rw-id2` (advanced OAuth 2.0 + PKCE)

### Support and Bug Reports

- **Email:** certification@oidf.org
- **Issues:** https://gitlab.com/openid/conformance-suite/issues
- **Documentation:** https://gitlab.com/openid/conformance-suite/-/wikis/home

---

## Go-Native Testing Alternatives

While there are no complete Go-native conformance test suites equivalent to the official MCP and OpenID suites, several Go libraries provide testing utilities.

### For OAuth 2.0 / PKCE Testing

#### 1. github.com/256dpi/oauth2/v2/oauth2test

**Package:** https://pkg.go.dev/github.com/256dpi/oauth2/v2/oauth2test
**Repository:** https://github.com/256dpi/oauth2

Provides reusable integration tests for OAuth2 servers.

**Test Functions:**
- `AccessTokenTest` - Validates access tokens
- `AuthorizationCodeGrantTest` - Tests authorization code flow
- `AuthorizationEndpointTest` - General authorization endpoint tests
- `ClientCredentialsGrantTest` - Tests client credentials grant
- `PasswordGrantTest` - Tests resource owner password credentials
- `RefreshTokenTest` - Tests token refresh
- `TokenRevocationTest` - Tests token revocation

**Usage Example:**

```go
package oauth_test

import (
    "testing"
    "net/http"

    "github.com/256dpi/oauth2/v2/oauth2test"
)

func TestOAuthServer(t *testing.T) {
    // Create your OAuth handler
    handler := NewOAuthHandler()

    // Define test spec
    spec := &oauth2test.Spec{
        Handler:                    handler,
        TokenEndpoint:              "http://localhost:8080/oauth/token",
        AuthorizeEndpoint:          "http://localhost:8080/oauth/authorize",
        RevocationEndpoint:         "http://localhost:8080/oauth/revoke",
        IntrospectionEndpoint:      "http://localhost:8080/oauth/introspect",
        ProtectedResource:          "http://localhost:8080/api/protected",
        PasswordGrantSupport:       true,
        ClientCredentialsGrantSupport: true,
        RefreshTokenGrantSupport:   true,
        PKCESupport:               true,
    }

    // Run authorization code grant test
    oauth2test.AuthorizationCodeGrantTest(t, spec)

    // Run PKCE-specific tests
    oauth2test.PKCETest(t, spec)
}
```

#### 2. golang.org/x/oauth2

**Package:** https://pkg.go.dev/golang.org/x/oauth2

Official Go OAuth2 library with PKCE support.

**PKCE Implementation:**

```go
package main

import (
    "context"
    "golang.org/x/oauth2"
)

func main() {
    config := &oauth2.Config{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        Endpoint: oauth2.Endpoint{
            AuthURL:  "http://localhost:8080/oauth/authorize",
            TokenURL: "http://localhost:8080/oauth/token",
        },
        RedirectURL: "http://localhost:8081/callback",
        Scopes:      []string{"read", "write"},
    }

    // Generate PKCE verifier
    verifier := oauth2.GenerateVerifier()

    // Create auth URL with PKCE challenge
    authURL := config.AuthCodeURL("state",
        oauth2.AccessTypeOffline,
        oauth2.S256ChallengeOption(verifier))

    // Exchange code for token with verifier
    token, err := config.Exchange(context.Background(),
        authCode,
        oauth2.VerifierOption(verifier))
}
```

**Testing PKCE:**

```go
package oauth_test

import (
    "testing"
    "golang.org/x/oauth2"
)

func TestPKCEGeneration(t *testing.T) {
    // Test verifier generation
    verifier := oauth2.GenerateVerifier()

    if len(verifier) != 43 {
        t.Errorf("Expected verifier length 43, got %d", len(verifier))
    }

    // Test uniqueness
    verifier2 := oauth2.GenerateVerifier()
    if verifier == verifier2 {
        t.Error("Verifiers should be unique")
    }
}

func TestPKCEChallenge(t *testing.T) {
    verifier := oauth2.GenerateVerifier()

    // S256 challenge is automatically computed
    option := oauth2.S256ChallengeOption(verifier)

    // Test that option is properly created
    if option == nil {
        t.Error("S256ChallengeOption should not be nil")
    }
}
```

#### 3. github.com/grokify/go-pkce

**Package:** https://pkg.go.dev/github.com/grokify/go-pkce
**Repository:** https://github.com/grokify/go-pkce

Dedicated PKCE library for Go.

**Usage:**

```go
package main

import (
    "github.com/grokify/go-pkce"
)

func main() {
    // Generate PKCE parameters
    pkcePair, err := pkce.NewPKCEPair(pkce.S256)
    if err != nil {
        panic(err)
    }

    // Use in authorization request
    authURL := fmt.Sprintf(
        "%s?client_id=%s&code_challenge=%s&code_challenge_method=%s",
        config.AuthEndpoint,
        config.ClientID,
        pkcePair.CodeChallenge,
        pkcePair.CodeChallengeMethod,
    )

    // Later, exchange with verifier
    tokenRequest := map[string]string{
        "code": authCode,
        "code_verifier": pkcePair.CodeVerifier,
    }
}
```

### For MCP Testing

#### Official Go SDK

**Package:** https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk
**Repository:** https://github.com/modelcontextprotocol/go-sdk

**Testing Example:**

```go
package mcp_test

import (
    "testing"
    "context"

    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPServer(t *testing.T) {
    // Create server
    server := mcp.NewServer()

    // Register handlers
    server.HandleInitialize(func(req *mcp.InitializeRequest) (*mcp.InitializeResponse, error) {
        return &mcp.InitializeResponse{
            ProtocolVersion: "2024-11-05",
            Capabilities: mcp.ServerCapabilities{
                Tools: &mcp.ToolsCapability{},
            },
        }, nil
    })

    // Test initialization
    ctx := context.Background()
    resp, err := server.Initialize(ctx, &mcp.InitializeRequest{
        ProtocolVersion: "2024-11-05",
        ClientInfo: mcp.ClientInfo{
            Name:    "test-client",
            Version: "1.0.0",
        },
    })

    if err != nil {
        t.Fatalf("Initialize failed: %v", err)
    }

    if resp.ProtocolVersion != "2024-11-05" {
        t.Errorf("Expected protocol version 2024-11-05, got %s", resp.ProtocolVersion)
    }

    if resp.Capabilities.Tools == nil {
        t.Error("Expected tools capability to be present")
    }
}

func TestMCPToolsListing(t *testing.T) {
    server := mcp.NewServer()

    // Register a tool
    server.RegisterTool(mcp.Tool{
        Name:        "get_weather",
        Description: "Get current weather",
        InputSchema: mcp.ToolInputSchema{
            Type: "object",
            Properties: map[string]interface{}{
                "location": map[string]string{
                    "type": "string",
                    "description": "City name",
                },
            },
            Required: []string{"location"},
        },
    })

    // Test listing
    ctx := context.Background()
    tools, err := server.ListTools(ctx, &mcp.ListToolsRequest{})

    if err != nil {
        t.Fatalf("ListTools failed: %v", err)
    }

    if len(tools.Tools) != 1 {
        t.Errorf("Expected 1 tool, got %d", len(tools.Tools))
    }

    if tools.Tools[0].Name != "get_weather" {
        t.Errorf("Expected tool name 'get_weather', got '%s'", tools.Tools[0].Name)
    }
}
```

### Custom Integration Test Framework

For comprehensive testing, you can build a custom framework:

```go
package conformance

import (
    "testing"
    "net/http"
    "net/http/httptest"
)

type ConformanceTest struct {
    Name        string
    Description string
    Method      string
    Path        string
    Body        interface{}
    Expected    interface{}
    Validator   func(t *testing.T, resp *http.Response)
}

func RunConformanceTests(t *testing.T, handler http.Handler, tests []ConformanceTest) {
    server := httptest.NewServer(handler)
    defer server.Close()

    for _, test := range tests {
        t.Run(test.Name, func(t *testing.T) {
            // Make request
            req, _ := http.NewRequest(test.Method, server.URL+test.Path, nil)
            resp, err := http.DefaultClient.Do(req)

            if err != nil {
                t.Fatalf("Request failed: %v", err)
            }
            defer resp.Body.Close()

            // Run custom validator
            if test.Validator != nil {
                test.Validator(t, resp)
            }
        })
    }
}

// Usage
func TestMyOAuthServer(t *testing.T) {
    handler := NewOAuthHandler()

    tests := []ConformanceTest{
        {
            Name:   "PKCE Code Challenge",
            Method: "GET",
            Path:   "/oauth/authorize?response_type=code&code_challenge=...",
            Validator: func(t *testing.T, resp *http.Response) {
                if resp.StatusCode != http.StatusFound {
                    t.Errorf("Expected redirect, got %d", resp.StatusCode)
                }
            },
        },
        // Add more tests...
    }

    RunConformanceTests(t, handler, tests)
}
```

---

## Summary Comparison

| Feature | MCP Conformance | OpenID Conformance | Go-Native Tests |
|---------|----------------|-------------------|-----------------|
| **Official Support** | ✅ Official npm package | ✅ Official OpenID Foundation | ⚠️ Community libraries |
| **Installation** | npx (no install) | Docker or hosted | go get |
| **localhost Testing** | ✅ Direct support | ✅ Via host.docker.internal | ✅ Native support |
| **CI/CD Ready** | ✅ GitHub Action | ✅ Python script | ✅ Standard go test |
| **Automation** | ✅ Fully automated | ✅ Fully automated | ✅ Fully automated |
| **Test Coverage** | MCP protocol only | OAuth/OIDC/FAPI | Custom coverage |
| **Learning Curve** | Low | Medium-High | Low |
| **Setup Complexity** | Very Simple | Moderate | Simple |

---

## Recommended Testing Strategy

### For MCP Servers
1. **Development:** Use MCP Inspector for manual testing
2. **CI/CD:** Use `@modelcontextprotocol/conformance` with GitHub Actions
3. **Unit Tests:** Use Go SDK's testing utilities
4. **Integration Tests:** Run conformance suite on every PR

### For OAuth 2.0 Providers
1. **Development:** Use OpenID conformance suite locally via Docker
2. **CI/CD:** Use `run-test-plan.py` for automated validation
3. **Unit Tests:** Use `github.com/256dpi/oauth2/v2/oauth2test`
4. **PKCE Validation:** Use `golang.org/x/oauth2` for implementation
5. **Integration Tests:** Run subset of OpenID tests focusing on PKCE

### Complete CI/CD Pipeline Example

```yaml
name: Full Conformance Testing

on: [push, pull_request]

jobs:
  mcp-conformance:
    name: MCP Conformance Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Build MCP server
        run: go build -o mcp-server ./cmd/mcp

      - name: Start MCP server
        run: |
          ./mcp-server &
          sleep 2

      - name: Run MCP conformance
        uses: modelcontextprotocol/conformance@v0.1.11
        with:
          mode: server
          url: http://localhost:8080/mcp

  oauth-conformance:
    name: OAuth Conformance Tests
    runs-on: ubuntu-latest

    services:
      mongodb:
        image: mongo:5.0
        ports:
          - 27017:27017

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Build OAuth server
        run: go build -o oauth-server ./cmd/oauth

      - name: Start OAuth server
        run: |
          ./oauth-server &
          sleep 5

      - name: Setup conformance suite
        run: |
          git clone https://gitlab.com/openid/conformance-suite.git
          cd conformance-suite
          git checkout release-v5.1.35
          docker-compose -f docker-compose-localtest.yml up -d
          sleep 30

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run OAuth conformance
        run: |
          cd conformance-suite
          pip install -r scripts/requirements.txt
          python scripts/run-test-plan.py \
            "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
            ../oauth-config.json

  go-unit-tests:
    name: Go Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Run Go tests
        run: go test -v -race -coverprofile=coverage.txt ./...

      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          file: ./coverage.txt
```

---

## Additional Resources

### MCP Resources
- MCP Specification: https://github.com/modelcontextprotocol/modelcontextprotocol
- MCP Go SDK: https://github.com/modelcontextprotocol/go-sdk
- MCP Inspector: https://www.npmjs.com/package/@modelcontextprotocol/inspector
- MCP Discord: Check #conformance-testing-wg channel

### OAuth Resources
- OAuth 2.1 Draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
- OAuth 2.0 (RFC 6749): https://datatracker.ietf.org/doc/html/rfc6749
- PKCE (RFC 7636): https://datatracker.ietf.org/doc/html/rfc7636
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- FAPI 2.0: https://openid.net/specs/fapi-2_0.html

### Testing Resources
- OAuth 2.0 Playground: https://www.oauth.com/playground/
- JWT Debugger: https://jwt.io/
- OpenID Certification: https://openid.net/certification/

---

**Document Version:** 1.0
**Last Updated:** 2026-02-02
**Maintained By:** Agent Notes Project
