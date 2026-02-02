# Testing Tools and Test Suites

This document provides comprehensive information about official test suites and tools for MCP Protocol, OAuth 2.1, and OIDC testing.

## 1. MCP Protocol Testing

### 1.1 @modelcontextprotocol/conformance Test Suite

The official conformance test suite for the Model Context Protocol.

**Repository**: https://github.com/modelcontextprotocol/conformance

#### Installation

No installation required - run directly with npx:

```bash
npx @modelcontextprotocol/conformance
```

#### Testing MCP Servers

Test your MCP server implementation against conformance requirements:

```bash
# Run all server scenarios (default)
npx @modelcontextprotocol/conformance server --url http://localhost:3000/mcp

# Run a single scenario
npx @modelcontextprotocol/conformance server --url http://localhost:3000/mcp --scenario server-initialize

# List all available server scenarios
npx @modelcontextprotocol/conformance list --server
```

#### Testing MCP Clients

Test your MCP client implementation:

```bash
# Run a single scenario
npx @modelcontextprotocol/conformance client --command "tsx examples/clients/typescript/everything-client.ts" --scenario initialize

# Run an entire suite
npx @modelcontextprotocol/conformance client --command "tsx examples/clients/typescript/everything-client.ts" --suite auth
```

**How it works**: The framework appends the server URL as an argument to your command and sets the `MCP_CONFORMANCE_SCENARIO` environment variable to the scenario name.

#### Expected Output

- Results are saved to `results/<scenario>-<timestamp>/`
- A `checks.json` file contains conformance check results with pass/fail status
- Each test scenario produces detailed logs and validation results

#### CI/CD Integration

The conformance suite can be integrated into GitHub Actions or other CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run MCP Conformance Tests
  run: |
    npx @modelcontextprotocol/conformance server --url http://localhost:3000/mcp
```

**Benefits for CI/CD**:
- Automates MCP validation in CI/CD pipelines
- Catches context mismatches early
- Prevents deployment failures
- Ensures models receive expected inputs

### 1.2 @modelcontextprotocol/inspector

Visual testing and debugging tool for MCP servers.

**Repository**: https://github.com/modelcontextprotocol/inspector
**Documentation**: https://modelcontextprotocol.io/docs/tools/inspector

#### Installation

No installation required - run directly with npx:

```bash
npx @modelcontextprotocol/inspector
```

#### Running Against Your Server

```bash
# For a server built at build/index.js
npx @modelcontextprotocol/inspector node build/index.js

# For other server types
npx @modelcontextprotocol/inspector <command-to-run-your-server>
```

#### Features

The Inspector consists of two components:

1. **MCP Inspector Client (MCPI)** - React-based web UI (default port 6274)
2. **MCP Proxy (MCPP)** - Node.js server acting as protocol bridge (default port 6277)

#### Accessing the Inspector

Once started, the UI is accessible at:
```
http://localhost:6274
```

#### Testing Capabilities

**Tools Panel**:
- Lists all tools exposed by your server
- Select a tool and fill in input parameters
- Uses form generated from JSON schema
- Click "Call" to see exact JSON response

**Resources Panel**:
- Test resource endpoints
- View resource metadata and content

**Prompts Panel**:
- Test prompt templates
- View prompt generation

#### Configuration

The inspector supports configuration files for multiple servers:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["build/index.js"],
      "transport": "stdio"
    }
  }
}
```

Supported transport types: `stdio`, `streamable-http`, and others.

#### CI/CD Integration

The MCP Inspector is primarily an interactive development tool and is not typically integrated into automated CI/CD pipelines. For automated testing, use the conformance test suite instead.

### 1.3 Go-Native MCP Test Clients

#### Official Go SDK

**Repository**: https://github.com/modelcontextprotocol/go-sdk
**Package**: `github.com/modelcontextprotocol/go-sdk/mcp`
**Documentation**: https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp

The official Go SDK maintained by the Model Context Protocol organization in collaboration with Google.

#### Installation

```bash
go get github.com/modelcontextprotocol/go-sdk/mcp
```

#### Basic Test Client Example

```go
package main

import (
    "context"
    "os/exec"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPServer(t *testing.T) {
    // Create a client
    cmd := exec.Command("path/to/your/mcp-server")
    transport := mcp.CommandTransport(cmd)

    client, err := mcp.NewClient(transport)
    if err != nil {
        t.Fatalf("Failed to create client: %v", err)
    }
    defer client.Close()

    ctx := context.Background()

    // Initialize session
    session, err := client.Initialize(ctx, &mcp.InitializeRequest{
        ProtocolVersion: "1.0",
        ClientInfo: mcp.ClientInfo{
            Name:    "test-client",
            Version: "1.0.0",
        },
    })
    if err != nil {
        t.Fatalf("Failed to initialize: %v", err)
    }

    // Call a tool
    result, err := session.CallTool(ctx, &mcp.CallToolRequest{
        Name: "test-tool",
        Arguments: map[string]interface{}{
            "param": "value",
        },
    })
    if err != nil {
        t.Fatalf("Failed to call tool: %v", err)
    }

    // Validate result
    // ... your test assertions
}
```

#### Features

- Client creation and connection via stdin/stdout
- Automatic input/output schema generation
- Automatic input validation
- Type-safe APIs for constructing MCP clients and servers

#### Community Go Libraries

**mark3labs/mcp-go**: https://github.com/mark3labs/mcp-go
- Popular community implementation
- Seamless integration between LLM applications and external data sources

**Convict3d/mcp-go**: https://pkg.go.dev/github.com/Convict3d/mcp-go
- Professional Go client library
- Clean, type-safe implementation

#### CI/CD Integration

Go test clients can be easily integrated into CI/CD:

```bash
# In your CI pipeline
go test ./tests/mcp -v

# Or with coverage
go test -cover ./tests/mcp
```

## 2. OAuth 2.1 Provider Testing

### 2.1 OAuth 2.1 Conformance Testing

**Status**: OAuth 2.1 is currently in draft (expires April 23, 2026)
**Specification**: https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/

#### Key OAuth 2.1 Requirements

- Mandates Authorization Code + PKCE flow
- Removes implicit flow
- Removes Resource Owner Password Credentials (ROPC) flow
- Tightens redirect handling
- Hardens token usage

#### OpenID Foundation Conformance Suite

While there isn't a dedicated OAuth 2.1 conformance suite yet, the OpenID Foundation provides conformance testing for OAuth 2.0 and related profiles.

**Official Suite**: https://openid.net/certification/about-conformance-suite/
**GitLab Repository**: https://gitlab.com/openid/conformance-suite

##### Installation

The conformance suite can be run locally inside Docker:

```bash
# Clone the repository
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite

# Build and run with Docker
docker-compose up
```

##### Running Tests

Access the suite at `https://localhost:8443` (or deployed at `https://certification.openid.net`)

##### CI/CD Integration

The suite includes a Python script for automation:

```bash
# Automated test execution
python scripts/run-test-plan.py \
    --plan-name oidcc-basic-certification-test-plan \
    --config-file .gitlab-ci/local-provider-oidcc-conformance-config.json
```

**Configuration Example**:
```json
{
  "alias": "my-oauth-provider",
  "server": {
    "discoveryUrl": "https://your-server.com/.well-known/oauth-authorization-server"
  },
  "client": {
    "client_id": "test-client",
    "client_secret": "test-secret"
  }
}
```

##### GitHub Actions Integration Example

```yaml
name: OAuth Conformance Tests

on: [push, pull_request]

jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Start OAuth Server
        run: |
          # Start your OAuth server
          ./start-oauth-server.sh

      - name: Run Conformance Tests
        run: |
          docker run --network=host \
            -v $(pwd)/config.json:/config.json \
            openid/conformance-suite \
            python /conformance-suite/scripts/run-test-plan.py \
              --config-file /config.json \
              --plan-name oauth2-test-plan
```

##### Expected Output

- Test results with pass/fail status
- Detailed logs for each test
- JSON reports for automated processing
- Certification artifacts (if seeking formal certification)

##### CI/CD Benefits

- **Automated validation**: Run tests on every commit
- **Early detection**: Catch OAuth implementation issues early
- **No cost for testing**: Free to use for development
- **Certification path**: Same tests used for official OpenID certification

### 2.2 PKCE Testing Tools

PKCE (Proof Key for Code Exchange) is mandatory in OAuth 2.1.

#### Online PKCE Generator

**URL**: https://tonyxu-io.github.io/pkce-generator/
**URL**: https://example-app.com/pkce

**Features**:
- Generate code verifier
- Generate code challenge (S256 or plain)
- No installation required

#### OAuth 2.0 Playground

**URL**: https://www.oauth.com/playground/authorization-code-with-pkce.html

**Features**:
- Interactive PKCE flow testing
- Step-by-step visualization
- Real-time validation

#### Command-Line Testing

```bash
# Generate code verifier (43-128 characters)
CODE_VERIFIER=$(openssl rand -base64 64 | tr -d '\n' | tr -d '=' | tr '+/' '-_' | cut -c1-128)

# Generate code challenge (SHA256 hash, base64url encoded)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr -d '\n' | tr -d '=' | tr '+/' '-_')

echo "Code Verifier: $CODE_VERIFIER"
echo "Code Challenge: $CODE_CHALLENGE"
```

#### PKCE Library Testing (Ruby)

**Repository**: https://github.com/bkuhlmann/pkce

```bash
gem install pkce
```

```ruby
require 'pkce'

# Generate PKCE pair
pkce = PKCE.generate
puts "Verifier: #{pkce.verifier}"
puts "Challenge: #{pkce.challenge}"
```

#### Testing Your OAuth Server

Manual PKCE flow testing:

```bash
# 1. Generate PKCE pair
CODE_VERIFIER="your-generated-verifier"
CODE_CHALLENGE="your-generated-challenge"

# 2. Authorization request
curl "https://your-oauth-server.com/authorize?\
client_id=YOUR_CLIENT_ID&\
redirect_uri=https://your-app.com/callback&\
response_type=code&\
scope=openid profile&\
code_challenge=$CODE_CHALLENGE&\
code_challenge_method=S256"

# 3. Token request (after receiving authorization code)
curl -X POST https://your-oauth-server.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=https://your-app.com/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "code_verifier=$CODE_VERIFIER"
```

#### Server-Side Validation Requirements

Your OAuth server must:
1. Verify `code_challenge` parameter is present in authorization request
2. Store the `code_challenge` with the authorization code
3. Verify `code_verifier` during token exchange
4. Validate that `SHA256(code_verifier)` matches stored `code_challenge`
5. Support `S256` method (required in OAuth 2.1)

#### CI/CD Integration

```python
# Example Python test
import hashlib
import base64
import secrets

def test_pkce_validation():
    # Generate PKCE pair
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')

    # Test authorization endpoint
    auth_response = requests.get(
        'https://your-server.com/authorize',
        params={
            'client_id': 'test-client',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'response_type': 'code',
            'redirect_uri': 'http://localhost/callback'
        }
    )

    # Extract authorization code
    code = extract_code_from_redirect(auth_response)

    # Test token endpoint
    token_response = requests.post(
        'https://your-server.com/token',
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'code_verifier': code_verifier,
            'client_id': 'test-client',
            'redirect_uri': 'http://localhost/callback'
        }
    )

    assert token_response.status_code == 200
    assert 'access_token' in token_response.json()
```

#### Expected Security Validations

Your tests should verify:
- Server rejects requests without `code_challenge`
- Server rejects invalid `code_verifier`
- Server rejects replay attacks (code used twice)
- Server enforces `S256` method
- Server validates code_challenge length (43-128 chars)

### 2.3 Dynamic Client Registration (DCR) Testing

DCR allows OAuth clients to register dynamically instead of manual pre-registration.

**Specification**: RFC 7591 - https://datatracker.ietf.org/doc/html/rfc7591

#### Testing Approach

DCR is not widely implemented by major providers (Google, GitHub, Microsoft Entra ID), so testing typically requires self-hosted solutions.

#### Manual DCR Testing

```bash
# Basic registration request
curl -X POST https://your-oauth-server.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://client.example.com/callback"],
    "client_name": "Test Client",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic"
  }'

# Expected response
{
  "client_id": "generated-client-id",
  "client_secret": "generated-client-secret",
  "client_id_issued_at": 1234567890,
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://client.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

#### Protected DCR with Initial Access Token

```bash
# Registration with authentication
curl -X POST https://your-oauth-server.com/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <INITIAL_ACCESS_TOKEN>" \
  -d '{
    "redirect_uris": ["https://client.example.com/callback"],
    "client_name": "Protected Test Client"
  }'
```

#### DCR with Software Statement Assertion (SSA)

```bash
# Registration with JWT SSA
curl -X POST https://your-oauth-server.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://client.example.com/callback"],
    "software_statement": "eyJhbGciOiJSUzI1NiJ9.eyJ...signed-jwt"
  }'
```

#### Testing Platforms

**Curity Identity Server**:
- Provides DCR testing capabilities
- GraphQL API to list DCR-registered clients
- Supports open (unauthenticated) and protected modes

**Logto**:
- Supports DCR with RFC 7591 compliance
- Provides testing environments

**Tailscale + tsidp**:
- Integrates DCR with existing IdP
- Useful for hybrid testing scenarios

#### CI/CD Testing Example

```javascript
// Node.js DCR test
const axios = require('axios');

async function testDCR() {
    // Register a client
    const registrationResponse = await axios.post(
        'https://your-oauth-server.com/register',
        {
            redirect_uris: ['http://localhost:3000/callback'],
            client_name: 'CI Test Client',
            grant_types: ['authorization_code'],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_post'
        },
        {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${process.env.INITIAL_ACCESS_TOKEN}`
            }
        }
    );

    console.log('Registered client:', registrationResponse.data.client_id);

    // Use the dynamically registered client
    const { client_id, client_secret } = registrationResponse.data;

    // Test authorization flow with new client
    // ...

    // Clean up: Delete the client
    if (registrationResponse.data.registration_access_token) {
        await axios.delete(
            `https://your-oauth-server.com/register/${client_id}`,
            {
                headers: {
                    'Authorization': `Bearer ${registrationResponse.data.registration_access_token}`
                }
            }
        );
    }
}
```

#### Expected DCR Features to Test

1. **Registration Endpoint**:
   - Accepts valid registration requests
   - Returns client credentials
   - Validates redirect_uris

2. **Client Management**:
   - Read client configuration
   - Update client metadata
   - Delete client registration

3. **Authentication Methods**:
   - Open registration (testing only)
   - Initial access token
   - Software Statement Assertion (SSA)

4. **Security Validations**:
   - Validates JWT signatures in SSA
   - Enforces redirect_uri constraints
   - Validates grant_types and response_types

#### CI/CD Integration Benefits

- **Ephemeral credentials**: Create test clients on-demand
- **Isolation**: Each test run uses fresh credentials
- **Security**: Automatic cleanup after tests
- **Scalability**: No manual client pre-registration

### 2.4 JWT Token Validation Testing

#### Browser-Based JWT Debuggers

**JWT.io** - https://www.jwt.io/
- Decode and verify JWTs
- Validate signatures
- Based on RFC 7519
- All operations happen in browser

**JWT.is** - https://jwt.is/
- Next-generation JWT debugging
- Quick understanding of header, claims, signature

**Token.dev** - https://token.dev/
- JWT decoder with browser-only verification

#### Command-Line Tools

**jwt_tool** - https://github.com/ticarpi/jwt_tool

```bash
# Installation
pip install pyjwt cryptography

# Clone jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool

# Validate a JWT
python jwt_tool.py <JWT_TOKEN>

# Verify signature with public key
python jwt_tool.py <JWT_TOKEN> -V -pk public_key.pem

# Scan for vulnerabilities
python jwt_tool.py <JWT_TOKEN> -M at
```

#### JWT Validation in Go

```go
package main

import (
    "fmt"
    "github.com/golang-jwt/jwt/v5"
)

func validateJWT(tokenString string, publicKey interface{}) error {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Verify signing method
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return publicKey, nil
    })

    if err != nil {
        return fmt.Errorf("token validation failed: %w", err)
    }

    if !token.Valid {
        return fmt.Errorf("token is invalid")
    }

    // Access claims
    if claims, ok := token.Claims.(jwt.MapClaims); ok {
        // Validate standard claims
        if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
            return fmt.Errorf("token expired")
        }

        if !claims.VerifyIssuer("https://your-oauth-server.com", true) {
            return fmt.Errorf("invalid issuer")
        }

        if !claims.VerifyAudience("your-api", true) {
            return fmt.Errorf("invalid audience")
        }
    }

    return nil
}
```

#### JWT Validation Best Practices

According to RFC 8725 (JWT Best Current Practices):

1. **Verify the signature** using the correct algorithm
2. **Validate standard claims**:
   - `exp` (expiration time)
   - `iss` (issuer)
   - `aud` (audience)
   - `nbf` (not before)
3. **Reject unknown algorithms**
4. **Use explicit algorithm verification** (prevent algorithm confusion attacks)
5. **Validate token binding** (if applicable)

#### Testing JWT Validation in Your Server

```bash
# Generate test JWT with jwks-rsa
npm install -g jsonwebtoken

# Create a test token
node -e "
const jwt = require('jsonwebtoken');
const privateKey = require('fs').readFileSync('private.pem');
const token = jwt.sign(
    {
        sub: 'test-user',
        aud: 'your-api',
        iss: 'https://your-oauth-server.com',
        exp: Math.floor(Date.now() / 1000) + 3600
    },
    privateKey,
    { algorithm: 'RS256', keyid: 'key-1' }
);
console.log(token);
"

# Test your API with the token
curl -H "Authorization: Bearer <TOKEN>" https://your-api.com/protected-endpoint
```

#### CI/CD Integration

```python
# pytest example
import jwt
import requests
import time

def test_jwt_validation():
    # Your server's public key
    public_key = """-----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----"""

    # Get token from OAuth server
    token_response = requests.post(
        'https://your-oauth-server.com/token',
        data={
            'grant_type': 'client_credentials',
            'client_id': 'test-client',
            'client_secret': 'test-secret',
            'scope': 'api'
        }
    )

    access_token = token_response.json()['access_token']

    # Decode and verify
    decoded = jwt.decode(
        access_token,
        public_key,
        algorithms=['RS256'],
        audience='your-api',
        issuer='https://your-oauth-server.com'
    )

    # Validate claims
    assert decoded['iss'] == 'https://your-oauth-server.com'
    assert decoded['aud'] == 'your-api'
    assert decoded['exp'] > time.time()

    # Test with API
    api_response = requests.get(
        'https://your-api.com/protected',
        headers={'Authorization': f'Bearer {access_token}'}
    )

    assert api_response.status_code == 200
```

#### Security Testing Scenarios

Test your JWT validation against:

1. **Expired tokens**: Verify rejection of expired JWTs
2. **Invalid signatures**: Test with modified tokens
3. **Algorithm confusion**: Test with different algorithms
4. **Missing claims**: Test with incomplete tokens
5. **Wrong issuer**: Test with tokens from unauthorized issuers
6. **Wrong audience**: Test with tokens for different audiences

#### Expected Output

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-1"
  },
  "payload": {
    "iss": "https://your-oauth-server.com",
    "sub": "user-123",
    "aud": "your-api",
    "exp": 1234567890,
    "iat": 1234564290,
    "scope": "read write"
  },
  "signature": "valid"
}
```

## 3. OIDC Testing (OpenID Connect)

### 3.1 OIDC Conformance Test Suite

**Official Suite**: https://openid.net/certification/about-conformance-suite/
**GitLab Repository**: https://gitlab.com/openid/conformance-suite
**Production Instance**: https://certification.openid.net

#### Features

- Free and open source
- Tests OpenID Connect Core 1.0
- Tests FAPI (Financial-grade API)
- Tests OAuth 2.0 profiles
- Can be run locally or via OpenID Foundation servers
- API for CI/CD integration

#### Installation

##### Docker Installation

```bash
# Clone repository
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite

# Build and run
docker-compose up
```

Access at: `https://localhost:8443`

##### Local Build

```bash
# Requirements: Java 11+, Maven, MongoDB
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite

# Build
mvn clean package

# Run
java -jar target/conformance-suite.jar
```

#### Running Tests

##### Interactive Testing

1. Navigate to https://localhost:8443 or https://certification.openid.net
2. Select test plan (e.g., "OpenID Connect Core: Basic Certification")
3. Configure your OpenID Provider details:
   - Discovery URL
   - Client credentials
   - Redirect URIs
4. Run test suite
5. Review results

##### Automated Testing (CI/CD)

```bash
# Using the run-test-plan.py script
python scripts/run-test-plan.py \
    --plan-name oidcc-basic-certification-test-plan \
    --config-file config.json \
    --output-dir results/ \
    --expected-failures-file expected-failures.json
```

**Configuration File Example** (`config.json`):

```json
{
  "alias": "my-oidc-provider",
  "description": "Testing My OIDC Provider",
  "server": {
    "discoveryUrl": "https://your-oidc-provider.com/.well-known/openid-configuration"
  },
  "client": {
    "client_id": "test-client-id",
    "client_secret": "test-client-secret",
    "redirect_uri": "https://localhost:8443/test/a/your-test-id/callback"
  },
  "browser": [
    {
      "match": "https://your-oidc-provider.com/authorize*",
      "tasks": [
        {
          "task": "Wait for title",
          "text": "Sign In"
        },
        {
          "task": "Type text",
          "selector": "input[name=username]",
          "text": "testuser"
        },
        {
          "task": "Type text",
          "selector": "input[name=password]",
          "text": "testpass"
        },
        {
          "task": "Click on",
          "selector": "button[type=submit]"
        }
      ]
    }
  ]
}
```

#### CI/CD Integration

##### GitLab CI Example

```yaml
# .gitlab-ci.yml
oidc-conformance:
  stage: test
  image: openid/conformance-suite:latest
  services:
    - name: mongo:4.4
      alias: mongodb
  script:
    - python /conformance-suite/scripts/run-test-plan.py
        --plan-name oidcc-basic-certification-test-plan
        --config-file .gitlab-ci/oidc-config.json
        --expected-failures-file .gitlab-ci/expected-failures.json
  artifacts:
    reports:
      junit: results/test-results.xml
    paths:
      - results/
    when: always
```

##### GitHub Actions Example

```yaml
# .github/workflows/oidc-conformance.yml
name: OIDC Conformance Tests

on: [push, pull_request]

jobs:
  conformance:
    runs-on: ubuntu-latest

    services:
      mongodb:
        image: mongo:4.4
        ports:
          - 27017:27017

    steps:
      - uses: actions/checkout@v3

      - name: Start OIDC Provider
        run: |
          ./scripts/start-oidc-provider.sh
          sleep 10

      - name: Run Conformance Tests
        run: |
          docker run --network=host \
            -v $(pwd)/oidc-config.json:/config.json \
            -v $(pwd)/results:/results \
            openid/conformance-suite \
            python /conformance-suite/scripts/run-test-plan.py \
              --config-file /config.json \
              --output-dir /results \
              --plan-name oidcc-basic-certification-test-plan

      - name: Upload Results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: conformance-results
          path: results/
```

#### Expected Output

```json
{
  "testPlanId": "oidcc-basic-certification-test-plan",
  "variant": {
    "client_registration": "static_client",
    "response_type": "code",
    "response_mode": "default"
  },
  "testModules": [
    {
      "testId": "oidcc-server-test",
      "testName": "OpenID Connect Core: Server Test",
      "result": "PASSED",
      "duration": 1234
    },
    {
      "testId": "oidcc-client-test-invalid-iss",
      "testName": "Test client validation of issuer",
      "result": "PASSED",
      "duration": 567
    }
  ],
  "summary": {
    "total": 45,
    "passed": 44,
    "failed": 1,
    "warnings": 2,
    "skipped": 0
  }
}
```

#### Test Plans Available

- **OpenID Connect Core**: Basic and advanced RP/OP tests
- **FAPI 1.0**: Financial-grade API tests
- **FAPI 2.0**: Next-generation financial API
- **CIBA**: Client Initiated Backchannel Authentication
- **OpenID4VP/OpenID4VCI**: Verifiable Credentials (launching Feb 26, 2026)

#### Certification Process

1. **Development Testing**: Use free suite locally
2. **Self-Certification**: Run tests via certification.openid.net
3. **Submit Results**: For official certification (fee required)
4. **Accreditation**: Optional accreditation services (Q2 2026)

### 3.2 ID Token Validation Testing

#### Manual ID Token Validation

ID tokens are JWTs with specific OIDC claims.

**Required Claims**:
- `iss` - Issuer identifier
- `sub` - Subject (user) identifier
- `aud` - Audience (your client_id)
- `exp` - Expiration time
- `iat` - Issued at time

**Additional Claims**:
- `nonce` - Replay protection
- `auth_time` - When user authenticated
- `acr` - Authentication Context Class Reference
- `amr` - Authentication Methods References

#### ID Token Validation Example (Go)

```go
package main

import (
    "context"
    "fmt"
    "github.com/coreos/go-oidc/v3/oidc"
)

func validateIDToken(ctx context.Context, rawToken string) error {
    // Create OIDC provider
    provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
    if err != nil {
        return fmt.Errorf("failed to create provider: %w", err)
    }

    // Configure verifier
    verifier := provider.Verifier(&oidc.Config{
        ClientID: "your-client-id.apps.googleusercontent.com",
        // Optional: require specific claims
        SkipClientIDCheck: false,
        SkipExpiryCheck: false,
        SkipIssuerCheck: false,
    })

    // Verify ID token
    idToken, err := verifier.Verify(ctx, rawToken)
    if err != nil {
        return fmt.Errorf("failed to verify ID token: %w", err)
    }

    // Extract claims
    var claims struct {
        Email         string `json:"email"`
        EmailVerified bool   `json:"email_verified"`
        Name          string `json:"name"`
        Picture       string `json:"picture"`
    }

    if err := idToken.Claims(&claims); err != nil {
        return fmt.Errorf("failed to parse claims: %w", err)
    }

    fmt.Printf("User: %s (%s)\n", claims.Name, claims.Email)
    return nil
}
```

#### Testing ID Token Validation

```bash
# Get an ID token from your OIDC provider
curl -X POST https://your-oidc-provider.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "redirect_uri=YOUR_REDIRECT_URI"

# Response contains id_token
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGc..."
}

# Decode and verify the ID token
# Use jwt.io or jwt_tool to inspect
```

#### ID Token Validation Checklist

Test that your validation:

1. **Verifies signature** using provider's public keys
2. **Validates issuer** (`iss` claim matches expected issuer)
3. **Validates audience** (`aud` claim contains your client_id)
4. **Checks expiration** (`exp` claim is in the future)
5. **Validates issued-at** (`iat` claim is reasonable)
6. **Checks nonce** (if provided in auth request)
7. **Validates authorized party** (`azp` claim if multiple audiences)

#### CI/CD Testing Example

```python
# pytest example
import jwt
import requests
from jwt import PyJWKClient

def test_google_id_token_validation():
    # Simulate getting an ID token
    # In real tests, use mock or test credentials
    id_token = get_test_id_token()

    # Get Google's public keys
    jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
    jwks_client = PyJWKClient(jwks_url)

    # Get signing key
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    # Verify and decode
    decoded = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience="your-client-id.apps.googleusercontent.com",
        issuer="https://accounts.google.com"
    )

    # Validate claims
    assert decoded["iss"] in ["https://accounts.google.com", "accounts.google.com"]
    assert decoded["aud"] == "your-client-id.apps.googleusercontent.com"
    assert "email" in decoded
    assert "sub" in decoded

    print(f"ID token valid for user: {decoded['email']}")
```

### 3.3 Mock OIDC Providers

Mock OIDC providers allow testing without depending on real identity providers.

#### mockoidc (Go)

**Repository**: https://github.com/oauth2-proxy/mockoidc
**Documentation**: https://pkg.go.dev/github.com/oauth2-proxy/mockoidc

##### Installation

```bash
go get github.com/oauth2-proxy/mockoidc
```

##### Basic Usage

```go
package main

import (
    "testing"
    "github.com/oauth2-proxy/mockoidc"
    "github.com/stretchr/testify/assert"
)

func TestOIDCIntegration(t *testing.T) {
    // Start mock OIDC server
    m, err := mockoidc.Run()
    assert.NoError(t, err)
    defer m.Shutdown()

    // Mock server provides discovery endpoint
    discoveryURL := m.Issuer()
    fmt.Println("Discovery URL:", discoveryURL)

    // Create a custom user
    user := &mockoidc.User{
        Subject:           "test-user-123",
        Email:             "test@example.com",
        EmailVerified:     true,
        PreferredUsername: "testuser",
        Name:              "Test User",
    }

    // Queue the user for next login
    code := m.QueueUser(user)

    // Now test your OIDC client against m.Issuer()
    // Your client will receive tokens for the queued user

    // Access standard OIDC endpoints:
    // - m.DiscoveryEndpoint() -> /.well-known/openid-configuration
    // - m.AuthorizationEndpoint() -> /authorize
    // - m.TokenEndpoint() -> /token
    // - m.UserinfoEndpoint() -> /userinfo
    // - m.JWKSEndpoint() -> /jwks
}

func TestTokenExpiration(t *testing.T) {
    m, _ := mockoidc.Run()
    defer m.Shutdown()

    // Get token
    token := getTokenFromMock(m)

    // Fast forward time to test expiration
    m.FastForward(time.Hour * 2)

    // Token should now be expired
    assert.False(t, isTokenValid(token))
}
```

##### Features

- **Automatic user sessions**: Default user automatically logged in
- **Custom users**: Queue specific users for testing
- **Time manipulation**: Fast-forward to test expirations
- **Standard endpoints**: Full OIDC discovery and token endpoints
- **Local testing**: Runs on localhost with random port

##### CI/CD Integration

```go
// integration_test.go
func TestYourOIDCClient(t *testing.T) {
    m, err := mockoidc.Run()
    require.NoError(t, err)
    defer m.Shutdown()

    // Configure your OIDC client to use mock
    client := &OIDCClient{
        Issuer:       m.Issuer(),
        ClientID:     m.ClientID,
        ClientSecret: m.ClientSecret,
    }

    // Test login flow
    token, err := client.Authenticate("testuser", "password")
    require.NoError(t, err)

    // Verify token
    claims, err := client.ValidateToken(token)
    require.NoError(t, err)
    assert.Equal(t, mockoidc.DefaultUser().Email, claims.Email)
}
```

#### oauth2-mock-server (Node.js)

**Repository**: https://github.com/axa-group/oauth2-mock-server
**npm**: https://www.npmjs.com/package/oauth2-mock-server

##### Installation

```bash
npm install --save-dev oauth2-mock-server
```

##### Basic Usage

```javascript
const { OAuth2Server } = require('oauth2-mock-server');

async function setupMockOIDC() {
    const server = new OAuth2Server();

    // Generate RSA key
    await server.issuer.keys.generate('RS256');

    // Start server
    await server.start(8080, 'localhost');

    console.log('Issuer URL:', server.issuer.url);
    console.log('Discovery:', `${server.issuer.url}/.well-known/openid-configuration`);

    // Customize token claims
    server.service.once('beforeTokenSigning', (token, req) => {
        token.payload.sub = 'test-user-123';
        token.payload.email = 'test@example.com';
        token.payload.email_verified = true;
        token.payload.name = 'Test User';
    });

    return server;
}

// In tests
describe('OIDC Integration', () => {
    let mockOIDC;

    beforeAll(async () => {
        mockOIDC = await setupMockOIDC();
    });

    afterAll(async () => {
        await mockOIDC.stop();
    });

    test('should authenticate user', async () => {
        const client = new OIDCClient({
            issuer: mockOIDC.issuer.url,
            clientId: 'test-client',
            clientSecret: 'test-secret'
        });

        // Test authentication flow
        const token = await client.getToken('authorization_code', {
            code: 'test-code',
            redirectUri: 'http://localhost/callback'
        });

        expect(token.id_token).toBeDefined();

        // Decode and verify ID token
        const decoded = jwt.decode(token.id_token);
        expect(decoded.email).toBe('test@example.com');
    });
});
```

##### Features

- **Easy setup**: Few lines to start
- **Customizable tokens**: Modify claims via event emitters
- **OIDC compliant**: Standard endpoints and discovery
- **Test-friendly**: Start/stop per test
- **Event hooks**: Intercept token generation

##### CI/CD Integration

```javascript
// jest.config.js
module.exports = {
    globalSetup: './test/setup-mock-oidc.js',
    globalTeardown: './test/teardown-mock-oidc.js'
};

// test/setup-mock-oidc.js
const { OAuth2Server } = require('oauth2-mock-server');

module.exports = async () => {
    const server = new OAuth2Server();
    await server.issuer.keys.generate('RS256');
    await server.start(8080, 'localhost');

    global.__MOCK_OIDC__ = server;
    process.env.OIDC_ISSUER = server.issuer.url;
};

// test/teardown-mock-oidc.js
module.exports = async () => {
    await global.__MOCK_OIDC__.stop();
};
```

#### oidc-provider-mock (Python)

**PyPI**: https://pypi.org/project/oidc-provider-mock/

##### Installation

```bash
pip install oidc-provider-mock
```

##### Basic Usage

```python
import pytest
from oidc_provider_mock import OIDCProviderMock

@pytest.fixture
def oidc_provider():
    """Fixture to provide mock OIDC server."""
    with OIDCProviderMock() as mock:
        # Configure users
        mock.add_user(
            sub="test-user-123",
            email="test@example.com",
            email_verified=True,
            name="Test User"
        )

        yield mock

def test_oidc_login(oidc_provider):
    """Test OIDC login flow."""
    client = OIDCClient(
        issuer=oidc_provider.issuer,
        client_id="test-client",
        client_secret="test-secret"
    )

    # Simulate authorization
    auth_url = client.get_authorization_url()

    # Mock provider returns success
    code = oidc_provider.authorize(auth_url)

    # Exchange code for tokens
    tokens = client.get_tokens(code)

    assert tokens["id_token"]
    assert tokens["access_token"]
```

##### Features

- **pytest integration**: Works as pytest fixture
- **Thread-based**: Runs in background thread
- **User management**: Add users with custom claims
- **Flask-based**: Lightweight Python server

#### @bluecateng/mock-oidc-provider (Node.js)

**npm**: https://www.npmjs.com/package/@bluecateng/mock-oidc-provider

##### Installation

```bash
npm install --save-dev @bluecateng/mock-oidc-provider
```

##### Basic Usage

```javascript
const { MockOIDCProvider } = require('@bluecateng/mock-oidc-provider');

const mockProvider = new MockOIDCProvider({
    issuer: 'http://localhost:9000',
    clients: [{
        client_id: 'test-client',
        client_secret: 'test-secret',
        redirect_uris: ['http://localhost:3000/callback']
    }]
});

await mockProvider.start(9000);

// Use in tests
// mockProvider.issuer -> http://localhost:9000
// mockProvider.getDiscoveryUrl() -> /.well-known/openid-configuration

await mockProvider.stop();
```

#### Google Cloud Mock OIDC Provider

**Article**: https://alphasec.io/secure-federated-access-to-google-cloud-building-a-mock-oidc-identity-provider/

For testing Google Sign-In specifically, you can build a lightweight Flask-based mock that:
- Issues signed ID tokens mimicking Google's format
- Provides Google-compatible claims
- Supports testing without real Google credentials

```python
from flask import Flask, jsonify
import jwt
import time

app = Flask(__name__)

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
...your test key...
-----END RSA PRIVATE KEY-----"""

@app.route('/.well-known/openid-configuration')
def discovery():
    return jsonify({
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "http://localhost:5000/authorize",
        "token_endpoint": "http://localhost:5000/token",
        "userinfo_endpoint": "http://localhost:5000/userinfo",
        "jwks_uri": "http://localhost:5000/jwks"
    })

@app.route('/token', methods=['POST'])
def token():
    # Generate mock ID token
    id_token = jwt.encode(
        {
            "iss": "https://accounts.google.com",
            "sub": "123456789",
            "aud": "your-client-id.apps.googleusercontent.com",
            "email": "test@example.com",
            "email_verified": True,
            "name": "Test User",
            "picture": "https://example.com/photo.jpg",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        },
        PRIVATE_KEY,
        algorithm='RS256',
        headers={"kid": "test-key-id"}
    )

    return jsonify({
        "access_token": "mock-access-token",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600
    })

if __name__ == '__main__':
    app.run(port=5000)
```

### 3.4 Comparison of Mock OIDC Providers

| Feature | mockoidc (Go) | oauth2-mock-server (Node.js) | oidc-provider-mock (Python) |
|---------|---------------|------------------------------|----------------------------|
| **Language** | Go | Node.js | Python |
| **Installation** | go get | npm install | pip install |
| **Ease of Use** | Very Easy | Easy | Easy |
| **Custom Users** | Yes | Yes | Yes |
| **Time Travel** | Yes | No | No |
| **Event Hooks** | No | Yes | Limited |
| **pytest Integration** | N/A | N/A | Yes |
| **CI/CD Ready** | Yes | Yes | Yes |
| **Random Port** | Yes | Manual | Manual |
| **Thread/Goroutine** | Goroutine | Process | Thread |
| **Best For** | Go projects | Node.js projects | Python/pytest |

## Summary: CI/CD Integration Guide

### Quick Setup for CI/CD

#### MCP Testing
```bash
# Add to CI pipeline
npx @modelcontextprotocol/conformance server --url http://localhost:3000/mcp
```

#### OAuth 2.1 / OIDC Testing
```bash
# Clone and run conformance suite
git clone https://gitlab.com/openid/conformance-suite.git
docker-compose up -d
python scripts/run-test-plan.py --config-file ci-config.json
```

#### JWT Validation Testing
```bash
# Use jwt_tool in CI
pip install pyjwt cryptography
python jwt_tool.py $TEST_TOKEN -V -pk public_key.pem
```

#### Mock OIDC Testing
```go
// Go projects
m, _ := mockoidc.Run()
defer m.Shutdown()
// Run tests against m.Issuer()
```

```javascript
// Node.js projects
const server = new OAuth2Server();
await server.start(8080, 'localhost');
// Run tests
await server.stop();
```

### Key Benefits

1. **Automated validation**: Catch issues before production
2. **Consistent testing**: Same tests in dev and CI
3. **Fast feedback**: Quick test execution
4. **No manual steps**: Fully automated pipeline
5. **Compliance verification**: Ensure standards conformance

### Recommended Testing Strategy

1. **Unit Tests**: Use mock providers (mockoidc, oauth2-mock-server)
2. **Integration Tests**: Use MCP Inspector and conformance suite locally
3. **CI/CD Tests**: Automated conformance suite with Docker
4. **Pre-Production**: Manual testing with OpenID certification site
5. **Production Monitoring**: JWT validation and logging

## Sources

### MCP Protocol Testing
- [GitHub - modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance)
- [GitHub - modelcontextprotocol/inspector](https://github.com/modelcontextprotocol/inspector)
- [MCP Inspector Documentation](https://modelcontextprotocol.io/docs/tools/inspector)
- [How to use MCP Inspector - Medium](https://medium.com/@laurentkubaski/how-to-use-mcp-inspector-2748cd33faeb)
- [GitHub - modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- [GitHub - mark3labs/mcp-go](https://github.com/mark3labs/mcp-go)
- [Integrating Model Context Protocol with GitHub Actions](https://markaicode.com/model-context-protocol-github-actions-cicd/)

### OAuth 2.1 Testing
- [OAuth 2.1 Draft Specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [OpenID Foundation Conformance Suite](https://openid.net/certification/about-conformance-suite/)
- [GitLab - OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite)
- [Authorization Code Flow with PKCE - Auth0](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce)
- [Online PKCE Generator Tool](https://tonyxu-io.github.io/pkce-generator/)
- [OAuth 2.0 Playground - PKCE Flow](https://www.oauth.com/playground/authorization-code-with-pkce.html)
- [RFC 7636 - PKCE Specification](https://datatracker.ietf.org/doc/html/rfc7636)
- [Dynamic Client Registration Overview - Curity](https://curity.io/resources/learn/openid-connect-understanding-dcr/)
- [RFC 7591 - OAuth 2.0 Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)

### JWT Testing
- [JWT.io](https://www.jwt.io/)
- [JWT.is](https://jwt.is/)
- [Token.dev JWT Debugger](https://token.dev/)
- [GitHub - ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)
- [RFC 8725 - JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [OWASP - Testing JSON Web Tokens](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)

### OIDC Testing
- [OpenID for Verifiable Credential Certification Launch Feb 2026](https://openid.net/openid-for-verifiable-credential-self-certification-to-launch-feb-2026/)
- [GitLab - OpenID Conformance Suite CI/CD](https://gitlab.com/openid/conformance-suite/-/wikis/Continuous-Integration-&-Deployment)
- [GitHub - oauth2-proxy/mockoidc](https://github.com/oauth2-proxy/mockoidc)
- [npm - oauth2-mock-server](https://www.npmjs.com/package/oauth2-mock-server)
- [GitHub - axa-group/oauth2-mock-server](https://github.com/axa-group/oauth2-mock-server)
- [PyPI - oidc-provider-mock](https://pypi.org/project/oidc-provider-mock/)
- [npm - @bluecateng/mock-oidc-provider](https://www.npmjs.com/package/@bluecateng/mock-oidc-provider)
- [Secure Federated Access - Mock OIDC Provider](https://alphasec.io/secure-federated-access-to-google-cloud-building-a-mock-oidc-identity-provider/)
