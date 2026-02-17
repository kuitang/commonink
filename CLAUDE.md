# CRITICAL Principles
- NEVER add `.gitleaksignore`, `.gitleaks.toml`, or otherwise bypass/override gitleaks. If gitleaks flags a false positive, fix the source: use innocuous placeholder strings (e.g., `$COMMON_INK_API_KEY`, `demo-token-here`) instead of patterns that look like real secrets. This applies to documentation, tests, and any committed files.
- Other agents may be working in this directory. Carefully scope your edits. Do NOT use bulk commands like git checkout or git stash that will destroy other agents progress.
- You MUST use Makefile commands (`make build`, `make run-test`, `make test`, etc.) for ALL build/run/test operations. NEVER invoke `go build`, `go test`, or run the server binary directly — the Makefile handles goenv, CGO flags, secrets, and BASE_URL correctly.
- In every task/subagent prompt, You MUST tell them to read the entire CLAUDE.md
- EVERY TASK MUST USE OPUS 4.6.
- Use parallel tasks, back ground tasks, everywhere. Defer implementation and research to them.
- If you find an error in CLAUDE.md or anything out of date with the code, you must fix CLAUDE.md
- NEVER write fallback or backwards compatible code. Always make sure we execute the difficult path.
- Expense, complexity, and token limit are of no object. Simply execute what I tell you to and do not simplify it. (However, use tasks to do the heavy lifting, always as parallel as possible.)
- ALWAYS follow the directives below on property-based testing.
- ALWAYS use gpt-5-mini! NEVER use a gpt-4 series model
- Plan  and milestone files should be terse and only contain new and specific information. Follow the format of spec.md. Do NOT include code in plan files. At best, high level pseudocode.

# Developer Guide - Remote Notes MicroSaaS

Quick reference for Claude and developers working on this project.

## Prerequisites

**Go 1.25+ REQUIRED via goenv** - This project uses goenv for Go version management.

### Go Setup (CRITICAL for Claude agents)
The project has a `.go-version` file that specifies Go 1.25.6. All shell commands must initialize goenv:

```bash
# Add this prefix to ALL go commands in scripts/tasks:
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)"

# Or as a one-liner prefix for any go command:
# $(eval "$(~/.goenv/bin/goenv init -)") && go build ...
```

### CGO Flags (CRITICAL - Required for SQLCipher + FTS5)
**ALL `go build`, `go test`, and `go run` commands MUST use these CGO flags:**

```bash
CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5" CGO_LDFLAGS="-lm"
```

**Complete prefix for ALL Go commands:**
```bash
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)" && CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5" CGO_LDFLAGS="-lm"
```

Without these flags:
- SQLCipher won't compile (CGO_ENABLED=1)
- FTS5 full-text search won't work (CGO_CFLAGS)
- Math functions for FTS5 ranking won't link (CGO_LDFLAGS="-lm")

**Verify correct Go version:**
```bash
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)" && go version
# Should output: go version go1.25.6 linux/arm64
```

**DO NOT use `/usr/bin/go`** - it's an outdated system Go (1.19).

### Secrets Setup (REQUIRED)

All secrets (MASTER_KEY, OAUTH_HMAC_SECRET, OAUTH_SIGNING_KEY, API keys) are **hard-required** -- there is no fallback generation. Secrets are managed in two places:

- **`secrets.sh`** -- Contains ONLY secrets (GOOGLE_CLIENT_SECRET, RESEND_API_KEY, OPENAI_API_KEY, etc.). Gitignored.
- **`Makefile`** -- Contains identifiers/URLs (GOOGLE_CLIENT_ID, BASE_URL, etc.) and deterministic test secrets (MASTER_KEY, OAUTH_HMAC_SECRET, OAUTH_SIGNING_KEY). Make's `export` only propagates to child processes, not the caller.

For local testing, `make test` injects the deterministic test secrets automatically -- no need to source anything.
For production runs (`make run`), the Makefile sources `secrets.sh`:
```bash
cp secrets.sh.example secrets.sh
# Fill in real secret values in secrets.sh
```

## Test Strategy Overview

This project uses **property-based testing** with rapid + Go's native fuzzing. See `notes/testing-strategy.md` for philosophy.

### Test Categories
1. **E2E API Tests** - Property tests via HTTP (roundtrip, idempotence, isolation)
2. **E2E MCP Tests** - MCP protocol compliance
3. **Unit Tests** - Auth/crypto/parsing only (sensitive logic)
4. **Browser Tests** - Playwright for critical UI flows

### **DO NOT** write traditional example-based unit tests except for:
- Bug regressions (add failing input to fuzz corpus)
- Documentation examples

## CI Commands

All CI commands go through `make`. The Makefile handles goenv, CGO flags, and deterministic test secrets automatically.

### Quick Check (~45s) - Run Before Every Commit
```bash
make test
```
- Runs all `Test*` functions (rapid property tests)
- Excludes e2e conformance and browser tests
- No coverage collection
- Fails fast

### Full CI (~5 min) - Run Before PR
```bash
make test-full
```
- All `Test*` functions with coverage (including Claude conformance tests)
- Coverage report generation
- **Requires**: `OPENAI_API_KEY` in environment (for conformance tests)
- **Output**: `test-results/coverage.html`, `test-results/full-test.log`

### Fuzz Testing (30+ min) - Run Nightly or When Changing Security Code
```bash
make test-fuzz
```
- Calls `scripts/fuzz.sh` under the hood
- Coverage-guided fuzzing of all `Fuzz*` functions
- Compares baseline vs fuzz coverage
- **Fails** if new crash inputs found
- **Output**: `test-results/fuzz-findings/` (if issues found)

### Advanced Fuzz Options
The `scripts/fuzz.sh` script accepts options when called directly:
```bash
./scripts/fuzz.sh fuzz --timeout 30m
./scripts/fuzz.sh fuzz --parallel 8
./scripts/fuzz.sh fuzz --output ./my-results
```

## Git Workflow

### Pre-Commit Hook (Automatic)
Git hooks run automatically:
1. `go fmt` all changed files
2. `make test`

If either fails, commit is blocked.

### Manual Hook Install
Already installed automatically. If needed:
```bash
./scripts/setup-hooks.sh
```

## Running Locally

### Build & Run (all mocks, local only)
```bash
make run-test   # builds, runs on :8080 with mock OIDC + S3 + email
```

### Build & Run (all mocks, with Tailscale Funnel for external clients)
```bash
# One-time: set up Tailscale Funnel (stable URL, survives restarts)
sudo tailscale funnel --bg 8080
# Stable URL: https://kui-vibes.tailfaeb4d.ts.net

# Start server with Tailscale BASE_URL
BASE_URL='https://kui-vibes.tailfaeb4d.ts.net' make run-test
```

### Build & Run (real services)
```bash
cp secrets.sh.example secrets.sh  # fill in real values
make run                          # sources secrets.sh, uses real OIDC/S3/email
```

### Notes
- Auth handlers use **form-encoded POST** (not JSON)
- Login/register: `POST /auth/login` or `POST /auth/register` with `email=...&password=...`
- Password: any password accepted in test mode (verification not yet implemented)
- Sessions/OAuth state persist in SQLite (`data/sessions.db`), survive server restarts
- User IDs are deterministic: `user-` + UUID5(DNS, email)

### Manual MCP Testing (OAuth 2.1 full flow)
With server running on :8080:
```bash
# 1. Discovery
curl -s http://localhost:8080/.well-known/oauth-protected-resource
curl -s http://localhost:8080/.well-known/oauth-authorization-server

# 2. DCR
curl -s -X POST http://localhost:8080/oauth/register \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["http://localhost:3000/callback"],"client_name":"Test","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}'
# Returns client_id (public client, no secret)

# 3. Register user + get session cookie
curl -X POST http://localhost:8080/auth/register \
  -d "email=test@example.com&password=TestPassword123!" -c cookies.txt

# 4. Authorize (with PKCE) - renders consent page, sets oauth_auth_req cookie
CODE_VERIFIER=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 -w 0 | tr '+/' '-_' | tr -d '=')
STATE=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
curl -s -b cookies.txt -c auth_cookies.txt \
  "http://localhost:8080/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=http://localhost:3000/callback&response_type=code&scope=notes:read+notes:write&state=${STATE}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256" -o /dev/null

# 5. Submit consent (decision=allow) - redirects with ?code=...
curl -s -D - -o /dev/null -X POST http://localhost:8080/oauth/consent \
  -b auth_cookies.txt -d "decision=allow"
# Extract code from Location header

# 6. Token exchange
curl -s -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code&client_id=${CLIENT_ID}&code=${AUTH_CODE}&redirect_uri=http://localhost:3000/callback&code_verifier=${CODE_VERIFIER}"
# Returns access_token (JWT), refresh_token

# 7. MCP with token
curl -s -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

### MCP Tools Available
`note_create`, `note_view`, `note_list`, `note_update`, `note_delete`, `note_search`

## Writing Tests

### E2E API Property Test Template
```go
// File: tests/e2e/notes_api_test.go

// 1. Property test logic (called by both rapid and fuzz)
func testNotesAPI_CRUD_Properties(t *rapid.T, client *APIClient) {
    // Generate random note
    title := rapid.String().Draw(t, "title")
    content := rapid.String().Draw(t, "content")

    // Property: Create → Read → Compare (roundtrip)
    noteID := client.CreateNote(t, title, content)
    retrieved := client.GetNote(t, noteID)

    if retrieved.Title != title || retrieved.Content != content {
        t.Fatalf("Roundtrip failed: got %+v", retrieved)
    }
}

// 2. Rapid entry point (go test)
func TestNotesAPI_CRUD_Properties(t *testing.T) {
    client := setupTestClient(t)
    rapid.Check(t, func(t *rapid.T) {
        testNotesAPI_CRUD_Properties(t, client)
    })
}

// 3. Fuzz entry point (go test -fuzz)
func FuzzNotesAPI_CRUD_Properties(f *testing.F) {
    client := setupTestClient(f)
    f.Add([]byte{0x00}) // Minimal seed
    f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
        testNotesAPI_CRUD_Properties(t, client)
    }))
}
```

### Sensitive Logic Unit Test Template
```go
// File: internal/auth/token_test.go

func testToken_ExpiryRespected(t *rapid.T) {
    // Generate random token with expiry
    expiresIn := rapid.Int64Range(1, 3600).Draw(t, "expiresIn")
    token := GenerateToken("user123", expiresIn)

    // Property: Token valid before expiry, invalid after
    if !ValidateToken(token) {
        t.Fatal("Token invalid before expiry")
    }

    // Fast-forward time (use testing clock if available)
    time.Sleep(time.Duration(expiresIn+1) * time.Second)

    if ValidateToken(token) {
        t.Fatal("Token still valid after expiry")
    }
}

func TestToken_ExpiryRespected_Properties(t *testing.T) {
    rapid.Check(t, testToken_ExpiryRespected)
}
```

### Playwright Browser Test Guidelines

Browser tests live in `tests/browser/` and are **excluded from `make test`** (run separately).

**Selectors**: Always use specific, fast selectors — IDs, attributes, or roles. Avoid text-only selectors for waits.
```go
// GOOD: specific selectors with short timeouts
page.Locator("#magic-link-dialog").WaitFor(playwright.LocatorWaitForOptions{
    State:   playwright.WaitForSelectorStateVisible,
    Timeout: playwright.Float(5000), // 5s max
})
page.Locator("[role='status']")           // flash message banner
page.Locator("#login-email")              // by ID
page.Locator("input[name='email']")       // by attribute
page.Locator("form[action='/auth/login']") // by form action

// BAD: vague selectors, long timeouts
page.Locator("div.some-class")            // fragile CSS class
page.WaitForTimeout(3000)                 // arbitrary sleep
```

**Wait strategy**: Use `WaitForLoadState(DomContentLoaded)` for navigation, then `WaitFor(Visible, 5s)` on a specific element. Never use `NetworkIdle` unless you need all async requests to finish (e.g., after fetch()).

**Test env**: Use `setupAuthTestEnv(t)` which creates httptest server with all routes (web + auth handlers). See `tests/browser/auth_flow_test.go`.

## Common Commands

### Format Code
```bash
go fmt ./...
```

### Lint
```bash
go vet ./...
```

### Update Dependencies
```bash
go get -u ./...
go mod tidy
```

### Generate Coverage Report (Manual)
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
open coverage.html  # or xdg-open on Linux
```

### Run Specific Test
```bash
go test -v -run TestNotesAPI_CRUD ./tests/e2e
```

### Run Specific Fuzz Test
```bash
go test -fuzz=FuzzNotesAPI_CRUD -fuzztime=1m ./tests/e2e
```

## Debugging Tips

### Enable Verbose Logging
```bash
go test -v ./...
```

### Print Coverage Gaps
```bash
./scripts/coverage-gaps.sh test-results/coverage.out
```

### Compare Coverage (Baseline vs Fuzz)
```bash
./scripts/compare-coverage.sh baseline.out fuzz.out
```

### View Fuzz Corpus
```bash
ls -la testdata/fuzz/FuzzNotesAPI_CRUD/
```

### Reproduce Fuzz Failure
```bash
# Fuzz creates a failing input file
go test -run=FuzzNotesAPI_CRUD/abc123  # Use the specific corpus filename
```

## Project-Specific Notes

### Database Setup (Per-User SQLite)
- Each user gets `/data/{user_id}/notes.db`
- Tests create temp directories: `t.TempDir()`
- Fresh DB per test (fast because SQLite)

### Test Server
- Use `httptest.Server` with real handlers (not subprocess)
- Coverage instrumentation works
- Faster startup than real server

### MCP Transport (Streamable HTTP - MCP Spec 2025-03-26)
- **Streamable HTTP** transport, stateless mode (no initialize handshake)
- Single endpoint `POST /mcp` - protected by OAuth 2.1 Bearer token, API Key, or session cookie
- `JSONResponse: true` - returns `application/json` (not SSE)
- Auth: `Authorization: Bearer <JWT>` or `Authorization: Bearer <API_KEY>`
- 401 response includes `WWW-Authenticate: Bearer resource_metadata="..."` per RFC 6750
- Reference: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports

### Rate Limiting in Tests
- Disable rate limiting in test env
- Or use high limits: `limiter.NewLimiter(1000, 100)`

### Flakiness Budget
- **0% tolerance** for quick and full CI
- Flaky test = broken test (must fix or remove)
- If Playwright flakes, add explicit waits or retry logic

## When to Run Each CI Level

| Level | Command | When | Duration | Purpose |
|-------|---------|------|----------|---------|
| **quick** | `make test` | Before every commit | ~45s | Fast feedback loop |
| **full** | `make test-full` | Before PR, after feature complete | ~5min | Comprehensive validation + coverage |
| **fuzz** | `make test-fuzz` | Nightly, after security changes | 30+ min | Deep edge case discovery |

## Coverage Targets

- **Overall**: ≥70% (configurable in Makefile)
- **Auth/Crypto**: ≥95% (critical paths)
- **MCP Handlers**: ≥85% (core functionality)
- **Web UI**: ≥50% (minimal, mostly Playwright)

## External Resources

- **MCP Conformance**: `notes/testing-tools.md` § MCP Protocol Testing
- **OAuth Testing**: `notes/testing-tools.md` § OAuth 2.1 Provider Testing
- **Library Docs**: `notes/go-libraries-2026.md`
- **Full Spec**: `spec.md`

## Troubleshooting

### "package X is not in GOROOT" or wrong Go version
→ You're using system Go instead of goenv. Prefix commands with:
```bash
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)"
```
→ Verify with `go version` - must show go1.25.6

### "CGO_ENABLED required for SQLCipher"
→ Install gcc: `sudo apt-get install build-essential`
→ Build with: `CGO_ENABLED=1 go build`

### "Coverage below threshold"
→ Run: `./scripts/coverage-gaps.sh test-results/coverage.out`
→ Add tests for uncovered lines or adjust threshold

### "Fuzz test hanging"
→ Reduce fuzz time: `./scripts/fuzz.sh fuzz --timeout 5m`
→ Check for infinite loops in property test

### Playwright "browser not found"
→ Install: `go run github.com/playwright-community/playwright-go/cmd/playwright install chromium`

## Quick Reference

| Task | Command |
|------|---------|
| Build | `make build` |
| Run (real services) | `make run` (requires secrets.sh) |
| Run (all mocks) | `make run-test` (uses `--test` flag) |
| Run (real email only) | `make run-email` (mock OIDC + S3) |
| Run tests | `make test` |
| Full tests + coverage | `make test-full` |
| Fuzz | `make test-fuzz` |
| Format | `make fmt` |
| Lint | `make vet` |
| Clean | `make clean` |
| Deploy | `make deploy` |
| Show targets | `make help` |

---

**Remember**: Property-based tests > Example-based tests. If you're tempted to write a unit test, ask: "Can this be a property instead?"
