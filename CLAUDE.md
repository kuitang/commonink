# CRITICAL Principles
- In every task/subagent prompt, You MUST tell them to read the entire CLAUDE.md
- EVERY TASK MUST USE OPUS 4.5.
- Use parallel tasks, back ground tasks, everywhere. Defer implementation and research to them.
- If you find an error in CLAUDE.md or anything out of date with the code, you must fix CLAUDE.md
- NEVER write fallback or backwards compatible code. Always make sure we execute the difficult path.
- Expense, complexity, and token limit are of no object. Simply execute what I tell you to and do not simplify it. (However, use tasks to do the heavy lifting, always as parallel as possible.)
- ALWAYS follow the directives below on property-based testing.
- ALWAYS use gpt-5-mini! NEVER use a gpt-4 series model

# Developer Guide - Remote Notes MicroSaaS

Quick reference for Claude and developers working on this project.

## Prerequisites

**Go 1.22+ REQUIRED** - Run `go version` to verify. See README.md for installation.

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

### Quick Check (~30s) - Run Before Every Commit
```bash
./scripts/ci.sh quick
```
- Runs all `Test*` functions (rapid property tests)
- No coverage collection
- Fails fast

### Full CI (~5 min) - Run Before PR
```bash
./scripts/ci.sh full
```
- All `Test*` functions with coverage
- Playwright browser tests
- Coverage report generation
- **Requires**: Coverage ≥ 70% (configurable)
- **Output**: `test-results/coverage.html`

### Fuzz Testing (30+ min) - Run Nightly or When Changing Security Code
```bash
./scripts/ci.sh fuzz --timeout 30m
```
- Coverage-guided fuzzing of all `Fuzz*` functions
- Compares baseline vs fuzz coverage
- **Fails** if new crash inputs found
- **Output**: `test-results/fuzz-findings/` (if issues found)

### Options
```bash
--timeout <duration>       # Fuzz duration (default: 30m)
--parallel <n>             # Test workers (default: CPU count)
--output <dir>             # Results dir (default: ./test-results)
--coverage-threshold <n>   # Min coverage % (default: 70)
```

## Git Workflow

### Pre-Commit Hook (Automatic)
Git hooks run automatically:
1. `go fmt` all changed files
2. `./scripts/ci.sh quick`

If either fails, commit is blocked.

**Bypass** (not recommended): `git commit --no-verify`

### Manual Hook Install
Already installed automatically. If needed:
```bash
./scripts/setup-hooks.sh
```

## Building

### Standard Build
```bash
go build -o bin/server ./cmd/server
```

### With SQLCipher (Requires CGO + gcc)
```bash
CGO_ENABLED=1 go build -o bin/server ./cmd/server
```

### Run Smoke Test
```bash
./bin/server
```

### Run Test Server
```bash
START_SERVER=true ./bin/server
```

## Testing External Integrations

### MCP Conformance Tests
```bash
# Run conformance tests (server must be running at localhost:8080)
./scripts/mcp-conformance.sh
```

### OAuth 2.1 Conformance
```bash
# Run automated conformance tests (Docker required)
./scripts/oauth-conformance-test.sh

# Manual testing via OpenID suite (keep suite running)
KEEP_RUNNING=true ./scripts/oauth-conformance-test.sh
# Then open: https://localhost:8443
```

### Mock OIDC Provider (for Google Sign-In tests)
```bash
go get github.com/oauth2-proxy/mockoidc
# See notes/testing-tools.md for usage examples
```

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

### Playwright Browser Test Template
```go
// File: tests/browser/signup_flow_test.go

func TestBrowser_SignupFlow(t *testing.T) {
    // Deterministic scenario (NOT property-based)
    pw, err := playwright.Run()
    if err != nil {
        t.Fatal(err)
    }
    defer pw.Stop()

    browser, _ := pw.Chromium.Launch()
    page, _ := browser.NewPage()

    // Test flow
    page.Goto("http://localhost:8080/login")
    page.Click("button:has-text('Sign in with Google')")
    // ... assertions ...
}
```

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
- **Streamable HTTP** transport only (NOT SSE, NOT WebSocket)
- Single endpoint `/mcp` handles:
  - **POST**: Client sends JSON-RPC messages (requests, notifications, responses)
  - **GET**: Server pushes messages to client (optional SSE stream)
  - **DELETE**: Session termination (optional)
- Session management via `Mcp-Session-Id` header
- Test via HTTP POST to `/mcp` with proper Accept header:
  ```bash
  curl -X POST http://localhost:8080/mcp \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
  ```
- Reference: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports

### Rate Limiting in Tests
- Disable rate limiting in test env
- Or use high limits: `limiter.NewLimiter(1000, 100)`

### Flakiness Budget
- **0% tolerance** for quick and full CI
- Flaky test = broken test (must fix or remove)
- If Playwright flakes, add explicit waits or retry logic

## When to Run Each CI Level

| Level | When | Duration | Purpose |
|-------|------|----------|---------|
| **quick** | Before every commit | ~30s | Fast feedback loop |
| **full** | Before PR, after feature complete | ~5min | Comprehensive validation + coverage |
| **fuzz** | Nightly, after security changes | 30+ min | Deep edge case discovery |

## Coverage Targets

- **Overall**: ≥70% (configurable in ci.sh)
- **Auth/Crypto**: ≥95% (critical paths)
- **MCP Handlers**: ≥85% (core functionality)
- **Web UI**: ≥50% (minimal, mostly Playwright)

## External Resources

- **MCP Conformance**: `notes/testing-tools.md` § MCP Protocol Testing
- **OAuth Testing**: `notes/testing-tools.md` § OAuth 2.1 Provider Testing
- **Library Docs**: `notes/go-libraries-2026.md`
- **Full Spec**: `spec.md`

## Troubleshooting

### "package X is not in GOROOT"
→ Go version too old. Need Go 1.22+. See README.md

### "CGO_ENABLED required for SQLCipher"
→ Install gcc: `sudo apt-get install build-essential`
→ Build with: `CGO_ENABLED=1 go build`

### "Coverage below threshold"
→ Run: `./scripts/coverage-gaps.sh test-results/coverage.out`
→ Add tests for uncovered lines or adjust threshold

### "Fuzz test hanging"
→ Reduce fuzz time: `./scripts/ci.sh fuzz --timeout 5m`
→ Check for infinite loops in property test

### Playwright "browser not found"
→ Install: `go run github.com/playwright-community/playwright-go/cmd/playwright install chromium`

## Quick Reference

| Task | Command |
|------|---------|
| Run tests | `./scripts/ci.sh quick` |
| Check coverage | `./scripts/ci.sh full` |
| Fuzz | `./scripts/ci.sh fuzz` |
| Build | `go build ./cmd/server` |
| Format | `go fmt ./...` |
| MCP test | `./scripts/mcp-conformance.sh` |

---

**Remember**: Property-based tests > Example-based tests. If you're tempted to write a unit test, ask: "Can this be a property instead?"
