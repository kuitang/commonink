# Property-Based Testing Strategy: rapid + gofuzz

## Executive Summary

This document defines a testing strategy centered on **property-based testing** using Go's `rapid` library integrated with native `go fuzz`. The approach prioritizes end-to-end testing of REST API and MCP endpoints, with unit tests reserved only for sensitive logic and regression cases from bug reports.

---

## 1. Design Philosophy

### 1.1 Core Principles

| Principle | Rationale |
|-----------|-----------|
| **Property > Example** | Properties express invariants that must hold for all inputs; examples only prove specific cases work |
| **End-to-End > Unit** | Testing the actual API surface catches integration bugs that unit tests miss |
| **Fuzzing as CI Extension** | Coverage-guided fuzzing finds edge cases that pure random generation cannot |
| **Single Source of Truth** | One script runs CI locally and remotely—no "works on my machine" |

### 1.2 When NOT to Write Traditional Unit Tests

Traditional example-based unit tests (`TestFoo_ReturnsBar`) are **only appropriate for**:

1. **Regression tests from bug reports** — When a user reports a bug with a specific input, add that input as a seed corpus entry
2. **Documentation tests** — Examples that serve as API documentation (sparingly)

Everything else should be property-based.

---

## 2. Testing Taxonomy

### 2.1 Test Categories

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PROPERTY-BASED TESTS                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  END-TO-END (E2E) TESTS                                              │   │
│  │  • REST API endpoints                                                │   │
│  │  • MCP protocol endpoints                                            │   │
│  │  • User journey simulations                                          │   │
│  │  • State machine tests (login → action → logout sequences)          │   │
│  │                                                                       │   │
│  │  Implementation: rapid + HTTP client against running server          │   │
│  │  Coverage: Business logic, integration, API contracts                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  SENSITIVE LOGIC UNIT TESTS                                          │   │
│  │  • Authentication (token generation, validation, expiry)             │   │
│  │  • Authorization (permission checks, role hierarchies)               │   │
│  │  • Data integrity (checksums, signatures, encryption)                │   │
│  │  • Input parsing (malformed JSON, unicode edge cases, injections)    │   │
│  │                                                                       │   │
│  │  Implementation: rapid at function level                             │   │
│  │  Coverage: Security boundaries, data corruption prevention           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  BROWSER E2E (Playwright)                                            │   │
│  │  • Critical user flows (signup, checkout, etc.)                      │   │
│  │  • Visual regression                                                 │   │
│  │  • JavaScript-dependent functionality                                │   │
│  │                                                                       │   │
│  │  Implementation: playwright-go with deterministic scenarios          │   │
│  │  Note: NOT property-based (too slow); run in "full" CI only          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 What Goes Where

| Test Type | Location | Naming Convention | When to Use |
|-----------|----------|-------------------|-------------|
| E2E API Property Tests | `tests/e2e/*_test.go` | `TestAPI_<Resource>_Properties` | Default for all features |
| E2E MCP Property Tests | `tests/e2e/*_mcp_test.go` | `TestMCP_<Protocol>_Properties` | MCP endpoint testing |
| Sensitive Logic Tests | `internal/<pkg>/*_test.go` | `TestSecure_<Function>_Properties` | Auth, crypto, parsing |
| Playwright Tests | `tests/browser/*_test.go` | `TestBrowser_<Flow>` | Browser-specific behavior |
| Bug Regression Seeds | `testdata/fuzz/<TestName>/` | Corpus files | From bug reports only |

---

## 3. rapid + gofuzz Integration

### 3.1 Dual Execution Model

Every property test MUST be executable in two modes:

1. **rapid mode** (fast, 100 iterations default)
   - Runs during development and quick CI
   - Uses rapid's intelligent shrinking
   - Deterministic reproduction via `-rapid.seed`

2. **fuzz mode** (slow, coverage-guided)
   - Runs during dedicated fuzz CI jobs
   - Uses Go's native coverage instrumentation
   - Discovers inputs rapid's random generation misses
   - Corpus persists in `testdata/fuzz/`

### 3.2 Test Structure Pattern

Each property test file should follow this structure:

```
// File: tests/e2e/notes_api_test.go

// 1. Property test function (called by both rapid and fuzz)
func testNotesAPI_CRUD_Properties(t *rapid.T, client *APIClient) {
    // Property-based test logic here
    // Uses rapid generators for input
    // Asserts properties (not specific outputs)
}

// 2. Rapid test entry point (go test)
func TestNotesAPI_CRUD_Properties(t *testing.T) {
    client := setupTestClient(t)
    rapid.Check(t, func(t *rapid.T) {
        testNotesAPI_CRUD_Properties(t, client)
    })
}

// 3. Fuzz test entry point (go test -fuzz)
func FuzzNotesAPI_CRUD_Properties(f *testing.F) {
    client := setupTestClient(f)
    f.Add([]byte{0x00}) // Minimal seed
    f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
        testNotesAPI_CRUD_Properties(t, client)
    }))
}
```

### 3.3 Why This Dual Approach?

| Aspect | rapid Only | gofuzz Only | rapid + gofuzz |
|--------|------------|-------------|----------------|
| Structured input generation | ✅ Excellent | ❌ Byte streams | ✅ Best of both |
| Coverage guidance | ❌ Random only | ✅ Yes | ✅ Yes |
| Shrinking | ✅ Automatic | ⚠️ Minimization only | ✅ Full shrinking |
| Speed | ✅ Fast | ❌ Slow | ✅ Fast default, slow when needed |
| Magic value discovery | ❌ Unlikely | ✅ Excellent | ✅ Yes |
| State machine support | ✅ Yes | ❌ No | ✅ Yes |

---

## 4. Property Patterns for E2E Testing

### 4.1 Core Properties to Test

#### REST API Properties

| Property | Description | Example |
|----------|-------------|---------|
| **Roundtrip** | `GET(POST(x)) == x` | Create note → fetch note → compare |
| **Idempotence** | `PUT(x); PUT(x)` same result | Update note twice, same final state |
| **User Isolation** | User A cannot see User B's data | Search returns only current user's notes |
| **Pagination Consistency** | Union of all pages == full result | Paginate through all notes |
| **Error Shape** | All errors follow schema | Random invalid requests return proper error JSON |
| **Auth Enforcement** | Unauthenticated requests fail | All endpoints return 401 without token |

#### MCP Protocol Properties

| Property | Description |
|----------|-------------|
| **Request-Response Matching** | Every request gets exactly one response |
| **Tool Schema Compliance** | Tool outputs match declared schemas |
| **Capability Honoring** | Server only offers declared capabilities |
| **Session Consistency** | State is consistent within a session |

### 4.2 State Machine Testing Pattern

For testing user journeys (sequences of API calls):

```
State Machine Model:
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   ┌─────────┐  register   ┌────────────┐  login   ┌───────┐ │
│   │Anonymous│────────────▶│ Registered │─────────▶│Logged │ │
│   └─────────┘             └────────────┘          │  In   │ │
│        │                        │                 └───┬───┘ │
│        │                        │                     │     │
│        └────────login───────────┤                     │     │
│                 (fail)          │                     │     │
│                                 │              ┌──────┴───┐ │
│                                 │              │Can CRUD  │ │
│                                 │              │notes,    │ │
│                                 │              │search,   │ │
│                                 │              │logout    │ │
│                                 │              └──────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘

rapid.Repeat generates random valid sequences through this graph.
Properties checked at each state transition.
```

---

## 5. Sensitive Logic Unit Tests

### 5.1 Functions Requiring Unit-Level Property Tests

These functions are tested at the unit level (not E2E) because:
- Security impact is high
- Edge cases are subtle
- Fast feedback is critical

| Category | Functions | Properties to Test |
|----------|-----------|-------------------|
| **AuthN** | `GenerateToken`, `ValidateToken`, `RefreshToken` | Expiry correctness, signature validity, timing attack resistance |
| **AuthZ** | `CheckPermission`, `EvaluatePolicy`, `InheritRole` | No privilege escalation, deny-by-default, transitivity |
| **Crypto** | `Encrypt`, `Decrypt`, `Hash`, `Sign` | Roundtrip, no plaintext leakage, determinism where expected |
| **Parsing** | `ParseUserInput`, `SanitizeHTML`, `ValidateJSON` | Injection prevention, unicode normalization, malformed input handling |
| **Data Integrity** | `Checksum`, `Serialize`, `Deserialize` | Corruption detection, version compatibility |

### 5.2 Input Generators for Security Testing

Implement custom generators that produce adversarial inputs:

| Generator | Purpose | Inputs Generated |
|-----------|---------|------------------|
| `SQLInjectionStrings()` | Test SQL injection | `'; DROP TABLE--`, `1 OR 1=1`, etc. |
| `XSSPayloads()` | Test XSS prevention | `<script>`, `javascript:`, `onerror=` |
| `UnicodeEdgeCases()` | Test unicode handling | Zero-width chars, RTL overrides, homoglyphs |
| `JWTMalformed()` | Test JWT parsing | Missing segments, invalid base64, wrong alg |
| `BoundaryIntegers()` | Test integer handling | `MaxInt64`, `MinInt64`, `0`, `-1` |

---

## 6. CI Harness Design

### 6.1 Single Entry Point

All CI runs through ONE script: `./scripts/ci.sh`

```
Usage: ./scripts/ci.sh <level> [options]

Levels:
  quick   - rapid only, no coverage, ~30 seconds
  full    - rapid + Playwright + coverage report, ~5 minutes  
  fuzz    - quick + coverage-guided fuzzing, ~30+ minutes

Options:
  --timeout <duration>   Fuzz timeout (default: 30m)
  --parallel <n>         Parallel test workers (default: GOMAXPROCS)
  --output <dir>         Output directory for reports (default: ./test-results)
```

### 6.2 CI Levels Specification

#### Level: `quick`

**Purpose**: Fast feedback during development and PR checks

**What runs**:
- All `Test*` functions (rapid property tests)
- No `Fuzz*` functions
- No Playwright
- No coverage collection

**Expected duration**: ~30 seconds

**Exit criteria**: Any test failure = CI failure

#### Level: `full`

**Purpose**: Comprehensive validation before merge

**What runs**:
- All `Test*` functions with coverage instrumentation
- Playwright browser tests
- Coverage report generation

**Expected duration**: ~5 minutes

**Outputs**:
- `test-results/coverage.out` — Raw coverage profile
- `test-results/coverage.html` — HTML coverage report
- `test-results/coverage-gaps.txt` — List of uncovered lines
- `test-results/playwright/` — Playwright traces and screenshots

**Coverage requirements**:
- Minimum total coverage: configurable (recommend 70%+)
- CI fails if coverage drops below threshold

#### Level: `fuzz`

**Purpose**: Deep exploration for edge cases and security issues

**What runs**:
- All `Fuzz*` functions with coverage-guided fuzzing
- All `Test*` functions (as baseline)
- Coverage comparison: unit vs fuzz

**Expected duration**: 30+ minutes (configurable via `--timeout`)

**Outputs**:
- `test-results/fuzz-coverage.out` — Fuzz coverage profile
- `test-results/coverage-comparison.txt` — Unit vs Fuzz coverage diff
- `test-results/fuzz-findings/` — Any new corpus entries (potential bugs)
- `testdata/fuzz/` — Updated corpus (committed to repo)

### 6.3 Coverage Gap Detection

The CI script must implement coverage gap analysis as described in our discussions:

**Algorithm**:
1. Parse coverage profiles (format: `file.go:startLine.startCol,endLine.endCol stmtCount hitCount`)
2. Compare unit coverage vs fuzz coverage
3. Report:
   - Lines hit by fuzz but not unit tests → **Need documentation tests**
   - Lines never hit by either → **Dead code or inadequate testing**
   - Coverage improvement percentage

**Output format** (`coverage-gaps.txt`):
```
=== LINES HIT BY FUZZ BUT NOT UNIT TESTS ===
  internal/auth/token.go:47 (hit 23 times)
  internal/auth/token.go:49 (hit 8 times)
  
=== LINES NEVER HIT ===
  internal/legacy/deprecated.go:12-45 (dead code?)
  
=== COVERAGE SUMMARY ===
  Unit tests: 847/1203 lines (70.4%)
  Fuzz tests: 1089/1203 lines (90.5%)
  Improvement from fuzzing: +20.1%
```

---

## 7. GitHub Actions Integration

### 7.1 Workflow Structure

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  quick:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Quick Tests
        run: ./scripts/ci.sh quick
        
  full:
    runs-on: ubuntu-latest
    needs: quick
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Install Playwright
        run: go run github.com/playwright-community/playwright-go/cmd/playwright install --with-deps
      - name: Full Tests
        run: ./scripts/ci.sh full
      - name: Upload Coverage
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: test-results/
          retention-days: 30
      - name: Coverage Gate
        run: |
          COVERAGE=$(go tool cover -func=test-results/coverage.out | grep total | awk '{print $3}' | tr -d '%')
          if (( $(echo "$COVERAGE < 70" | bc -l) )); then
            echo "Coverage $COVERAGE% is below threshold 70%"
            exit 1
          fi
```

### 7.2 Fuzz Workflow (Nightly)

```yaml
# .github/workflows/fuzz.yml
name: Fuzz Testing

on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM daily
  workflow_dispatch:      # Manual trigger

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          
      # Restore corpus from previous runs
      - name: Restore Fuzz Corpus
        uses: actions/cache@v4
        with:
          path: |
            testdata/fuzz
            ~/.cache/go-build/fuzz
          key: fuzz-corpus-${{ github.sha }}
          restore-keys: |
            fuzz-corpus-
            
      - name: Fuzz Tests
        run: ./scripts/ci.sh fuzz --timeout 30m
        
      # Commit new corpus entries back to repo
      - name: Commit Corpus Updates
        if: github.event_name == 'schedule'
        run: |
          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add testdata/fuzz/
          git diff --staged --quiet || git commit -m "chore: update fuzz corpus [skip ci]"
          git push
          
      - name: Upload Fuzz Results
        uses: actions/upload-artifact@v4
        with:
          name: fuzz-results-${{ github.run_number }}
          path: test-results/
          retention-days: 90
          
      # Alert on new findings
      - name: Check for New Findings
        run: |
          if [ -d "test-results/fuzz-findings" ] && [ "$(ls -A test-results/fuzz-findings)" ]; then
            echo "::warning::New fuzz findings detected! Review test-results/fuzz-findings/"
            exit 1
          fi
```

### 7.3 Artifact Management

| Artifact | Retention | Purpose |
|----------|-----------|---------|
| `coverage-report` | 30 days | PR review, trend analysis |
| `fuzz-results-*` | 90 days | Investigate findings, corpus debugging |
| `testdata/fuzz/` | Permanent (in repo) | Regression tests, seed corpus |
| `playwright-traces` | 7 days | Debug browser test failures |

---

## 8. Playwright Integration

### 8.1 Can You Run rapid+gofuzz with Playwright?

**Short answer**: Technically yes, practically no for fuzzing.

**Technical feasibility**:
- `playwright-go` is a Go library
- Playwright can be called from within a rapid property test
- MakeFuzz works with any rapid test

**Practical limitations**:
- Browser startup: ~500ms-2s per test
- Network latency: variable
- Fuzzing requires thousands of iterations → hours/days runtime
- Coverage feedback is for Go code, not browser JS

### 8.2 Recommended Approach

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   rapid + gofuzz                           Playwright                       │
│   ──────────────                           ──────────                       │
│   • API-level property tests               • Deterministic UI flows         │
│   • Fast (1000s of iterations)             • Slow (10s of scenarios)        │
│   • Coverage-guided                        • Not fuzzable                   │
│   • Runs in quick + fuzz CI                • Runs in full CI only           │
│                                                                             │
│   Use for:                                 Use for:                         │
│   • REST API endpoints                     • Critical user journeys         │
│   • MCP protocol                           • JS-dependent features          │
│   • Business logic                         • Visual regression              │
│   • Auth flows (API level)                 • Cross-browser compat           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.3 Playwright Test Structure

Playwright tests are **not** property-based. They are deterministic scenarios:

```
// tests/browser/signup_flow_test.go

func TestBrowser_SignupFlow(t *testing.T) {
    // Deterministic scenario, not property-based
    // 1. Navigate to signup page
    // 2. Fill form with specific test data
    // 3. Submit
    // 4. Assert success state
}
```

If you want to test multiple input variations in Playwright, use **table-driven tests** with a fixed set of interesting cases, not random generation.

---

## 9. Implementation Checklist

### Phase 1: Foundation
- [ ] Set up rapid as test dependency
- [ ] Create `./scripts/ci.sh` with three levels
- [ ] Implement coverage gap detection tool
- [ ] Configure GitHub Actions workflows

### Phase 2: E2E Test Suite
- [ ] Implement API client for test use
- [ ] Create generators for domain objects (User, Note, etc.)
- [ ] Write state machine test for core user journey
- [ ] Add roundtrip, isolation, and idempotence properties

### Phase 3: Sensitive Logic Tests
- [ ] Identify all auth/authz functions
- [ ] Create adversarial input generators
- [ ] Write property tests for each security boundary

### Phase 4: Playwright Integration
- [ ] Set up playwright-go
- [ ] Identify critical browser-only flows
- [ ] Write deterministic Playwright tests
- [ ] Add to `full` CI level

### Phase 5: Fuzzing Polish
- [ ] Run initial fuzz campaign (1+ hours)
- [ ] Triage and fix findings
- [ ] Commit corpus to repo
- [ ] Set up nightly fuzz schedule

---

## 10. Open Questions for Implementor

1. **Database Setup**: How should tests manage database state? Options:
   - Fresh DB per test (slow but isolated)
   - Transaction rollback after each test (fast but complex)
   - Shared DB with cleanup (fast but potential interference)

    - fresh db per test. it's sqllite so it should be fast.

2. **Test Server**: Should E2E tests:
   - Start a real server process?
   - Use httptest.Server with the real handler?
   - Mock external dependencies?
   - 
Practical Recommendation for Your Strategy
Hybrid approach:
Test LevelServer TypeRationalequick (rapid)httptest.ServerSpeed matters, coverage worksfull (rapid + Playwright)httptest.ServerCoverage still importantfuzzhttptest.ServerNeed coverage guidanceSmoke tests (separate job)Real processCatch lifecycle bugs
Add a small "smoke test" job that:

Builds the real binary
Starts it as a subprocess
Runs ~10 critical path requests
Verifies graceful shutdown

3. **MCP Testing**: What MCP transports need testing?
   - stdio
   - HTTP/SSE
   - WebSocket

mcp uses streamable http only.

4. **Flakiness Budget**: What's acceptable flakiness rate for E2E tests?
   - 0% (any flake blocks merge)
   - <1% (retry once)
   - Context-dependent

---

## Appendix A: Property Cheat Sheet

| Pattern | Formula | When to Use |
|---------|---------|-------------|
| Roundtrip | `decode(encode(x)) == x` | Serialization, API CRUD |
| Idempotence | `f(f(x)) == f(x)` | PUT requests, normalization |
| Invariant | `property(f(x)) == true` | Sorted, balanced, valid state |
| Commutativity | `f(a,b) == f(b,a)` | Set operations, aggregations |
| Oracle | `f(x) == reference(x)` | Testing against known-good impl |
| Metamorphic | `f(transform(x)) == transform(f(x))` | When oracle unavailable |

## Appendix B: Generator Patterns

| Generator | Use Case |
|-----------|----------|
| `rapid.String()` | General string input |
| `rapid.StringMatching(regex)` | Constrained strings (emails, IDs) |
| `rapid.SliceOf(g)` | Lists of items |
| `rapid.MapOf(k, v)` | Dictionaries |
| `rapid.Custom(fn)` | Domain objects |
| `rapid.OneOf(g1, g2, ...)` | Union types |
| `rapid.Deferred(fn)` | Recursive structures |
| `rapid.SampledFrom(slice)` | Enum-like values |

## Appendix C: References

- [rapid documentation](https://pkg.go.dev/pgregory.net/rapid)
- [Go Fuzzing documentation](https://go.dev/doc/security/fuzz/)
- [playwright-go](https://github.com/playwright-community/playwright-go)
- [Property-Based Testing with PropEr, Erlang, and Elixir](https://pragprog.com/titles/fhproper/) (conceptual reference)

