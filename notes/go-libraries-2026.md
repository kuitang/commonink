# Go Libraries and Tools - February 2026

Comprehensive research on latest stable versions of Go libraries and tools for production use.

---

## 1. MCP Server - Model Context Protocol SDK

**Official Go SDK**: `github.com/modelcontextprotocol/go-sdk`

**Latest Version**: v1.2.0 (stable v1.0.0 released December 2025)

**Import Path**:
```go
import "github.com/modelcontextprotocol/go-sdk/mcp"
```

**Key Information**:
- Official SDK maintained in collaboration with Google
- v1.0.0 established compatibility guarantee with no breaking API changes going forward
- Includes `jsonrpc` package for custom transports
- Includes `auth` package with OAuth primitives
- Anthropic donated MCP to Linux Foundation in December 2025, establishing the Agentic AI Foundation (AAIF)
- Platinum members include AWS, Bloomberg, Cloudflare, Google, and Microsoft

**API Stability**: v1.0.0+ guarantees backward compatibility

**Community Alternatives**:
- `github.com/mark3labs/mcp-go` - Third-party implementation that inspired the official SDK

---

## 2. OAuth 2.1 Server - Authorization Server Implementation

**Recommended Library**: `github.com/ory/fosite`

**Latest Version**: Check releases at github.com/ory/fosite/releases

**Import Path**:
```go
import "github.com/ory/fosite"
```

**Key Features**:
- Production-ready OAuth2 and OpenID Connect framework
- Implements IETF RFC6749 (OAuth 2.0) with security countermeasures from RFC6819
- Full PKCE (Proof Key for Code Exchange) support - required by OAuth 2.1
- All OpenID Connect flows: code, implicit, hybrid
- Token introspection support
- Custom storage implementations
- Extensible with custom endpoint handlers

**OAuth 2.1 Context**:
- OAuth 2.1 stabilized with RFC 9700 in January 2026
- PKCE now mandatory for all OAuth clients using authorization code flow
- Requires exact string matching for redirect URIs
- Omits Implicit grant and Resource Owner Password Credentials grant

**Client Library for PKCE**:
```go
import "golang.org/x/oauth2"
```
- `GenerateVerifier()` function generates PKCE code verifier with 32 octets of randomness
- Use with `Config.AuthCodeURL` and `S256ChallengeOption`

**DCR (Dynamic Client Registration)**:
- Supported via RFC 7591 implementation
- Note: Keycloak doesn't enforce PKCE by default for DCR-registered clients

**Alternative**: Keycloak 26.4+ (external service, not a Go library)
- Supports RFC 8414 (OAuth 2.0 Authorization Server Metadata)
- Can be used with MCP servers for OAuth protection

---

## 3. Google OIDC Client - "Sign in with Google"

**Recommended Library**: `github.com/coreos/go-oidc/v3`

**Latest Version**: v3.17.0 (November 2024)

**Import Paths**:
```go
import (
    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2/google"
)
```

**Key Features**:
- OpenID Connect client logic implementation
- Enables OIDC support for `golang.org/x/oauth2`
- Provider initialization: `oidc.NewProvider(ctx, "https://accounts.google.com")`
- Requires "openid" scope
- ID token verification support

**Official Google Libraries**:
```go
import (
    "google.golang.org/api/idtoken"  // For token verification
    "golang.org/x/oauth2/google"     // For OAuth2 with Google
)
```

**Recent Updates**:
- v3.17.0: Improved error messages for mismatched issuer URLs
- Actively maintained by CoreOS team

**Integration Notes**:
- Google recommends using Google Identity Services (GIS)
- Returns OpenID Connect formatted ID Tokens
- 100% compatible with standard OIDC flows

---

## 4. SQLite + SQLCipher - Encrypted Database

**Recommended Library**: `github.com/mutecomm/go-sqlcipher`

**Alternative**: `github.com/xeodou/go-sqlcipher`

**Import Path**:
```go
import "github.com/mutecomm/go-sqlcipher/sqlite3"
```

**Key Features**:
- Self-contained Go sqlite3 driver with AES-256 encryption
- Based on popular mattn/go-sqlite3 driver
- Conforms to standard `database/sql` interface
- Version tags match SQLCipher releases
- Encryption key loaded via query parameter: `_key`

**Critical Requirements**:
- Requires `CGO_ENABLED=1`
- Requires gcc compiler
- Uses OpenSSL for AES-256 encryption implementation

**Compatibility Notes**:
- SQLCipher 4.x is **incompatible** with SQLCipher 3.x
- Must match driver version to SQLCipher version

**Alternative Libraries**:
- `github.com/CovenantSQL/go-sqlite3-encrypt` - go-sqlite3 with built-in sqlcipher
- `github.com/Daskott/gorm-sqlite-cipher` - For use with GORM ORM framework

**Usage Example**:
```go
import (
    "database/sql"
    _ "github.com/mutecomm/go-sqlcipher/sqlite3"
)

db, err := sql.Open("sqlite3", "file:encrypted.db?_key=your-encryption-key")
```

---

## 5. Encryption - HKDF and AES

### HKDF (Key Derivation)

**Standard Library**: `crypto/hkdf`

**Import Path**:
```go
import "crypto/hkdf"
```

**Alternative**: `golang.org/x/crypto/hkdf`

**Key Features**:
- HMAC-based Extract-and-Expand Key Derivation Function
- Implements RFC 5869
- Expands limited input keying material into cryptographically strong secret keys
- Works with SHA256, SHA384, SHA512

### AES Encryption

**Standard Library**: `crypto/aes` and `crypto/cipher`

**Import Paths**:
```go
import (
    "crypto/aes"
    "crypto/cipher"
)
```

**Key Features**:
- AES encryption as defined in U.S. FIPS Publication 197
- Supports AES-GCM (Galois/Counter Mode) for authenticated encryption
- 128-bit and 256-bit key support

**Advanced Use Cases**:
- Cloudflare's CIRCL library for HPKE (Hybrid Public Key Encryption)
- Combines HKDF with AES-GCM for modern encryption schemes
- Google Tink library for AES-GCM-HKDF streaming AEAD

**Example Pattern**:
```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/hkdf"
    "crypto/sha256"
)

// HKDF key derivation
hkdf := hkdf.New(sha256.New, masterKey, salt, info)
key := make([]byte, 32)
hkdf.Read(key)

// AES-GCM encryption
block, _ := aes.NewCipher(key)
gcm, _ := cipher.NewGCM(block)
```

---

## 6. Stripe Go SDK

**Official SDK**: `github.com/stripe/stripe-go`

**Latest Version**: v84.2.0 (as of February 2026)

**API Version**: 2026-01-28.clover (pinned version: 2025-12-15.clover)

**Import Path**:
```go
import (
    "github.com/stripe/stripe-go/v84"
    "github.com/stripe/stripe-go/v84/client"
)
```

**Installation**:
```bash
go get github.com/stripe/stripe-go/v84
```

**Key Information**:
- Supports Go 1.15+
- **Deprecation Notice**: Go 1.20 and 1.21 support will be removed in upcoming major version
- Follows semantic versioning
- Each SDK version uses the API version current at time of release
- New features and bug fixes released on latest major version only

**Recent Features**:
- V2 Core Account resources support
- Settlement allocation intents
- Tax manual rules

**Versioning**:
- SDK uses major version number in import path (v84)
- Can pin specific API version if needed
- Automatic version upgrades can be controlled

---

## 7. LemonSqueezy Go SDK

**Community SDK**: `github.com/NdoleStudio/lemonsqueezy-go`

**Latest Version**: Published January 13, 2026

**Import Path**:
```go
import "github.com/NdoleStudio/lemonsqueezy-go"
```

**Key Information**:
- **Unofficial** community-maintained SDK (recognized by Lemon Squeezy)
- Created and maintained by @NdoleStudio
- MIT License
- Compatible with modern Go releases in module mode
- Currently imported by 2 packages

**Features**:
- User authentication
- Subscription management
- Order handling
- Webhook support for subscription and order events
- Full API coverage for Lemon Squeezy endpoints

**Status**:
- Actively maintained
- Latest update: January 2026
- No official Lemon Squeezy SDK exists for Go; this is the recommended community option

**Documentation**:
- https://docs.lemonsqueezy.com/api
- https://pkg.go.dev/github.com/NdoleStudio/lemonsqueezy-go

---

## 8. Resend Go SDK - Email Sending

**Official SDK**: `github.com/resend/resend-go`

**Latest Version**: v3.x (as of early 2026)

**Import Path**:
```go
import "github.com/resend/resend-go/v3"
```

**Key Features**:
- Official Resend SDK for Go
- Simple email sending API
- Batch email sending with validation modes:
  - **Strict**: Only sends if all emails are valid
  - **Permissive**: Processes all emails, allowing partial success
- Custom metadata tags for emails
- Support for Cc, Bcc, ReplyTo fields
- HTML and plain text email support

**Basic Usage**:
```go
import "github.com/resend/resend-go/v3"

client := resend.NewClient(apiKey)

params := &resend.SendEmailRequest{
    From:    "sender@example.com",
    To:      []string{"recipient@example.com"},
    Subject: "Hello",
    Html:    "<h1>Hello World</h1>",
    Text:    "Hello World",
}

email, err := client.Emails.Send(params)
```

**Maintenance Status**:
- Actively maintained (commit activity as of January 31, 2026)
- Part of official Resend SDK ecosystem
- Regular updates aligned with Resend platform changes

---

## 9. Testing Tools

### Property Testing: rapid

**Library**: `pgregory.net/rapid`

**Import Path**:
```go
import "pgregory.net/rapid"
```

**GitHub**: github.com/flyingmutant/rapid

**Key Features**:
- Modern Go property-based testing library
- Generates complex structured data
- State machine test support
- Can be used as fuzz target with `MakeFuzz`
- Integrated with Go's testing package

**Comparison to Fuzzing**:
- **Strengths**: Generates complex structured data, state machine tests
- **Limitations**: No coverage-guided feedback, no mutations (unlike Go's native fuzzing)
- **Use Together**: Use rapid for structured data, fuzzing for byte-level security testing

### Native Go Fuzzing

**Standard Library**: `testing` package (Go 1.18+)

**Import Path**:
```go
import "testing"
```

**Key Features**:
- Built directly into Go toolchain since Go 1.18
- Coverage-guided fuzzing
- Mutation-based testing
- Run with: `go test -fuzz=FuzzTestName`
- Corpus management for reproducible tests

**Best Practices (2026)**:
- Use native fuzzing for security testing and edge case discovery
- Use property-based testing (rapid) for business logic validation
- Combine both approaches for comprehensive test coverage

### Browser Automation: playwright-go

**Library**: `github.com/playwright-community/playwright-go`

**Latest Version**: Check releases at github.com/playwright-community/playwright-go/releases

**Import Path**:
```go
import "github.com/playwright-community/playwright-go"
```

**Installation**:
```bash
go get -u github.com/playwright-community/playwright-go
# Install driver (replace 0.xxxx.x with version from go.mod)
go run github.com/playwright-community/playwright-go/cmd/playwright install
```

**Key Features**:
- Cross-browser automation (Chromium, Firefox, WebKit)
- Headless and headed execution modes
- Browser context management
- Page interactions and element selection
- Network interception
- Client-side certificate support
- Screenshot and video recording

**Important Notes**:
- Each minor version upgrade requires specific Playwright driver version
- Must install driver separately from package
- Community-maintained (not official Playwright project)
- Actively maintained in 2026

**Testing Integration**:
- Works with standard Go testing package
- Compatible with Godog (BDD framework)
- Supports concurrent test execution

---

## 10. HTTP Framework Recommendations

### Framework Comparison (2026)

#### Chi - Minimalist Router
**Library**: `github.com/go-chi/chi`

**Latest Version**: v5.0.12+ (published January 14, 2026)

**Import Path**:
```go
import "github.com/go-chi/chi/v5"
```

**Strengths**:
- Lightweight and composable
- 100% compatible with net/http
- No external dependencies (stdlib only)
- Idiomatic Go code
- Support for Go 1.22+ mux routing features (`request.PathValue()`)
- 16,099+ known importers

**Best For**:
- Projects wanting minimal abstraction over stdlib
- Teams prioritizing stdlib compatibility
- Microservices and simple APIs
- When you want middleware composability

#### Gin - Most Popular
**Library**: `github.com/gin-gonic/gin`

**Stars**: 75,000+ GitHub stars

**Strengths**:
- Highest performance in benchmarks
- Largest ecosystem and community
- Comprehensive documentation
- Streamlined design with minimal overhead
- JSON validation and binding

**Best For**:
- High-traffic applications
- Teams wanting proven, popular framework
- When performance is critical
- Rapid development with many features

#### Fiber - Express-like
**Library**: `github.com/gofiber/fiber`

**Strengths**:
- Built on fasthttp (not net/http)
- Express.js-inspired API (familiar to JS developers)
- Exceptional performance (comparable to Gin)
- Fast development cycle

**Limitations**:
- Not compatible with standard net/http middleware
- Different ecosystem from stdlib-based frameworks

**Best For**:
- Teams with JavaScript/Express.js background
- When maximum performance is needed
- Projects that don't need stdlib compatibility

#### Echo - Feature-Rich
**Library**: `github.com/labstack/echo`

**Strengths**:
- Comprehensive feature set
- Excellent documentation
- Idiomatic API design
- Slightly more features than Gin
- Good performance (slightly slower than Gin/Fiber in benchmarks)

**Best For**:
- Projects needing many built-in features
- Teams wanting good docs and examples
- Balanced approach between features and performance

#### Standard Library (net/http)

**Import Path**:
```go
import "net/http"
```

**Strengths**:
- Zero dependencies
- Long-term stability
- Complete control
- Go 1.22+ includes enhanced routing
- Works with any middleware

**Best For**:
- Simple applications
- Learning Go web development
- Maximum control and minimal magic
- Long-term maintenance (no framework updates needed)

### Recommendation Summary

**2026 Recommendations**:

1. **Start with Chi** if you want minimal framework overhead with good routing
2. **Use Gin** for high-traffic production apps with large community support
3. **Choose Fiber** if your team knows Express.js and needs top performance
4. **Pick Echo** if you want comprehensive features and excellent docs
5. **Use stdlib (net/http)** for simple apps or when you want zero dependencies

**Popular Choice in 2026**: Gin remains the most popular, but Chi is gaining traction for its stdlib-first approach and Go 1.22+ compatibility.

---

## 11. Rate Limiting

### Recommended Library: Tollbooth

**Library**: `github.com/didip/tollbooth`

**Latest Version**: v8.x.x

**Import Path**:
```go
import "github.com/didip/tollbooth"
```

**Key Features**:
- Generic HTTP rate limiting middleware
- Uses Token Bucket algorithm (golang.org/x/time/rate)
- No external storage required (no Redis/database)
- Rate limit by:
  - Remote IP address
  - Request path
  - HTTP methods
  - Custom headers
  - Basic auth usernames

**Version History**:
- v7.x.x: Replaced time/rate with embedded version for more rate limit headers
- v8.x.x: Addressed RemoteIP vulnerability by replacing `SetIPLookups` with `SetIPLookup`

**Important in v8+**: Must explicitly define how to pick IP address; if IP cannot be found, rate limiter is not activated.

**Community Status**: De facto standard for HTTP rate limiting in Go

### Standard Library: golang.org/x/time/rate

**Library**: `golang.org/x/time/rate`

**Import Path**:
```go
import "golang.org/x/time/rate"
```

**Key Features**:
- Token bucket rate limiter implementation
- Three methods: `Allow()`, `Reserve()`, `Wait()`
- Safe for concurrent use by multiple goroutines
- Size b (burst), rate r (tokens per second)

**Methods**:
- `Allow()`: Returns false if no token available
- `Reserve()`: Returns reservation for future token with wait time
- `Wait()`: Blocks until token available or context canceled

**Best For**:
- Fine-grained rate limiting control
- Non-HTTP rate limiting
- API client request throttling
- Controlling throughput to external services

**Usage Example**:
```go
import "golang.org/x/time/rate"

// Allow 10 requests per second with burst of 5
limiter := rate.NewLimiter(10, 5)

// In handler
if !limiter.Allow() {
    http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
    return
}
```

### Other Options

**Uber's Leaky Bucket**: `github.com/uber-go/ratelimit`
- Alternative algorithm implementation
- Leaky bucket instead of token bucket
- Simpler API for basic use cases

**Project Discovery**: `github.com/projectdiscovery/ratelimit`
- Blocking rate limit implementation
- Used in security scanning tools

### Recommendation

**For HTTP middleware**: Use `github.com/didip/tollbooth` (v8+)
- Well-maintained, widely used, comprehensive features

**For application-level rate limiting**: Use `golang.org/x/time/rate`
- Standard library, flexible, no dependencies

**For high-performance needs**: Consider implementing custom solution with `golang.org/x/time/rate` as foundation

---

## Summary Matrix

| Category | Library | Version | Import Path | Status |
|----------|---------|---------|-------------|--------|
| MCP SDK | modelcontextprotocol/go-sdk | v1.2.0 | github.com/modelcontextprotocol/go-sdk/mcp | Official, Google-backed |
| OAuth 2.1 Server | ory/fosite | Latest | github.com/ory/fosite | Production-ready, comprehensive |
| OAuth 2.1 Client | golang.org/x/oauth2 | Latest | golang.org/x/oauth2 | Standard library, PKCE support |
| Google OIDC | coreos/go-oidc | v3.17.0 | github.com/coreos/go-oidc/v3/oidc | Community standard |
| SQLite + Encryption | mutecomm/go-sqlcipher | Latest | github.com/mutecomm/go-sqlcipher | Requires CGO |
| HKDF | crypto/hkdf | stdlib | crypto/hkdf | Standard library |
| AES | crypto/aes | stdlib | crypto/aes | Standard library |
| Stripe | stripe/stripe-go | v84.2.0 | github.com/stripe/stripe-go/v84 | Official |
| LemonSqueezy | NdoleStudio/lemonsqueezy-go | Jan 2026 | github.com/NdoleStudio/lemonsqueezy-go | Community (unofficial) |
| Resend | resend/resend-go | v3.x | github.com/resend/resend-go/v3 | Official |
| Property Testing | rapid | Latest | pgregory.net/rapid | Modern, comprehensive |
| Fuzzing | testing | Go 1.18+ | testing | Standard library |
| Browser Testing | playwright-community/playwright-go | Latest | github.com/playwright-community/playwright-go | Community-maintained |
| HTTP Framework | go-chi/chi | v5.0.12+ | github.com/go-chi/chi/v5 | Minimal, stdlib-compatible |
| HTTP Framework | gin-gonic/gin | Latest | github.com/gin-gonic/gin | Most popular |
| HTTP Framework | gofiber/fiber | Latest | github.com/gofiber/fiber | Express-like, fasthttp |
| HTTP Framework | labstack/echo | Latest | github.com/labstack/echo | Feature-rich |
| Rate Limiting | didip/tollbooth | v8.x | github.com/didip/tollbooth | HTTP middleware |
| Rate Limiting | golang.org/x/time/rate | Latest | golang.org/x/time/rate | Application-level |

---

## Production Readiness Notes

### High Confidence (Official/Widely Used)
- MCP SDK (official, Google-backed, Linux Foundation)
- Stripe SDK (official)
- Resend SDK (official)
- All stdlib packages (crypto/*, testing, net/http)
- go-oidc (CoreOS/community standard)
- Gin (75k+ stars, proven at scale)
- Chi (16k+ importers, stdlib-compatible)
- Tollbooth (community standard for HTTP rate limiting)

### Good Community Support
- Fosite (Ory ecosystem, used by Hydra)
- LemonSqueezy SDK (unofficial but recognized)
- Playwright-go (active community)
- Fiber (large community, Express.js familiarity)
- Echo (excellent documentation)

### Requires CGO (Deployment Consideration)
- go-sqlcipher (requires CGO_ENABLED=1 and gcc)

### Breaking Changes to Watch
- Stripe: Go 1.20/1.21 deprecation coming
- SQLCipher: v4 incompatible with v3
- Playwright-go: Driver version must match package version

---

## Sources

### MCP SDK
- [GitHub - modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- [State of GO 2026](https://devnewsletter.com/p/state-of-go-2026)
- [Building an MCP Code Review Server in Go Using Official SDKs](https://dshills.medium.com/building-an-mcp-code-review-server-in-go-using-official-sdks-011a6f63abc1)

### OAuth 2.1 and OIDC
- [OAuth 2.1](https://oauth.net/2.1/)
- [Protecting MCP Server with OAuth 2.1: A Practical Guide Using Go and Keycloak](https://medium.com/@wadahiro/protecting-mcp-server-with-oauth-2-1-a-practical-guide-using-go-and-keycloak-7544eb5379d3)
- [GitHub - ory/fosite](https://github.com/ory/fosite)
- [How to Implement OAuth2 Server in Go with fosite](https://oneuptime.com/blog/post/2026-01-07-go-oauth2-server-fosite/view)
- [Sign in with Google in Go - Eli Bendersky's website](https://eli.thegreenplace.net/2024/sign-in-with-google-in-go/)
- [GitHub - coreos/go-oidc](https://github.com/coreos/go-oidc)

### Database and Encryption
- [GitHub - mutecomm/go-sqlcipher](https://github.com/mutecomm/go-sqlcipher)
- [crypto/hkdf - Go Packages](https://pkg.go.dev/crypto/hkdf)
- [crypto/aes - Go Packages](https://pkg.go.dev/crypto/aes)
- [Derive keys using HKDF with SHA256 in Go](https://blog.vitalvas.com/post/2025/07/17/derive-keys-hkdf-sha256-golang/)

### Payment SDKs
- [GitHub - stripe/stripe-go](https://github.com/stripe/stripe-go)
- [Stripe Go SDK Docs](https://pkg.go.dev/github.com/stripe/stripe-go/v81)
- [GitHub - NdoleStudio/lemonsqueezy-go](https://github.com/NdoleStudio/lemonsqueezy-go)

### Email
- [Send emails with Go - Resend](https://resend.com/docs/send-with-go)
- [GitHub - resend/resend-go](https://github.com/resend/resend-go)

### Testing
- [GitHub - flyingmutant/rapid](https://github.com/flyingmutant/rapid)
- [Go Fuzzing - The Go Programming Language](https://go.dev/doc/security/fuzz/)
- [How to Use Fuzzing in Go for Security Testing](https://oneuptime.com/blog/post/2026-01-07-go-fuzzing-security/view)
- [Go Testing in 2025: Mocks, Fuzzing & Property-Based Testing](https://dev.to/aleksei_aleinikov/go-testing-in-2025-mocks-fuzzing-property-based-testing-1gmg)
- [GitHub - playwright-community/playwright-go](https://github.com/playwright-community/playwright-go)
- [Playwright in Golang for Web Scraping [Tutorial 2026]](https://www.zenrows.com/blog/playwright-golang)

### HTTP Frameworks
- [Choosing a Go Web Framework in 2026: A Minimalist's Guide](https://medium.com/@samayun_pathan/choosing-a-go-web-framework-in-2026-a-minimalists-guide-to-gin-fiber-chi-echo-and-beego-c79b31b8474d)
- [Best Go Backend Frameworks in 2026 - Complete Comparison – Encore](https://encore.dev/articles/best-go-backend-frameworks)
- [GitHub - go-chi/chi](https://github.com/go-chi/chi)

### Rate Limiting
- [GitHub - didip/tollbooth](https://github.com/didip/tollbooth)
- [Rate limiting your Go application - LogRocket Blog](https://blog.logrocket.com/rate-limiting-go-application/)
- [golang.org/x/time/rate - Go Packages](https://pkg.go.dev/golang.org/x/time/rate)
- [Go Wiki: Rate Limiting](https://go.dev/wiki/RateLimiting)

---

*Last Updated: February 2, 2026*
