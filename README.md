# Remote Notes MicroSaaS

MCP-first notes service enabling AI context sharing across Claude, ChatGPT, and any MCP-compatible client.

## Prerequisites

**CRITICAL: Go 1.22 or later is required**

The current system has Go 1.19, but this project requires Go 1.22+ due to:
- MCP SDK using `cmp`, `iter`, `log/slog`, `maps`, `slices` packages (Go 1.21+)
- Modern standard library features
- Native fuzzing improvements
- Enhanced routing in `net/http`

### Install Go 1.22+

```bash
# Download and install Go 1.22+ (or later)
wget https://go.dev/dl/go1.22.10.linux-arm64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.10.linux-arm64.tar.gz

# Update PATH in ~/.bashrc or ~/.zshrc
export PATH=/usr/local/go/bin:$PATH

# Verify
go version  # Should show go1.22.10 or later
```

## Quick Start

```bash
# Install dependencies
go mod download

# Build (requires Go 1.22+)
go build -o bin/server ./cmd/server

# For SQLCipher support (requires gcc and CGO)
CGO_ENABLED=1 go build -o bin/server ./cmd/server

# Run smoke test
./bin/server

# Run with test server
START_SERVER=true ./bin/server
```

## Project Structure

```
.
├── cmd/server/          # Main entry point
├── internal/
│   ├── auth/           # OAuth provider + Google OIDC
│   ├── notes/          # Note storage + encryption
│   ├── mcp/            # MCP protocol handler
│   ├── payment/        # Stripe/LemonSqueezy
│   ├── email/          # Resend client
│   └── ratelimit/      # Rate limiting middleware
├── web/
│   ├── templates/      # HTML templates
│   └── static/         # CSS, JS
├── tests/
│   ├── e2e/            # API property tests (rapid + httptest)
│   └── browser/        # Playwright tests
├── scripts/
│   └── ci.sh           # CI runner (quick, full, fuzz)
├── spec.md             # Engineering specification
├── PRIVACY.md          # Privacy policy
├── TOS.md              # Terms of Service
└── CLAUDE.md           # Developer guide
```

## Testing

See `CLAUDE.md` for detailed test instructions.

### Quick CI Test
```bash
./scripts/ci.sh quick    # ~30 seconds, rapid property tests
```

### Full CI Test
```bash
./scripts/ci.sh full     # ~5 minutes, includes Playwright + coverage
```

### Fuzz Testing
```bash
./scripts/ci.sh fuzz     # 30+ minutes, coverage-guided fuzzing
```

## Documentation

- **[spec.md](./spec.md)**: Complete engineering specification
- **[CLAUDE.md](./CLAUDE.md)**: Developer guide with test plan
- **[PRIVACY.md](./PRIVACY.md)**: Privacy policy
- **[TOS.md](./TOS.md)**: Terms of Service
- **[notes/go-libraries-2026.md](./notes/go-libraries-2026.md)**: Library research
- **[notes/testing-tools.md](./notes/testing-tools.md)**: External test resources

## Development

### Git Hooks

Git hooks are automatically installed to run `go fmt` and quick CI before commits:

```bash
# Hooks are in .git/hooks/pre-commit
# To bypass (not recommended): git commit --no-verify
```

### Environment Variables

See `spec.md` for complete list. Key variables:

```bash
MASTER_KEY=<hex-key>               # For encryption KEK derivation
GOOGLE_CLIENT_ID=<google-id>
GOOGLE_CLIENT_SECRET=<google-secret>
STRIPE_SECRET_KEY=<stripe-key>     # or LEMON_API_KEY
RESEND_API_KEY=<resend-key>
OAUTH_ISSUER=https://your-domain.com
DATABASE_PATH=/data
```

## Deployment

### Fly.io

```bash
fly launch
fly secrets set MASTER_KEY=<key> GOOGLE_CLIENT_ID=<id> ...
fly deploy
```

See `spec.md` for detailed deployment configuration.

## License

[Your license here]

## Contact

- Support: support@[your-domain]
- Security: security@[your-domain]
- Privacy: privacy@[your-domain]
