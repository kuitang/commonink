# Milestone 5: Payments + API Keys + Production Deployment

**Goal**: Implement LemonSqueezy payments, API keys, storage limits, and deploy to production on Fly.io.

**Prerequisites**: Milestone 4 complete (real auth integrations working), Milestone 3.5 complete (OAuth 2.1 provider working)

**Key Principle**: This is the "ship it" milestone. Everything needed for users to pay and the service to go live.

---

## What This Milestone Covers

| Feature | Description | Status |
|---------|-------------|--------|
| **Payments** | LemonSqueezy $5/year subscription | TODO |
| **API Keys** | Alternative to OAuth for programmatic access | TODO |
| **Storage Limits** | 100MB free, unlimited paid | TODO |
| **Production Deploy** | Fly.io with secrets, volumes, and domain | TODO |

**Note**: OAuth 2.1 Provider is in **Milestone 3.5**. Tigris storage is already implemented (`internal/s3client/`).

---

## Implementation DAG

```
                    [Milestone 4 Complete]
                    (Real auth working)
                            │
                    [Milestone 3.5 Complete]
                    (OAuth 2.1 provider working)
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
  [Payments/           [API Keys]      [Storage Limits
   LemonSqueezy]            │           Enforcement]
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                [Subscription Enforcement]
                     (rate limits)
                            │
                    [Wire into main.go]
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
[Manual: Payment    [Manual: AI Client   [Manual: API Key
 Flow (ngrok)]       MCP Connection]       Access]
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                [Fly.io Production Deploy]
                            │
                        [Launch]
```

---

## Tasks (Topologically Sorted)

### Layer 0: Prerequisites
- [x] M4 complete (real Google OIDC + Resend working)
- [x] Web UI + OAuth consent screens ready (from M3)
- [ ] Register domain name (required for production)

### Layer 1 (Parallel - No Dependencies)

#### 1. Payments / LemonSqueezy (`internal/payment/`)

**Purpose**: $5/year subscription with free tier.

**Endpoints**:
```
POST /checkout              - Create LemonSqueezy checkout session
POST /webhooks/lemon        - LemonSqueezy webhook receiver
GET  /subscription/status   - Check user's subscription
```

**Files**:
- `service.go` - Interface + checkout creation
- `webhook.go` - Webhook handler + signature verification
- `subscription.go` - Subscription status checking

**Interface** (M2/M4 DI pattern):
```go
type PaymentService interface {
    CreateCheckout(userID string) (*CheckoutSession, error)
    GetSubscription(userID string) (*Subscription, error)
    HandleWebhook(payload []byte, signature string) error
}

// Mock for testing
type MockPaymentService struct { ... }

// Real implementation
type LemonSqueezyService struct {
    client *lemonsqueezy.Client
    webhookSecret string
}
```

**Webhook Events**:
- `subscription_created` → Set user to paid
- `subscription_updated` → Update status
- `subscription_cancelled` → Set user to free
- `subscription_payment_failed` → Grace period handling

**User DB Update** (account table already has fields):
```sql
subscription_status TEXT DEFAULT 'free',  -- 'free', 'paid', 'cancelled'
subscription_id TEXT,                       -- LemonSqueezy subscription ID
```

#### 2. API Keys (`internal/auth/apikeys.go`)

**Purpose**: Alternative to OAuth for programmatic access (scripts, integrations).

**Schema** (already in user DB per spec.md):
```sql
CREATE TABLE api_keys (
    key_id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL,
    scope TEXT DEFAULT 'read_write',
    created_at INTEGER NOT NULL,
    last_used INTEGER
);
```

**Endpoints**:
```
GET    /settings/api-keys      - List user's API keys (web UI)
POST   /settings/api-keys      - Create new API key (returns key once)
DELETE /settings/api-keys/{id} - Revoke API key
```

**Authentication**:
- API key in `Authorization: Bearer key_xxx` header
- OR in `X-API-Key: key_xxx` header
- Check before OAuth token check in middleware

**Key Format**:
- Prefix: `key_` (distinguishes from OAuth tokens)
- 32 random bytes, base64url encoded
- Store SHA-256 hash in DB
- Show full key only once on creation

### Layer 2 (Depends on Layer 1)

#### 3. Storage Limits Enforcement (`internal/notes/limits.go`)

**Purpose**: Free tier 100MB, paid unlimited.

**Implementation**:
```go
type LimitsChecker struct {
    paymentService payment.PaymentService
}

func (l *LimitsChecker) CanWrite(userID string, newContentSize int64) error {
    sub, _ := l.paymentService.GetSubscription(userID)
    if sub.Status == "paid" {
        return nil // Unlimited
    }

    currentSize := l.getCurrentDBSize(userID)
    if currentSize + newContentSize > 100*1024*1024 { // 100MB
        return ErrStorageLimitExceeded
    }
    return nil
}
```

**Checks on**:
- `note_create`
- `note_update`

**User feedback**:
- Return 402 Payment Required with upgrade link
- Show usage in web UI settings

#### 4. Subscription Enforcement in Rate Limiter

**Update rate limiter** to check subscription:
```go
func (m *RateLimitMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    userID := auth.GetUserID(r.Context())

    // Check subscription for rate limit tier
    sub, _ := m.paymentService.GetSubscription(userID)
    isPaid := sub.Status == "paid"

    if !m.limiter.Allow(userID, isPaid) {
        w.Header().Set("Retry-After", "1")
        http.Error(w, "Rate limit exceeded", 429)
        return
    }

    m.next.ServeHTTP(w, r)
}
```

### Layer 3 (Depends on Layer 2)

#### 5. Wire Everything into main.go

```go
// Payments
var paymentSvc payment.PaymentService
if cfg.UseMockPayment {
    paymentSvc = payment.NewMockPaymentService()
} else {
    paymentSvc = payment.NewLemonSqueezyService(cfg.LemonAPIKey, cfg.LemonWebhookSecret)
}
mux.HandleFunc("POST /checkout", paymentHandler.CreateCheckout)
mux.HandleFunc("POST /webhooks/lemon", paymentHandler.Webhook)
mux.HandleFunc("GET /subscription/status", paymentHandler.Status)

// API Keys
mux.HandleFunc("GET /settings/api-keys", apiKeyHandler.List)
mux.HandleFunc("POST /settings/api-keys", apiKeyHandler.Create)
mux.HandleFunc("DELETE /settings/api-keys/{id}", apiKeyHandler.Delete)

// Update auth middleware to check API keys + OAuth tokens (from M3.5)
authMiddleware := auth.NewMiddleware(sessionSvc, userSvc, apiKeySvc, oauthProvider)
```

### Layer 4: Manual Testing (ngrok required for payments)

#### 6. Payment Flow

**Setup**:
1. Create LemonSqueezy account
2. Create product ($5/year)
3. Get API key and webhook secret
4. Configure webhook URL: `https://abc123.ngrok.app/webhooks/lemon`

**Test**:
```
□ Click "Upgrade" in web UI
□ Redirected to LemonSqueezy checkout
□ Use test card (4242 4242 4242 4242)
□ Complete payment
□ Webhook received, processed
□ User status updated to 'paid'
□ Rate limits increased
□ Storage limit removed
□ Subscription status shows "Active"
```

### Layer 5: Production Deployment

#### 7. Fly.io Setup

**fly.toml**:
```toml
app = "agent-notes"
primary_region = "iad"

[build]
  dockerfile = "Dockerfile"

[env]
  DATABASE_PATH = "/data"
  OAUTH_ISSUER = "https://notes.yourdomain.com"

[mounts]
  source = "agent_notes_data"
  destination = "/data"

[[services]]
  internal_port = 8080
  protocol = "tcp"

  [[services.ports]]
    handlers = ["http"]
    port = 80

  [[services.ports]]
    handlers = ["tls", "http"]
    port = 443

[checks]
  [checks.health]
    type = "http"
    path = "/health"
    interval = "10s"
    timeout = "2s"
```

**Dockerfile**:
```dockerfile
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o server ./cmd/server

FROM alpine:latest
RUN apk add --no-cache sqlite-libs ca-certificates
COPY --from=builder /app/server /server
COPY --from=builder /app/web /web
EXPOSE 8080
CMD ["/server"]
```

**Deploy Commands**:
```bash
# Create app
fly apps create agent-notes

# Create volume for SQLite
fly volumes create agent_notes_data --region iad --size 10

# Create Tigris storage
fly storage create

# Set secrets
fly secrets set \
  MASTER_KEY="$(openssl rand -hex 32)" \
  GOOGLE_CLIENT_ID="xxx" \
  GOOGLE_CLIENT_SECRET="xxx" \
  RESEND_API_KEY="re_xxx" \
  LEMON_API_KEY="xxx" \
  LEMON_WEBHOOK_SECRET="xxx" \
  AWS_ACCESS_KEY_ID="tid_xxx" \
  AWS_SECRET_ACCESS_KEY="tsec_xxx"

# Deploy
fly deploy

# Add custom domain
fly certs add notes.yourdomain.com
# Update DNS: CNAME notes.yourdomain.com → agent-notes.fly.dev
```

#### 8. Domain + DNS Setup

**Required DNS Records**:
```
# Main app
notes.yourdomain.com    CNAME   agent-notes.fly.dev

# Email verification (for Resend)
resend._domainkey       CNAME   (from Resend dashboard)
_dmarc                  TXT     "v=DMARC1; p=none"
```

**Update Configs for Production**:
```bash
OAUTH_ISSUER=https://notes.yourdomain.com
GOOGLE_REDIRECT_URL=https://notes.yourdomain.com/auth/google/callback
RESEND_FROM_EMAIL=noreply@yourdomain.com
PUBLIC_NOTES_URL=https://notes.yourdomain.com/public
```

---

## External Services Registration

| Service | URL | What You Need |
|---------|-----|---------------|
| **Fly.io** | https://fly.io/dashboard | Account, flyctl installed |
| **LemonSqueezy** | https://app.lemonsqueezy.com | Account, product created, API key, webhook secret |
| **Domain Registrar** | Namecheap/Cloudflare/etc | Domain name |
| **Google Cloud** | https://console.cloud.google.com | Update redirect URIs for production domain |
| **Resend** | https://resend.com | Verify production domain |

---

## Environment Variables (Production)

```bash
# ===== Core =====
MASTER_KEY=<64-char-hex-string>
DATABASE_PATH=/data
OAUTH_ISSUER=https://notes.yourdomain.com

# ===== Auth (Real) =====
USE_MOCK_OIDC=false
USE_MOCK_EMAIL=false
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxx
GOOGLE_REDIRECT_URL=https://notes.yourdomain.com/auth/google/callback
RESEND_API_KEY=re_xxx
RESEND_FROM_EMAIL=noreply@yourdomain.com

# ===== Payments =====
USE_MOCK_PAYMENT=false
LEMON_API_KEY=xxx
LEMON_WEBHOOK_SECRET=xxx
LEMON_STORE_ID=xxx
LEMON_PRODUCT_ID=xxx

# ===== Storage =====
USE_MOCK_STORAGE=false
AWS_ENDPOINT_URL_S3=https://fly.storage.tigris.dev
AWS_ACCESS_KEY_ID=tid_xxx
AWS_SECRET_ACCESS_KEY=tsec_xxx
BUCKET_NAME=agent-notes-public
PUBLIC_NOTES_URL=https://notes.yourdomain.com/public

# ===== Rate Limits =====
RATE_LIMIT_FREE_RPS=10
RATE_LIMIT_PAID_RPS=1000
```

---

## Dependencies to Add

```go
// go.mod additions for Milestone 5
require (
    github.com/NdoleStudio/lemonsqueezy-go v1.3.1         // Payments
)
```

---

## Expected File Structure

```
/home/kuitang/git/agent-notes/
├── internal/
│   ├── payment/                    # LemonSqueezy
│   │   ├── service.go              # Interface + mock
│   │   ├── lemonsqueezy.go         # Real implementation
│   │   ├── webhook.go              # Webhook handler
│   │   └── payment_test.go         # Tests
│   ├── auth/
│   │   └── apikeys.go              # API key management
│   └── notes/
│       └── limits.go               # Storage limits
├── web/
│   └── templates/
│       └── settings/
│           ├── api-keys.html       # API key management UI
│           └── subscription.html   # Subscription status UI
├── tests/
│   └── integration/
│       └── payment_test.go         # Payment integration tests
├── Dockerfile                       # Production build
├── fly.toml                         # Fly.io config
└── scripts/
    ├── milestone5-test.sh          # Master test script
    └── deploy.sh                   # Deployment helper
```

---

## Success Criteria

### Payments
- [ ] Checkout redirect works
- [ ] Webhook signature verified
- [ ] subscription_created updates user to paid
- [ ] subscription_cancelled updates user to free
- [ ] Subscription status shown in web UI

### API Keys
- [ ] Can create API key (shown once)
- [ ] Can list API keys (masked)
- [ ] Can revoke API key
- [ ] API key auth works for MCP/API

### Storage Limits
- [ ] Free users limited to 100MB
- [ ] Paid users unlimited
- [ ] 402 returned when limit exceeded

### Production
- [ ] Fly.io deploy succeeds
- [ ] Custom domain works with HTTPS
- [ ] Health checks pass
- [ ] All secrets configured
- [ ] SQLite volume persists across deploys

---

## Manual Testing Checklist

### Payment Flow (ngrok for webhooks)
```
□ Click "Upgrade to Pro" in web UI
□ Redirected to LemonSqueezy checkout
□ Complete with test card (4242 4242 4242 4242)
□ Webhook received (check server logs)
□ Subscription status shows "Pro"
□ Rate limits increased (verify with load test)
□ Storage limit removed
□ Cancel subscription in LemonSqueezy
□ Webhook received
□ Status reverts to "Free"
```

### API Keys
```
□ Go to Settings → API Keys
□ Click "Create API Key"
□ Key displayed (copy it!)
□ Key listed (masked: key_xxx...xxx)
□ Test: curl -H "Authorization: Bearer key_xxx" /api/notes
□ Works!
□ Revoke key
□ Test again → 401 Unauthorized
```

### Production Deploy
```
□ fly deploy succeeds
□ https://notes.yourdomain.com loads
□ Google OIDC redirect URL updated
□ Google login works
□ Magic link emails work
□ Notes persist across deploys
□ Payment webhooks work
□ Claude/ChatGPT can connect
```

---

## What's NOT in Milestone 5 (Future Work)

| Feature | Status |
|---------|--------|
| Multi-region deployment | Future (single region MVP) |
| Read replicas | Future (SQLite limitations) |
| Note versioning/history | Future (hard delete MVP) |
| Team/org support | Future (single user MVP) |
| Custom domains for public notes | Future |
| Analytics dashboard | Future |
| Mobile apps | Future |

---

## Commands to Execute

```bash
# Initialize goenv
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)"

# Install Milestone 5 dependencies
go get github.com/NdoleStudio/lemonsqueezy-go

# Run tests
./scripts/ci.sh quick

# Start with ngrok for webhook testing
ngrok http 8080 &
# Configure LemonSqueezy webhook to ngrok URL
go run ./cmd/server

# Deploy to production
fly deploy
fly secrets set MASTER_KEY="$(openssl rand -hex 32)"
# ... set other secrets ...
fly certs add notes.yourdomain.com
```

---

## Timeline Summary

| Phase | Content | Testing |
|-------|---------|---------|
| **M1** | CRUD + MCP | Automated |
| **M2** | Auth (mocks) | Automated |
| **M3** | Rate limits, UI, consent screens | Automated + Playwright |
| **M3.5** | OAuth 2.1 Provider | Local conformance tests |
| **M4** | Real auth (Google, Resend) | Manual (localhost) |
| **M5** | Payments, API keys, deploy | Manual (ngrok) + Production |

---

**After Milestone 5**: The service is live, users can pay, and AI clients can connect. Ship it!
