# Milestone 4: Real Auth Integrations + Manual Testing

**Goal**: Replace mock implementations with real Google OIDC and Resend email. Manual testing to verify production-ready auth flows. This is where you register for external services and domain names.

**Prerequisites**: Milestone 3 complete (rate limiting, public notes, web UI all working with mocks)

**Key Difference from M2/M3**: Real external services, requires registration/setup, manual testing required.

---

## What Needs to Be Registered

### 1. Google Cloud Console (for Google OIDC)

**Setup Steps**:
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create new project (or use existing)
3. Enable "Google+ API" or "Google Identity" API
4. Go to **APIs & Services → Credentials**
5. Click **Create Credentials → OAuth client ID**
6. Application type: **Web application**
7. Configure:
   - **Name**: "Remote Notes Dev" (or similar)
   - **Authorized JavaScript origins**: `http://localhost:8080`
   - **Authorized redirect URIs**: `http://localhost:8080/auth/google/callback`
8. Copy **Client ID** and **Client Secret**

**Important**: Google allows `http://localhost:*` for development - **NO ngrok needed for Google OIDC testing!**

**For Production** (later):
- Add production domain to authorized origins
- Add production callback URL to redirect URIs

### 2. Resend (for Email)

**Setup Steps**:
1. Go to [Resend Dashboard](https://resend.com/signup)
2. Create account
3. Go to **API Keys** → Create new key
4. Copy API key

**For Testing WITHOUT Domain Verification**:
- Use `onboarding@resend.dev` as the "From" address
- This works immediately, no DNS setup needed
- Emails will have "via resend.dev" branding

**For Production** (later):
- Go to **Domains** → Add your domain
- Add DNS records (TXT, CNAME) for verification
- Wait for verification (usually minutes)
- Use your domain in "From" address

### 3. Domain Name (Optional for M4, Required for Production)

- Register domain via Namecheap, Cloudflare, etc.
- Not needed for localhost testing
- Needed for: production deployment, verified email sending

---

## Implementation DAG

```
                    [Milestone 3 Complete]
                    (Mocks + UI working)
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
  [Google OIDC Impl]  [Resend Email Impl]  [Config System]
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                    [Integration Wiring]
                    (swap mocks for real)
                            │
              ┌─────────────┼─────────────┐
              │             │             │
      [Manual Test:    [Manual Test:   [Manual Test:
       Google Login]    Magic Link]     Password Reset]
              │             │             │
              └─────────────┼─────────────┘
                            │
                    [Automated Smoke Tests]
                    (real services, CI-optional)
                            │
                        [Document]
                            │
                        [Commit]
```

---

## Tasks

### Layer 1 (Parallel - No Dependencies)

1. **Real Google OIDC Client** (`internal/auth/oidc_google.go`)
   - Implements `OIDCClient` interface from M2
   - Uses `github.com/coreos/go-oidc/v3`
   - `NewGoogleOIDCClient(clientID, clientSecret, redirectURL)`
   - `GetAuthURL(state)` - Builds Google authorization URL
   - `ExchangeCode(ctx, code)` - Exchanges code for tokens, returns Claims

2. **Real Resend Email Client** (`internal/email/resend.go`)
   - Implements `EmailService` interface from M2
   - Uses `github.com/resend/resend-go/v3`
   - `NewResendEmailService(apiKey, fromAddress)`
   - `SendMagicLink(to, token)` - Sends magic login email
   - `SendPasswordReset(to, token)` - Sends password reset email
   - `SendWelcome(to, name)` - Sends welcome email
   - HTML templates from `internal/email/templates.go`

3. **Configuration System Enhancement** (`internal/config/config.go`)
   - Add real service configuration:
     ```go
     type Config struct {
         // From M2/M3
         MasterKey           string
         DatabasePath        string
         SessionDuration     time.Duration
         RateLimitConfig     ratelimit.Config

         // New for M4 - Real integrations
         UseMockOIDC         bool   // false in production
         UseMockEmail        bool   // false in production

         GoogleClientID      string
         GoogleClientSecret  string
         GoogleRedirectURL   string

         ResendAPIKey        string
         ResendFromEmail     string
     }
     ```
   - Environment-based loading with validation

### Layer 2 (Depends on Layer 1)

4. **Integration Wiring Update** (`cmd/server/main.go`)
   - Load config
   - Create real or mock services based on config:
     ```go
     var oidcClient auth.OIDCClient
     if cfg.UseMockOIDC {
         oidcClient = auth.NewMockOIDCClient()
     } else {
         oidcClient, err = auth.NewGoogleOIDCClient(
             cfg.GoogleClientID,
             cfg.GoogleClientSecret,
             cfg.GoogleRedirectURL,
         )
         if err != nil {
             log.Fatal("Failed to initialize Google OIDC:", err)
         }
     }

     var emailSvc email.EmailService
     if cfg.UseMockEmail {
         emailSvc = email.NewMockEmailService()
     } else {
         emailSvc = email.NewResendEmailService(
             cfg.ResendAPIKey,
             cfg.ResendFromEmail,
         )
     }
     ```

### Layer 3 (Manual Testing)

5. **Manual Test: Google Login**
   - Start server with real Google credentials
   - Open browser to `http://localhost:8080/login`
   - Click "Sign in with Google"
   - Complete Google consent flow
   - Verify: Redirected back to app, session cookie set, user created in DB

6. **Manual Test: Magic Link**
   - Start server with real Resend credentials
   - Open browser to `http://localhost:8080/login`
   - Enter real email address, click "Send Magic Link"
   - Check email inbox
   - Click link in email
   - Verify: Redirected to app, session cookie set

7. **Manual Test: Password Reset**
   - Create account with password
   - Click "Forgot Password"
   - Enter email, request reset
   - Check email inbox
   - Click reset link
   - Set new password
   - Verify: Can login with new password

### Layer 4 (Optional Automated Tests)

8. **Integration Smoke Tests** (`tests/integration/`)
   - Tests that run against real services
   - Skipped in normal CI (no credentials in CI)
   - Run manually before releases
   - Uses Resend test addresses (`delivered@resend.dev`)
   ```go
   func TestIntegration_ResendEmail(t *testing.T) {
       if os.Getenv("RESEND_API_KEY") == "" {
           t.Skip("RESEND_API_KEY not set, skipping integration test")
       }
       // ... test with real Resend
   }
   ```

---

## Does ngrok Work? When Is It Needed?

### ngrok NOT needed for M4:

| Service | Why Not Needed |
|---------|----------------|
| **Google OIDC** | Google allows `http://localhost:*` redirect URIs |
| **Resend Email** | Outbound API call, not a callback |
| **Password Auth** | Fully local |
| **Web UI** | All server-rendered |

### ngrok IS needed for M5 (OAuth Provider):

| Service | Why Needed |
|---------|------------|
| **OAuth 2.1 Provider** | ChatGPT/Claude need HTTPS to connect to YOUR server |
| **MCP over HTTPS** | AI clients require `https://` URLs |
| **Webhook callbacks** | LemonSqueezy webhooks (M6) |

---

## Manual Testing Checklist

### Google OIDC Login
```
□ Server started with GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET
□ Navigate to http://localhost:8080/login
□ Click "Sign in with Google"
□ Redirected to Google consent screen
□ Select Google account / grant consent
□ Redirected back to http://localhost:8080/auth/google/callback
□ Session cookie "session" is set (check DevTools → Application → Cookies)
□ User record created in database
□ Navigate to /notes - shows notes list
□ Subsequent visits maintain logged-in state
□ Logout clears session
□ After logout, /notes redirects to login
```

### Magic Link Login
```
□ Server started with RESEND_API_KEY and RESEND_FROM_EMAIL
□ Navigate to http://localhost:8080/login
□ Enter real email address in magic link form
□ Click "Send Magic Link"
□ "Check your email" message displayed
□ Email received in inbox (check spam folder)
□ Email has correct branding/styling
□ Email contains clickable link
□ Click link in email
□ Redirected to app, logged in
□ Session cookie set
□ Link cannot be reused (returns error on second click)
□ Expired link (after 15 min) returns error
```

### Password Registration + Login
```
□ Navigate to http://localhost:8080/register
□ Enter email and password
□ Password validation shown (min 8 chars)
□ Click "Register"
□ Account created
□ Redirected to login (or auto-logged in)
□ Navigate to http://localhost:8080/login
□ Enter email and password
□ Click "Sign In"
□ Logged in successfully
□ Wrong password shows error message
□ Non-existent email shows error message
```

### Password Reset
```
□ Have existing account with password
□ Navigate to login page
□ Click "Forgot Password"
□ Enter email address
□ Click "Send Reset Link"
□ "Check your email" message displayed
□ Email received with reset link
□ Click link in email
□ New password form displayed
□ Enter new password (with confirmation)
□ Password updated successfully
□ Can login with new password
□ Old password no longer works
□ Reset link cannot be reused
```

### Cross-Auth-Method Testing
```
□ Register with password → login with password ✓
□ Login with Google → same email gets same account
□ Request magic link → same email gets same account
□ All three methods work for same user
```

---

## File Structure Additions

```
/home/kuitang/git/agent-notes/
├── internal/
│   ├── auth/
│   │   ├── oidc.go             # Interface (from M2)
│   │   ├── oidc_mock.go        # Mock (from M2)
│   │   └── oidc_google.go      # NEW: Real Google OIDC
│   ├── email/
│   │   ├── service.go          # Interface (from M2)
│   │   ├── mock.go             # Mock (from M2)
│   │   └── resend.go           # NEW: Real Resend
│   └── config/
│       └── config.go           # Enhanced configuration
├── tests/
│   └── integration/
│       ├── google_test.go      # Real Google tests (skipped without creds)
│       └── resend_test.go      # Real Resend tests (skipped without creds)
└── docs/
    └── manual-testing.md       # Manual testing guide
```

---

## Environment Variables for Milestone 4

```bash
# ===== Real Services (NEW) =====

# Google OIDC (required for real Google login)
GOOGLE_CLIENT_ID=123456789-abcdef.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxxxxxxxxxxx
GOOGLE_REDIRECT_URL=http://localhost:8080/auth/google/callback

# Resend Email (required for real email sending)
RESEND_API_KEY=re_xxxxxxxxxxxx
RESEND_FROM_EMAIL=onboarding@resend.dev  # No domain verification needed
# Or after domain verification:
# RESEND_FROM_EMAIL=noreply@yourdomain.com

# ===== Mock Overrides (for development) =====
# Set these to use mocks instead of real services
USE_MOCK_OIDC=true
USE_MOCK_EMAIL=true

# ===== From Previous Milestones =====
MASTER_KEY=<64-char-hex>
DATABASE_PATH=/data
SESSION_DURATION=720h
```

---

## Dependencies to Add

```go
// go.mod additions for Milestone 4
require (
    github.com/coreos/go-oidc/v3 v3.17.0       // Real Google OIDC
    golang.org/x/oauth2 v0.23.0                // OAuth2 client (required by go-oidc)
    github.com/resend/resend-go/v3 v3.1.0      // Real Resend email
)
```

---

## Success Criteria

### Automated (CI - uses mocks)
- [ ] All M2/M3 tests still pass
- [ ] Real implementations compile without errors
- [ ] Config loading works correctly
- [ ] Graceful fallback to mocks when credentials missing

### Manual Testing (requires credentials)
- [ ] Google OIDC login works with real Google
- [ ] Magic link email received and works
- [ ] Password reset email received and works
- [ ] All three auth methods create sessions correctly
- [ ] User data persists in database
- [ ] Cross-auth-method linking works

### Documentation
- [ ] Setup instructions for Google Cloud Console
- [ ] Setup instructions for Resend
- [ ] Manual testing checklist documented

---

## What's Deferred to Later Milestones

**Milestone 5**: OAuth 2.1 Provider (for AI clients)
- ngrok required for testing
- Dynamic Client Registration
- PKCE flow
- Consent screen integration

**Milestone 6**: Payments (LemonSqueezy)

---

## Quick Reference: What to Register Where

| Service | URL | What You Get |
|---------|-----|--------------|
| Google Cloud Console | https://console.cloud.google.com/apis/credentials | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| Resend | https://resend.com/api-keys | `RESEND_API_KEY` |

**No domain registration needed for localhost testing!**
- Google: Allows localhost redirect URIs
- Resend: Use `onboarding@resend.dev` as sender

---

## Commands to Execute

```bash
# Initialize goenv
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)"

# Install Milestone 4 dependencies
go get github.com/coreos/go-oidc/v3
go get golang.org/x/oauth2
go get github.com/resend/resend-go/v3

# Set environment variables
export GOOGLE_CLIENT_ID="your-client-id"
export GOOGLE_CLIENT_SECRET="your-client-secret"
export GOOGLE_REDIRECT_URL="http://localhost:8080/auth/google/callback"
export RESEND_API_KEY="re_xxxx"
export RESEND_FROM_EMAIL="onboarding@resend.dev"

# Start server with real services
go run ./cmd/server

# Open browser for manual testing
open http://localhost:8080/login
```

---

## Milestone Summary

| Milestone | External Services | Manual Testing | ngrok |
|-----------|------------------|----------------|-------|
| M2 | Mocks only | No | No |
| M3 | Mocks only | No | No |
| **M4** | **Real Google + Resend** | **Yes** | No |
| M5 | Real + OAuth Provider | Yes | **Yes** |
| M6 | Real + LemonSqueezy | Yes | Yes (webhooks) |
