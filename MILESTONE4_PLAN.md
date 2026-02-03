# Milestone 4: Real Auth Integrations + Manual Testing

**Status**: COMPLETE

**Goal**: Replace mock implementations with real Google OIDC and Resend email. Manual testing to verify production-ready auth flows.

---

## What Was Implemented

### Layer 1: Real Service Integrations
1. **Real Google OIDC Client** (`internal/auth/oidc_google.go`) - Uses `github.com/coreos/go-oidc/v3`
2. **Real Resend Email Client** (`internal/email/resend.go`) - Uses `github.com/resend/resend-go/v3`
3. **Configuration System** - Environment-based switching between mock/real via `USE_MOCK_OIDC` and `USE_MOCK_EMAIL`

### Layer 2: Integration Wiring
4. **Server startup** (`cmd/server/main.go`) swaps mock/real based on env vars

### Layer 3: Manual Testing Results

#### TESTED AND WORKING
- **Google OIDC login**: User logged in with Google account successfully
- **Passwordless magic link**: User verified email was received via Resend (using `onboarding@resend.dev`)
- **Cross-auth-method linking**: Same email across Google and passwordless gives the same account (VERIFIED)

#### NOT MANUALLY TESTED
- **Sending emails from custom domain** (only `onboarding@resend.dev` was used; custom domain requires DNS verification in Resend)
- **Password reset email flow** (code is implemented but not manually tested end-to-end with real email)

### Additional Features Implemented (Beyond Original Plan)
- **PAT management UI** with one-time reveal (`/settings/tokens`, `/tokens`, `/tokens/new`)
- **URL shortener** (`/pub/{short_id}`) for public notes
- **Markdown rendering fix** (using gomarkdown + bluemonday sanitization)
- **Static pages**: privacy policy, terms of service, about page, API docs (`/privacy`, `/terms`, `/about`, `/docs/api`)
- **Branding to common.ink** across all templates, static pages, and email templates
- **Responsive design improvements** in web templates
- **mockoidc-based automated OIDC tests** (`tests/e2e/google_oidc_test.go`) using `github.com/oauth2-proxy/mockoidc`

---

## Secret Files (gitignored)

| File | Contents | Location |
|------|----------|----------|
| `google_secret.json` | Google OAuth client credentials (Client ID + Secret) | Project root |
| `resend_api_key.txt` | Resend API key for email sending | Project root |

These files are listed in `.gitignore` and must NOT be committed.

---

## Service Registration Reference

| Service | URL | What You Get |
|---------|-----|--------------|
| Google Cloud Console | https://console.cloud.google.com/apis/credentials | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| Resend | https://resend.com/api-keys | `RESEND_API_KEY` |

**No domain registration needed for localhost testing:**
- Google allows `http://localhost:*` redirect URIs
- Resend: Use `onboarding@resend.dev` as sender (no domain verification needed)

---

## Environment Variables

```
# Real Google OIDC
GOOGLE_CLIENT_ID=<from google_secret.json>
GOOGLE_CLIENT_SECRET=<from google_secret.json>
GOOGLE_REDIRECT_URL=http://localhost:8080/auth/google/callback

# Real Resend Email
RESEND_API_KEY=<from resend_api_key.txt>
RESEND_FROM_EMAIL=onboarding@resend.dev

# Toggle mock/real (default is mock)
USE_MOCK_OIDC=false   # set to use real Google
USE_MOCK_EMAIL=false   # set to use real Resend
```

---

## Success Criteria: Final Status

### Automated (CI - uses mocks)
- [x] All M2/M3 tests still pass
- [x] Real implementations compile without errors
- [x] Config loading works correctly
- [x] Graceful fallback to mocks when credentials missing

### Manual Testing (requires credentials)
- [x] Google OIDC login works with real Google
- [x] Magic link email received and works
- [ ] Password reset email received and works (NOT TESTED)
- [x] All three auth methods create sessions correctly
- [x] User data persists in database
- [x] Cross-auth-method linking works (same email = same account)

### Documentation
- [x] Setup instructions for Google Cloud Console (this file)
- [x] Setup instructions for Resend (this file)
- [x] Manual testing checklist documented

---

## What's Deferred to Later Milestones

**Milestone 5**: OAuth 2.1 Provider (for AI clients) - ngrok required
**Milestone 6**: Payments (LemonSqueezy)
