# Milestone 6: Email Confirmation, Payments, Production Hardening

**Goal**: Require email verification on registration, implement LemonSqueezy payments, harden production for real users.

**Prerequisites**: Milestone 5 complete (deployed to Fly.io, API keys working, custom domain).

---

## What This Milestone Covers

| Feature | Description | Priority |
|---------|-------------|----------|
| **Email Confirmation** | Require verification before account is active | P0 (security) |
| **Payments** | LemonSqueezy $5/year subscription | P1 |
| **Storage Limits** | 100MB free, unlimited paid | P1 |
| **Production Hardening** | Health milestone bump, www redirect, monitoring | P2 |

---

## Layer 0: Email Confirmation (P0 — Security Vulnerability)

### Problem
`RegisterWithPassword` creates an active account without verifying the email. Anyone can register with any email address.

### Design

**Flow**:
1. `POST /auth/register` → hash password, store account with `email_verified = false`
2. Send verification email via Resend with HMAC-signed token (same pattern as magic link)
3. User clicks `GET /auth/verify-email?token=xxx`
4. Token verified → set `email_verified = true`, create session, redirect to /notes
5. Unverified accounts cannot: create notes, access MCP, create API keys

**Schema change** (user DB `account` table):
```sql
ALTER TABLE account ADD COLUMN email_verified INTEGER DEFAULT 0;
```

**Token storage**: Reuse `magic_tokens` table in sessions.db (same HMAC-signed, SHA-256 hashed tokens).

**Resend template**: New `email_verification` template with "Verify your email" subject.

**Middleware enforcement**: Auth middleware checks `email_verified` flag. Unverified users get redirected to a "check your email" page with a resend button.

**Files to modify**:
- `internal/auth/user.go` — `RegisterWithPassword` sends verification email
- `internal/auth/handlers.go` — new `HandleVerifyEmail` endpoint, resend endpoint
- `internal/db/userdb/` — schema migration for `email_verified` column
- `internal/auth/middleware.go` — enforce verification check
- `web/templates/auth/verify-email.html` — "check your email" page

**Testing requirement**: Need Gmail CLI access (gogcli or similar) to read verification emails in e2e tests. For now, test with mock email service and verify token flow in property tests.

### Property Tests
- Roundtrip: register → verify token → account.email_verified == true
- Unverified user cannot access protected routes
- Expired token rejected
- Double-verification is idempotent

---

## Layer 1: Payments / LemonSqueezy (P1)

Same as MILESTONE5_PLAN.md Layer 1 Task 1. Deferred from M5 to focus on deployment.

---

## Layer 2: Storage Limits Enforcement (P1)

Same as MILESTONE5_PLAN.md Layer 2 Task 3. Depends on payments.

---

## Layer 3: Production Hardening (P2)

### Tasks
1. Bump `/health` milestone from 4 to 6
2. Add www.common.ink → common.ink redirect middleware
3. Set up Resend domain verification (SPF, DKIM, DMARC DNS records)
4. Configure Google OAuth for production redirect URI
5. Add structured logging (replace log.Printf with slog)
6. Add request ID middleware for tracing

---

## Gmail CLI for Testing

Need to set up authenticated Gmail access for reading verification/magic-link/reset emails in e2e tests. Options:
- `gogcli` — Google API CLI tool
- Google Apps Script + HTTP endpoint
- IMAP client in Go test code

This is a prerequisite for automated email flow testing.

---

## Success Criteria

### Email Confirmation
- [ ] Registration sends verification email
- [ ] Unverified users blocked from protected routes
- [ ] Verification link works and activates account
- [ ] Resend verification button works
- [ ] Property tests cover token roundtrip and expiry

### Payments
- [ ] LemonSqueezy checkout redirect
- [ ] Webhook signature verification
- [ ] Subscription status tracking

### Production
- [ ] Health endpoint shows milestone 6
- [ ] www redirect works
- [ ] Resend domain verified (emails from noreply@common.ink)
