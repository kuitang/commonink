package auth

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"pgregory.net/rapid"
)

// fakeClock is a controllable clock for testing time-dependent behavior.
type fakeClock struct {
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t}
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func drawMagicBaseTime(t *rapid.T, label string) time.Time {
	sec := rapid.Int64Range(946684800, 4102444800).Draw(t, label) // 2000-01-01 .. 2100-01-01 UTC
	return time.Unix(sec, 0).UTC()
}

// setupMagicTestService creates a UserService with a fake clock backed by a
// fresh in-memory sessions database. The caller controls time via the returned
// fakeClock.
func setupMagicTestService(t testing.TB) (*UserService, *fakeClock, *email.MockEmailService) {
	t.Helper()

	db.ResetForTesting()

	tmpDir := t.TempDir()
	db.DataDirectory = tmpDir

	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("failed to open sessions database: %v", err)
	}

	emailSvc := email.NewMockEmailService()
	masterKey := make([]byte, 32)
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)
	svc := NewUserService(sessionsDB, keyManager, emailSvc, "http://test.local", FakeInsecureHasher{})

	clk := newFakeClock(time.Now().UTC())
	svc.SetClock(clk)

	return svc, clk, emailSvc
}

func extractLinkFromEmailRT(t *rapid.T, emailSvc *email.MockEmailService, expectedTemplate string) *url.URL {
	last := emailSvc.LastEmail()
	if expectedTemplate != "" && last.Template != expectedTemplate {
		t.Fatalf("expected template %s, got %s", expectedTemplate, last.Template)
	}
	var link string
	switch data := last.Data.(type) {
	case email.MagicLinkData:
		if expectedTemplate != "" && expectedTemplate != "magic_link" {
			t.Fatalf("expected template %s, got magic_link", expectedTemplate)
		}
		link = data.Link
	case email.PasswordResetData:
		if expectedTemplate != "" && expectedTemplate != "password_reset" {
			t.Fatalf("expected template %s, got password_reset", expectedTemplate)
		}
		link = data.Link
	default:
		if expectedTemplate != "" && expectedTemplate != "none" {
			t.Fatalf("expected template %s but got unsupported payload: %T", expectedTemplate, last.Data)
		}
		t.Fatalf("unexpected email payload type: %T", last.Data)
	}
	if !strings.HasPrefix(link, "http://") && !strings.HasPrefix(link, "https://") {
		t.Fatalf("unexpected link format: %s", link)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("failed to parse link %s: %v", link, err)
	}
	return parsed
}

// extractTokenFromEmailRT pulls the raw token string from the last magic-link
// email captured by the mock email service. It parses the link query parameter.
// Uses *rapid.T for compatibility with property test callbacks.
func extractTokenFromEmailRT(t *rapid.T, emailSvc *email.MockEmailService) string {
	last := emailSvc.LastEmail()
	data, ok := last.Data.(email.MagicLinkData)
	if !ok {
		t.Fatalf("expected MagicLinkData, got %T", last.Data)
	}
	// Link format: http://test.local/auth/magic/verify?token=<TOKEN>
	const prefix = "http://test.local/auth/magic/verify?token="
	if len(data.Link) <= len(prefix) {
		t.Fatalf("unexpected link format: %s", data.Link)
	}
	return data.Link[len(prefix):]
}

func TestMagicAndResetLinks_AreHostAgnostic_Properties(t *testing.T) {
	svc, _, emailSvc := setupMagicTestService(t)
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		scheme := rapid.SampledFrom([]string{"http", "https"}).Draw(rt, "scheme")
		host := fmt.Sprintf(
			"%s.%s",
			rapid.StringMatching(`[a-z]{3,10}`).Draw(rt, "baseHost"),
			rapid.StringMatching(`[a-z]{2,8}`).Draw(rt, "baseTld"),
		)
		port := rapid.IntRange(1024, 65535).Draw(rt, "port")
		hasPort := rapid.Bool().Draw(rt, "hasPort")
		baseHost := host
		if hasPort {
			baseHost = fmt.Sprintf("%s:%d", host, port)
		}
		baseURL := fmt.Sprintf("%s://%s", scheme, baseHost)

		emailAddr := fmt.Sprintf("%s@%s", rapid.StringMatching(`[a-z]{3,12}`).Draw(rt, "name"), rapid.StringMatching(`[a-z]{2,6}`).Draw(rt, "domain"))

		emailSvc.Clear()
		if err := svc.SendMagicLink(ctx, emailAddr, baseURL); err != nil {
			rt.Fatalf("SendMagicLink failed: %v", err)
		}
		magicURL := extractLinkFromEmailRT(rt, emailSvc, "magic_link")
		if magicURL.Scheme != scheme {
			rt.Fatalf("magic link scheme mismatch: got=%s want=%s", magicURL.Scheme, scheme)
		}
		if magicURL.Host != baseHost {
			rt.Fatalf("magic link host mismatch: got=%s want=%s", magicURL.Host, baseHost)
		}
		if magicURL.Path != "/auth/magic/verify" {
			rt.Fatalf("magic link path mismatch: %s", magicURL.Path)
		}
		if magicURL.Query().Get("token") == "" {
			rt.Fatalf("magic link missing token")
		}

		emailSvc.Clear()
		if err := svc.SendPasswordReset(ctx, emailAddr, baseURL); err != nil {
			rt.Fatalf("SendPasswordReset failed: %v", err)
		}
		resetURL := extractLinkFromEmailRT(rt, emailSvc, "password_reset")
		if resetURL.Scheme != scheme {
			rt.Fatalf("password reset scheme mismatch: got=%s want=%s", resetURL.Scheme, scheme)
		}
		if resetURL.Host != baseHost {
			rt.Fatalf("password reset host mismatch: got=%s want=%s", resetURL.Host, baseHost)
		}
		if resetURL.Path != "/auth/password-reset-confirm" {
			rt.Fatalf("password reset path mismatch: %s", resetURL.Path)
		}
		if resetURL.Query().Get("token") == "" {
			rt.Fatalf("password reset missing token")
		}
	})
}

// TestMain resets the database singleton before/after all tests in this package.
func TestMain(m *testing.M) {
	code := m.Run()
	db.CloseAll()
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Property: token created < 15 min ago is VALID
// ---------------------------------------------------------------------------

func testMagicToken_ValidBeforeExpiry(t *rapid.T, svc *UserService, clk *fakeClock, emailSvc *email.MockEmailService) {
	// Generate a random duration strictly less than 15 minutes (in seconds).
	// Range: [0, 899] seconds = [0, 14m59s].
	advanceSec := rapid.Int64Range(0, int64(MagicTokenExpiry.Seconds())-1).Draw(t, "advanceSec")
	advance := time.Duration(advanceSec) * time.Second

	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")

	// Reset clock to a known base for this iteration.
	clk.now = drawMagicBaseTime(t, "baseUnixValidBefore")

	ctx := context.Background()
	if err := svc.SendMagicLink(ctx, emailAddr); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}

	token := extractTokenFromEmailRT(t, emailSvc)

	// Advance clock by the random duration (still within the 15-min window).
	clk.Advance(advance)

	user, err := svc.VerifyMagicToken(ctx, token)
	if err != nil {
		t.Fatalf("token should be valid after %v, got error: %v", advance, err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Email != emailAddr {
		t.Fatalf("expected email %q, got %q", emailAddr, user.Email)
	}
}

func TestMagicToken_ValidBeforeExpiry_Properties(t *testing.T) {
	svc, clk, emailSvc := setupMagicTestService(t)
	rapid.Check(t, func(t *rapid.T) {
		testMagicToken_ValidBeforeExpiry(t, svc, clk, emailSvc)
	})
}

func FuzzMagicToken_ValidBeforeExpiry_Properties(f *testing.F) {
	svc, clk, emailSvc := setupMagicTestService(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		testMagicToken_ValidBeforeExpiry(t, svc, clk, emailSvc)
	}))
}

// ---------------------------------------------------------------------------
// Property: token at exactly 15 min is INVALID (boundary)
// ---------------------------------------------------------------------------

func testMagicToken_InvalidAtExpiry(t *rapid.T, svc *UserService, clk *fakeClock, emailSvc *email.MockEmailService) {
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@boundary\.com`).Draw(t, "email")

	clk.now = drawMagicBaseTime(t, "baseUnixAtExpiry")

	ctx := context.Background()
	if err := svc.SendMagicLink(ctx, emailAddr); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}

	token := extractTokenFromEmailRT(t, emailSvc)

	// Advance clock to exactly the expiry boundary.
	clk.Advance(MagicTokenExpiry)

	_, err := svc.VerifyMagicToken(ctx, token)
	if err == nil {
		t.Fatal("token should be INVALID at exactly 15 min, but verification succeeded")
	}
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got: %v", err)
	}
}

func TestMagicToken_InvalidAtExpiry_Properties(t *testing.T) {
	svc, clk, emailSvc := setupMagicTestService(t)
	rapid.Check(t, func(t *rapid.T) {
		testMagicToken_InvalidAtExpiry(t, svc, clk, emailSvc)
	})
}

func FuzzMagicToken_InvalidAtExpiry_Properties(f *testing.F) {
	svc, clk, emailSvc := setupMagicTestService(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		testMagicToken_InvalidAtExpiry(t, svc, clk, emailSvc)
	}))
}

// ---------------------------------------------------------------------------
// Property: token older than 15 min is INVALID
// ---------------------------------------------------------------------------

func testMagicToken_InvalidAfterExpiry(t *rapid.T, svc *UserService, clk *fakeClock, emailSvc *email.MockEmailService) {
	// Generate a random duration strictly greater than 15 minutes.
	// Range: [901, 86400] seconds = (15m, 24h].
	advanceSec := rapid.Int64Range(int64(MagicTokenExpiry.Seconds())+1, 86400).Draw(t, "advanceSec")
	advance := time.Duration(advanceSec) * time.Second

	emailAddr := rapid.StringMatching(`[a-z]{5,10}@expired\.com`).Draw(t, "email")

	clk.now = drawMagicBaseTime(t, "baseUnixAfterExpiry")

	ctx := context.Background()
	if err := svc.SendMagicLink(ctx, emailAddr); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}

	token := extractTokenFromEmailRT(t, emailSvc)

	// Advance clock past the expiry window.
	clk.Advance(advance)

	_, err := svc.VerifyMagicToken(ctx, token)
	if err == nil {
		t.Fatalf("token should be INVALID after %v, but verification succeeded", advance)
	}
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got: %v", err)
	}
}

func TestMagicToken_InvalidAfterExpiry_Properties(t *testing.T) {
	svc, clk, emailSvc := setupMagicTestService(t)
	rapid.Check(t, func(t *rapid.T) {
		testMagicToken_InvalidAfterExpiry(t, svc, clk, emailSvc)
	})
}

func FuzzMagicToken_InvalidAfterExpiry_Properties(f *testing.F) {
	svc, clk, emailSvc := setupMagicTestService(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		testMagicToken_InvalidAfterExpiry(t, svc, clk, emailSvc)
	}))
}

// ---------------------------------------------------------------------------
// Property: token is consumed after single use (replay fails)
// ---------------------------------------------------------------------------

func testMagicToken_SingleUse(t *rapid.T, svc *UserService, clk *fakeClock, emailSvc *email.MockEmailService) {
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@replay\.com`).Draw(t, "email")

	clk.now = drawMagicBaseTime(t, "baseUnixSingleUse")

	ctx := context.Background()
	if err := svc.SendMagicLink(ctx, emailAddr); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}

	token := extractTokenFromEmailRT(t, emailSvc)

	// First verification should succeed.
	user, err := svc.VerifyMagicToken(ctx, token)
	if err != nil {
		t.Fatalf("first verification should succeed: %v", err)
	}
	if user.Email != emailAddr {
		t.Fatalf("expected email %q, got %q", emailAddr, user.Email)
	}

	// Second verification with the same token should fail.
	_, err = svc.VerifyMagicToken(ctx, token)
	if err == nil {
		t.Fatal("replay of consumed token should fail, but succeeded")
	}
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken on replay, got: %v", err)
	}
}

func TestMagicToken_SingleUse_Properties(t *testing.T) {
	svc, clk, emailSvc := setupMagicTestService(t)
	rapid.Check(t, func(t *rapid.T) {
		testMagicToken_SingleUse(t, svc, clk, emailSvc)
	})
}

func FuzzMagicToken_SingleUse_Properties(f *testing.F) {
	svc, clk, emailSvc := setupMagicTestService(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		testMagicToken_SingleUse(t, svc, clk, emailSvc)
	}))
}
