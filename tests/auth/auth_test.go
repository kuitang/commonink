package auth_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"pgregory.net/rapid"
)

// =============================================================================
// Test Setup Helpers
// =============================================================================

// testServices holds all the services needed for auth testing
type testServices struct {
	userSvc    *auth.UserService
	sessionSvc *auth.SessionService
	emailSvc   *email.MockEmailService
	oidcClient *auth.MockOIDCClient
}

// setupTestServices creates fresh instances of all auth services with mock dependencies.
// Each test gets isolated databases in a temp directory.
func setupTestServices(t *testing.T) *testServices {
	t.Helper()
	// Use temp directory for test database to ensure isolation
	db.DataDirectory = t.TempDir()
	db.ResetForTesting()

	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions DB: %v", err)
	}

	emailSvc := email.NewMockEmailService()
	oidcClient := auth.NewMockOIDCClient()
	userSvc := auth.NewUserService(sessionsDB, emailSvc, "http://test.local")
	sessionSvc := auth.NewSessionService(sessionsDB)

	return &testServices{
		userSvc:    userSvc,
		sessionSvc: sessionSvc,
		emailSvc:   emailSvc,
		oidcClient: oidcClient,
	}
}

// setupTestServicesF creates fresh instances for fuzz tests.
func setupTestServicesF(f *testing.F) *testServices {
	f.Helper()
	// Use temp directory for test database to ensure isolation
	db.DataDirectory = f.TempDir()
	db.ResetForTesting()

	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		f.Fatalf("Failed to open sessions DB: %v", err)
	}

	emailSvc := email.NewMockEmailService()
	oidcClient := auth.NewMockOIDCClient()
	userSvc := auth.NewUserService(sessionsDB, emailSvc, "http://test.local")
	sessionSvc := auth.NewSessionService(sessionsDB)

	return &testServices{
		userSvc:    userSvc,
		sessionSvc: sessionSvc,
		emailSvc:   emailSvc,
		oidcClient: oidcClient,
	}
}

// extractTokenFromMagicLink extracts the token from a magic link URL
func extractTokenFromMagicLink(link string) (string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", err
	}
	return u.Query().Get("token"), nil
}

// =============================================================================
// Property 1: Session Lifecycle
// Property: Create -> Validate returns userID -> Delete -> Validate fails
// =============================================================================

func TestAuth_SessionLifecycle_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		// Generate random email
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")

		// Create user
		user, err := svc.userSvc.FindOrCreateByEmail(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("FindOrCreateByEmail failed: %v", err)
		}

		// Create session
		sessionID, err := svc.sessionSvc.Create(ctx, user.ID)
		if err != nil {
			rt.Fatalf("Session create failed: %v", err)
		}

		// Property: Validate session returns correct user
		validatedUserID, err := svc.sessionSvc.Validate(ctx, sessionID)
		if err != nil {
			rt.Fatalf("Session validate failed: %v", err)
		}
		if validatedUserID != user.ID {
			rt.Fatalf("Validated user ID %s != original %s", validatedUserID, user.ID)
		}

		// Delete session
		if err := svc.sessionSvc.Delete(ctx, sessionID); err != nil {
			rt.Fatalf("Session delete failed: %v", err)
		}

		// Property: Validate should now fail
		_, err = svc.sessionSvc.Validate(ctx, sessionID)
		if err == nil {
			rt.Fatal("Session should be invalid after delete")
		}
	})
}

func FuzzAuth_SessionLifecycle_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")
		user, err := svc.userSvc.FindOrCreateByEmail(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("FindOrCreateByEmail failed: %v", err)
		}
		sessionID, err := svc.sessionSvc.Create(ctx, user.ID)
		if err != nil {
			rt.Fatalf("Session create failed: %v", err)
		}
		validatedUserID, err := svc.sessionSvc.Validate(ctx, sessionID)
		if err != nil {
			rt.Fatalf("Session validate failed: %v", err)
		}
		if validatedUserID != user.ID {
			rt.Fatalf("Validated user ID mismatch")
		}
		if err := svc.sessionSvc.Delete(ctx, sessionID); err != nil {
			rt.Fatalf("Session delete failed: %v", err)
		}
		_, err = svc.sessionSvc.Validate(ctx, sessionID)
		if err == nil {
			rt.Fatal("Session should be invalid after delete")
		}
	}))
}

// =============================================================================
// Property 2: Magic Link Flow
// Property: For any email, magic link is sent, captured by mock, and token verifies
// =============================================================================

func TestAuth_MagicLink_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		// Clear previous emails
		svc.emailSvc.Clear()

		// Generate random email
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")

		// Request magic link
		err := svc.userSvc.SendMagicLink(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("SendMagicLink failed: %v", err)
		}

		// Property: Email should be captured
		if svc.emailSvc.Count() == 0 {
			rt.Fatal("No email was sent")
		}

		lastEmail := svc.emailSvc.LastEmail()

		// Property: Email sent to correct address
		if lastEmail.To != emailAddr {
			rt.Fatalf("Email sent to wrong address: %s", lastEmail.To)
		}

		// Property: Correct template used
		if lastEmail.Template != email.TemplateMagicLink {
			rt.Fatalf("Wrong template: %s", lastEmail.Template)
		}

		// Extract token from email data
		data, ok := lastEmail.Data.(email.MagicLinkData)
		if !ok {
			rt.Fatal("Email data is not MagicLinkData")
		}

		// Extract token from link
		token, err := extractTokenFromMagicLink(data.Link)
		if err != nil {
			rt.Fatalf("Failed to parse magic link: %v", err)
		}
		if token == "" {
			rt.Fatal("Token is empty")
		}

		// Property: Verify token works and returns user with correct email
		user, err := svc.userSvc.VerifyMagicToken(ctx, token)
		if err != nil {
			rt.Fatalf("VerifyMagicToken failed: %v", err)
		}

		if user.Email != emailAddr {
			rt.Fatalf("User email %s != requested %s", user.Email, emailAddr)
		}
	})
}

func FuzzAuth_MagicLink_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		svc.emailSvc.Clear()
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")
		err := svc.userSvc.SendMagicLink(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("SendMagicLink failed: %v", err)
		}
		if svc.emailSvc.Count() == 0 {
			rt.Fatal("No email was sent")
		}
		lastEmail := svc.emailSvc.LastEmail()
		if lastEmail.To != emailAddr {
			rt.Fatalf("Email sent to wrong address")
		}
		data, ok := lastEmail.Data.(email.MagicLinkData)
		if !ok {
			rt.Fatal("Email data is not MagicLinkData")
		}
		token, _ := extractTokenFromMagicLink(data.Link)
		user, err := svc.userSvc.VerifyMagicToken(ctx, token)
		if err != nil {
			rt.Fatalf("VerifyMagicToken failed: %v", err)
		}
		if user.Email != emailAddr {
			rt.Fatalf("User email mismatch")
		}
	}))
}

// =============================================================================
// Property 3: Magic Link Single Use
// Property: Token can only be used once (consumed on first verify)
// =============================================================================

func TestAuth_MagicLink_SingleUse_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()
		svc.emailSvc.Clear()

		// Generate random email
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")

		// Request magic link
		err := svc.userSvc.SendMagicLink(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("SendMagicLink failed: %v", err)
		}

		// Extract token
		data := svc.emailSvc.LastEmail().Data.(email.MagicLinkData)
		token, _ := extractTokenFromMagicLink(data.Link)

		// First verification should succeed
		_, err = svc.userSvc.VerifyMagicToken(ctx, token)
		if err != nil {
			rt.Fatalf("First VerifyMagicToken should succeed: %v", err)
		}

		// Property: Second verification should fail (token consumed)
		_, err = svc.userSvc.VerifyMagicToken(ctx, token)
		if err == nil {
			rt.Fatal("Second VerifyMagicToken should fail - token should be consumed")
		}
	})
}

func FuzzAuth_MagicLink_SingleUse_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		svc.emailSvc.Clear()
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")
		_ = svc.userSvc.SendMagicLink(ctx, emailAddr)
		data := svc.emailSvc.LastEmail().Data.(email.MagicLinkData)
		token, _ := extractTokenFromMagicLink(data.Link)
		_, _ = svc.userSvc.VerifyMagicToken(ctx, token)
		_, err := svc.userSvc.VerifyMagicToken(ctx, token)
		if err == nil {
			rt.Fatal("Second VerifyMagicToken should fail")
		}
	}))
}

// =============================================================================
// Property 4: Password Hash Roundtrip
// Property: For any valid password, hash -> verify works
// =============================================================================

func TestAuth_Password_HashVerify_Roundtrip_Property(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate valid password (min 8 chars)
		password := rapid.StringN(8, 50, 100).Draw(rt, "password")

		// Hash
		hash, err := auth.HashPassword(password)
		if err != nil {
			rt.Fatalf("HashPassword failed: %v", err)
		}

		// Property: Verify returns true for correct password
		if !auth.VerifyPassword(password, hash) {
			rt.Fatal("Password verification failed for correct password")
		}
	})
}

func FuzzAuth_Password_HashVerify_Roundtrip_Property(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		password := rapid.StringN(8, 50, 100).Draw(rt, "password")
		hash, err := auth.HashPassword(password)
		if err != nil {
			rt.Fatalf("HashPassword failed: %v", err)
		}
		if !auth.VerifyPassword(password, hash) {
			rt.Fatal("Password verification failed")
		}
	}))
}

// =============================================================================
// Property 5: Password Wrong Password Fails
// Property: For any two different passwords, verify fails with wrong password
// =============================================================================

func TestAuth_Password_WrongPassword_Fails_Property(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate two distinct passwords
		password1 := rapid.StringN(8, 50, 100).Draw(rt, "password1")
		password2 := rapid.StringN(8, 50, 100).Filter(func(s string) bool {
			return s != password1
		}).Draw(rt, "password2")

		// Hash password1
		hash, err := auth.HashPassword(password1)
		if err != nil {
			rt.Fatalf("HashPassword failed: %v", err)
		}

		// Property: Verify should fail for password2
		if auth.VerifyPassword(password2, hash) {
			rt.Fatal("VerifyPassword should fail for wrong password")
		}
	})
}

func FuzzAuth_Password_WrongPassword_Fails_Property(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		password1 := rapid.StringN(8, 50, 100).Draw(rt, "password1")
		password2 := rapid.StringN(8, 50, 100).Filter(func(s string) bool {
			return s != password1
		}).Draw(rt, "password2")
		hash, _ := auth.HashPassword(password1)
		if auth.VerifyPassword(password2, hash) {
			rt.Fatal("VerifyPassword should fail for wrong password")
		}
	}))
}

// =============================================================================
// Property 6: Password Hash Non-Deterministic
// Property: Hashing same password twice produces different hashes (random salt)
// =============================================================================

func TestAuth_Password_Hash_NonDeterministic_Property(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		password := rapid.StringN(8, 50, 100).Draw(rt, "password")

		hash1, err := auth.HashPassword(password)
		if err != nil {
			rt.Fatalf("first HashPassword failed: %v", err)
		}

		hash2, err := auth.HashPassword(password)
		if err != nil {
			rt.Fatalf("second HashPassword failed: %v", err)
		}

		// Property: Different hashes (due to random salt)
		if hash1 == hash2 {
			rt.Fatal("Hashing is deterministic - salt is not random")
		}

		// Property: Both hashes still verify correctly
		if !auth.VerifyPassword(password, hash1) {
			rt.Fatal("First hash verification failed")
		}
		if !auth.VerifyPassword(password, hash2) {
			rt.Fatal("Second hash verification failed")
		}
	})
}

func FuzzAuth_Password_Hash_NonDeterministic_Property(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		password := rapid.StringN(8, 50, 100).Draw(rt, "password")
		hash1, _ := auth.HashPassword(password)
		hash2, _ := auth.HashPassword(password)
		if hash1 == hash2 {
			rt.Fatal("Hashing is deterministic")
		}
	}))
}

// =============================================================================
// Property 7: Password Validation - Weak Passwords Rejected
// Property: Passwords with fewer than 8 bytes are rejected
// =============================================================================

func TestAuth_Password_WeakPassword_Rejected_Property(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate short byte sequence (0-7 bytes)
		shortBytes := rapid.SliceOfN(rapid.Byte(), 0, 7).Draw(rt, "shortBytes")
		shortPassword := string(shortBytes)

		// Filter out cases where UTF-8 decoding results in 8+ chars
		if len(shortPassword) >= 8 {
			return // Skip this case
		}

		// Property: Short passwords should fail validation
		if err := auth.ValidatePasswordStrength(shortPassword); err == nil {
			rt.Fatalf("short password (len=%d) should fail validation", len(shortPassword))
		}
	})
}

func FuzzAuth_Password_WeakPassword_Rejected_Property(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		shortBytes := rapid.SliceOfN(rapid.Byte(), 0, 7).Draw(rt, "shortBytes")
		shortPassword := string(shortBytes)
		if len(shortPassword) >= 8 {
			return
		}
		if err := auth.ValidatePasswordStrength(shortPassword); err == nil {
			rt.Fatalf("short password should fail validation")
		}
	}))
}

// =============================================================================
// Property 8: Password Validation - Strong Passwords Accepted
// Property: Passwords with 8+ bytes are accepted
// =============================================================================

func TestAuth_Password_StrongPassword_Accepted_Property(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate valid password (8-100 bytes)
		validBytes := rapid.SliceOfN(rapid.Byte(), 8, 100).Draw(rt, "validBytes")
		validPassword := string(validBytes)

		// Property: Valid passwords should pass validation
		if err := auth.ValidatePasswordStrength(validPassword); err != nil {
			rt.Fatalf("valid password (len=%d) should pass validation: %v", len(validPassword), err)
		}
	})
}

func FuzzAuth_Password_StrongPassword_Accepted_Property(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		validBytes := rapid.SliceOfN(rapid.Byte(), 8, 100).Draw(rt, "validBytes")
		validPassword := string(validBytes)
		if err := auth.ValidatePasswordStrength(validPassword); err != nil {
			rt.Fatalf("valid password should pass validation: %v", err)
		}
	}))
}

// =============================================================================
// Property 9: Password Reset Flow
// Property: For any email, reset request -> email captured -> token works
// =============================================================================

func TestAuth_PasswordReset_Flow_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()
		svc.emailSvc.Clear()

		// Generate random email
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")

		// Request password reset
		err := svc.userSvc.SendPasswordReset(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("SendPasswordReset failed: %v", err)
		}

		// Property: Email should be captured
		if svc.emailSvc.Count() == 0 {
			rt.Fatal("No email was sent")
		}

		lastEmail := svc.emailSvc.LastEmail()

		// Property: Email sent to correct address
		if lastEmail.To != emailAddr {
			rt.Fatalf("Email sent to wrong address: %s", lastEmail.To)
		}

		// Property: Correct template used
		if lastEmail.Template != email.TemplatePasswordReset {
			rt.Fatalf("Wrong template: %s, expected %s", lastEmail.Template, email.TemplatePasswordReset)
		}

		// Extract token from email data
		data, ok := lastEmail.Data.(email.PasswordResetData)
		if !ok {
			rt.Fatal("Email data is not PasswordResetData")
		}

		// Extract token from link
		u, err := url.Parse(data.Link)
		if err != nil {
			rt.Fatalf("Failed to parse reset link: %v", err)
		}
		token := u.Query().Get("token")
		if token == "" {
			rt.Fatal("Token is empty")
		}

		// Generate new valid password
		newPassword := rapid.StringN(8, 50, 100).Draw(rt, "newPassword")

		// Property: Reset password with token should work
		err = svc.userSvc.ResetPassword(ctx, token, newPassword)
		if err != nil {
			rt.Fatalf("ResetPassword failed: %v", err)
		}
	})
}

func FuzzAuth_PasswordReset_Flow_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		svc.emailSvc.Clear()
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")
		_ = svc.userSvc.SendPasswordReset(ctx, emailAddr)
		if svc.emailSvc.Count() == 0 {
			rt.Fatal("No email was sent")
		}
		lastEmail := svc.emailSvc.LastEmail()
		data, _ := lastEmail.Data.(email.PasswordResetData)
		u, _ := url.Parse(data.Link)
		token := u.Query().Get("token")
		newPassword := rapid.StringN(8, 50, 100).Draw(rt, "newPassword")
		err := svc.userSvc.ResetPassword(ctx, token, newPassword)
		if err != nil {
			rt.Fatalf("ResetPassword failed: %v", err)
		}
	}))
}

// =============================================================================
// Property 10: Password Reset Token Single Use
// Property: Reset token can only be used once
// =============================================================================

func TestAuth_PasswordReset_SingleUse_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()
		svc.emailSvc.Clear()

		// Generate random email
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")

		// Request password reset
		err := svc.userSvc.SendPasswordReset(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("SendPasswordReset failed: %v", err)
		}

		// Extract token
		data := svc.emailSvc.LastEmail().Data.(email.PasswordResetData)
		u, _ := url.Parse(data.Link)
		token := u.Query().Get("token")

		newPassword1 := rapid.StringN(8, 50, 100).Draw(rt, "newPassword1")
		newPassword2 := rapid.StringN(8, 50, 100).Draw(rt, "newPassword2")

		// First reset should succeed
		err = svc.userSvc.ResetPassword(ctx, token, newPassword1)
		if err != nil {
			rt.Fatalf("First ResetPassword should succeed: %v", err)
		}

		// Property: Second reset should fail (token consumed)
		err = svc.userSvc.ResetPassword(ctx, token, newPassword2)
		if err == nil {
			rt.Fatal("Second ResetPassword should fail - token should be consumed")
		}
	})
}

func FuzzAuth_PasswordReset_SingleUse_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		svc.emailSvc.Clear()
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")
		_ = svc.userSvc.SendPasswordReset(ctx, emailAddr)
		data := svc.emailSvc.LastEmail().Data.(email.PasswordResetData)
		u, _ := url.Parse(data.Link)
		token := u.Query().Get("token")
		newPassword1 := rapid.StringN(8, 50, 100).Draw(rt, "newPassword1")
		newPassword2 := rapid.StringN(8, 50, 100).Draw(rt, "newPassword2")
		_ = svc.userSvc.ResetPassword(ctx, token, newPassword1)
		err := svc.userSvc.ResetPassword(ctx, token, newPassword2)
		if err == nil {
			rt.Fatal("Second ResetPassword should fail")
		}
	}))
}

// =============================================================================
// Property 11: Password Reset Weak Password Rejected
// Property: Reset with weak password is rejected
// =============================================================================

func TestAuth_PasswordReset_WeakPassword_Rejected_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()
		svc.emailSvc.Clear()

		// Generate random email
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")

		// Request password reset
		err := svc.userSvc.SendPasswordReset(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("SendPasswordReset failed: %v", err)
		}

		// Extract token
		data := svc.emailSvc.LastEmail().Data.(email.PasswordResetData)
		u, _ := url.Parse(data.Link)
		token := u.Query().Get("token")

		// Generate weak password (0-7 bytes)
		weakBytes := rapid.SliceOfN(rapid.Byte(), 0, 7).Draw(rt, "weakBytes")
		weakPassword := string(weakBytes)
		if len(weakPassword) >= 8 {
			return // Skip this case
		}

		// Property: Reset with weak password should fail
		err = svc.userSvc.ResetPassword(ctx, token, weakPassword)
		if err == nil {
			rt.Fatal("ResetPassword with weak password should fail")
		}
	})
}

func FuzzAuth_PasswordReset_WeakPassword_Rejected_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		svc.emailSvc.Clear()
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")
		_ = svc.userSvc.SendPasswordReset(ctx, emailAddr)
		data := svc.emailSvc.LastEmail().Data.(email.PasswordResetData)
		u, _ := url.Parse(data.Link)
		token := u.Query().Get("token")
		weakBytes := rapid.SliceOfN(rapid.Byte(), 0, 7).Draw(rt, "weakBytes")
		weakPassword := string(weakBytes)
		if len(weakPassword) >= 8 {
			return
		}
		err := svc.userSvc.ResetPassword(ctx, token, weakPassword)
		if err == nil {
			rt.Fatal("ResetPassword with weak password should fail")
		}
	}))
}

// =============================================================================
// Property 12: Same Email = Same User ID
// Property: Different auth methods with same email produce same user ID
// =============================================================================

func TestAuth_SameEmail_SameUser_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		// Generate random email
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")

		// Create user via first call
		user1, err := svc.userSvc.FindOrCreateByEmail(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("First FindOrCreateByEmail failed: %v", err)
		}

		// Create user via second call with same email
		user2, err := svc.userSvc.FindOrCreateByEmail(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("Second FindOrCreateByEmail failed: %v", err)
		}

		// Property: Same email produces same user ID (idempotence)
		if user1.ID != user2.ID {
			rt.Fatalf("Same email produced different user IDs: %s vs %s", user1.ID, user2.ID)
		}

		// Property: Email is preserved
		if user1.Email != emailAddr || user2.Email != emailAddr {
			rt.Fatalf("User email doesn't match: expected %s, got %s / %s", emailAddr, user1.Email, user2.Email)
		}
	})
}

func FuzzAuth_SameEmail_SameUser_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")
		user1, _ := svc.userSvc.FindOrCreateByEmail(ctx, emailAddr)
		user2, _ := svc.userSvc.FindOrCreateByEmail(ctx, emailAddr)
		if user1.ID != user2.ID {
			rt.Fatalf("Same email produced different user IDs")
		}
	}))
}

// =============================================================================
// Property 13: Different Emails = Different Users
// Property: Different emails produce different user IDs
// =============================================================================

func TestAuth_DifferentEmails_DifferentUsers_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		// Generate two different emails
		email1 := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email1")
		email2 := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Filter(func(s string) bool {
			return s != email1
		}).Draw(rt, "email2")

		user1, err := svc.userSvc.FindOrCreateByEmail(ctx, email1)
		if err != nil {
			rt.Fatalf("FindOrCreateByEmail for email1 failed: %v", err)
		}

		user2, err := svc.userSvc.FindOrCreateByEmail(ctx, email2)
		if err != nil {
			rt.Fatalf("FindOrCreateByEmail for email2 failed: %v", err)
		}

		// Property: Different emails produce different user IDs
		if user1.ID == user2.ID {
			rt.Fatalf("Different emails produced same user ID: %s (emails: %s, %s)", user1.ID, email1, email2)
		}
	})
}

func FuzzAuth_DifferentEmails_DifferentUsers_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		email1 := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email1")
		email2 := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Filter(func(s string) bool {
			return s != email1
		}).Draw(rt, "email2")
		user1, _ := svc.userSvc.FindOrCreateByEmail(ctx, email1)
		user2, _ := svc.userSvc.FindOrCreateByEmail(ctx, email2)
		if user1.ID == user2.ID {
			rt.Fatalf("Different emails produced same user ID")
		}
	}))
}

// =============================================================================
// Property 14: Google Login Flow
// Property: For any valid claims, login creates a session and user
// =============================================================================

func TestAuth_GoogleLogin_Flow_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		// Generate random OIDC claims
		sub := rapid.StringMatching(`[0-9]{10,20}`).Draw(rt, "googleSub")
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@gmail\.com`).Draw(rt, "email")
		name := rapid.StringMatching(`[A-Z][a-z]{3,10} [A-Z][a-z]{3,10}`).Draw(rt, "name")

		// Configure mock OIDC to return success
		svc.oidcClient.SetNextSuccess(sub, emailAddr, name, true)

		// Simulate auth URL generation
		state := rapid.StringMatching(`[a-zA-Z0-9]{16}`).Draw(rt, "state")
		authURL := svc.oidcClient.GetAuthURL(state)

		// Property: Auth URL contains state
		if !strings.Contains(authURL, state) {
			rt.Fatalf("Auth URL should contain state: %s", authURL)
		}

		// Property: State is captured
		if svc.oidcClient.LastState != state {
			rt.Fatalf("State not captured: expected %s, got %s", state, svc.oidcClient.LastState)
		}

		// Simulate code exchange
		code := rapid.StringMatching(`[a-zA-Z0-9]{32}`).Draw(rt, "code")
		claims, err := svc.oidcClient.ExchangeCode(ctx, code)
		if err != nil {
			rt.Fatalf("ExchangeCode failed: %v", err)
		}

		// Property: Code is captured
		if svc.oidcClient.LastCode != code {
			rt.Fatalf("Code not captured: expected %s, got %s", code, svc.oidcClient.LastCode)
		}

		// Property: Claims match configured values
		if claims.Sub != sub {
			rt.Fatalf("Sub mismatch: expected %s, got %s", sub, claims.Sub)
		}
		if claims.Email != emailAddr {
			rt.Fatalf("Email mismatch: expected %s, got %s", emailAddr, claims.Email)
		}
		if claims.Name != name {
			rt.Fatalf("Name mismatch: expected %s, got %s", name, claims.Name)
		}
		if !claims.EmailVerified {
			rt.Fatal("EmailVerified should be true")
		}

		// Create user from claims
		user, err := svc.userSvc.FindOrCreateByEmail(ctx, claims.Email)
		if err != nil {
			rt.Fatalf("FindOrCreateByEmail failed: %v", err)
		}

		// Create session for user
		sessionID, err := svc.sessionSvc.Create(ctx, user.ID)
		if err != nil {
			rt.Fatalf("Session create failed: %v", err)
		}

		// Property: Session is valid and returns correct user
		validatedUserID, err := svc.sessionSvc.Validate(ctx, sessionID)
		if err != nil {
			rt.Fatalf("Session validate failed: %v", err)
		}
		if validatedUserID != user.ID {
			rt.Fatalf("Validated user ID %s != expected %s", validatedUserID, user.ID)
		}
	})
}

func FuzzAuth_GoogleLogin_Flow_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		sub := rapid.StringMatching(`[0-9]{10,20}`).Draw(rt, "googleSub")
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@gmail\.com`).Draw(rt, "email")
		name := rapid.StringMatching(`[A-Z][a-z]{3,10} [A-Z][a-z]{3,10}`).Draw(rt, "name")
		svc.oidcClient.SetNextSuccess(sub, emailAddr, name, true)
		state := rapid.StringMatching(`[a-zA-Z0-9]{16}`).Draw(rt, "state")
		_ = svc.oidcClient.GetAuthURL(state)
		code := rapid.StringMatching(`[a-zA-Z0-9]{32}`).Draw(rt, "code")
		claims, _ := svc.oidcClient.ExchangeCode(ctx, code)
		user, _ := svc.userSvc.FindOrCreateByEmail(ctx, claims.Email)
		sessionID, _ := svc.sessionSvc.Create(ctx, user.ID)
		validatedUserID, err := svc.sessionSvc.Validate(ctx, sessionID)
		if err != nil {
			rt.Fatalf("Session validate failed: %v", err)
		}
		if validatedUserID != user.ID {
			rt.Fatalf("Validated user ID mismatch")
		}
	}))
}

// =============================================================================
// Property 15: Google Login Error Handling
// Property: When OIDC returns an error, no user or session is created
// =============================================================================

func TestAuth_GoogleLogin_Error_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		// Configure mock OIDC to return error
		svc.oidcClient.SetNextError(auth.ErrCodeExchangeFailed)

		// Simulate code exchange
		code := rapid.StringMatching(`[a-zA-Z0-9]{32}`).Draw(rt, "code")
		_, err := svc.oidcClient.ExchangeCode(ctx, code)

		// Property: Should fail with the configured error
		if err == nil {
			rt.Fatal("ExchangeCode should fail when error is configured")
		}
		if err != auth.ErrCodeExchangeFailed {
			rt.Fatalf("Unexpected error: %v", err)
		}
	})
}

func FuzzAuth_GoogleLogin_Error_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		svc.oidcClient.SetNextError(auth.ErrCodeExchangeFailed)
		code := rapid.StringMatching(`[a-zA-Z0-9]{32}`).Draw(rt, "code")
		_, err := svc.oidcClient.ExchangeCode(ctx, code)
		if err == nil {
			rt.Fatal("ExchangeCode should fail when error is configured")
		}
	}))
}

// =============================================================================
// Property 16: Session IDs are Unique
// Property: Multiple sessions for same user have different IDs
// =============================================================================

func TestAuth_Session_UniqueIDs_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		// Generate random email
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")

		// Create user
		user, err := svc.userSvc.FindOrCreateByEmail(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("FindOrCreateByEmail failed: %v", err)
		}

		// Create multiple sessions
		numSessions := rapid.IntRange(2, 10).Draw(rt, "numSessions")
		sessionIDs := make(map[string]bool)

		for i := 0; i < numSessions; i++ {
			sessionID, err := svc.sessionSvc.Create(ctx, user.ID)
			if err != nil {
				rt.Fatalf("Session create %d failed: %v", i, err)
			}

			// Property: Session ID should be unique
			if sessionIDs[sessionID] {
				rt.Fatalf("Duplicate session ID: %s", sessionID)
			}
			sessionIDs[sessionID] = true
		}

		// Property: All sessions created
		if len(sessionIDs) != numSessions {
			rt.Fatalf("Expected %d unique sessions, got %d", numSessions, len(sessionIDs))
		}
	})
}

func FuzzAuth_Session_UniqueIDs_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")
		user, _ := svc.userSvc.FindOrCreateByEmail(ctx, emailAddr)
		numSessions := rapid.IntRange(2, 10).Draw(rt, "numSessions")
		sessionIDs := make(map[string]bool)
		for i := 0; i < numSessions; i++ {
			sessionID, _ := svc.sessionSvc.Create(ctx, user.ID)
			if sessionIDs[sessionID] {
				rt.Fatalf("Duplicate session ID")
			}
			sessionIDs[sessionID] = true
		}
	}))
}

// =============================================================================
// Property 17: Delete All Sessions By User
// Property: DeleteByUserID removes all sessions for a user
// =============================================================================

func TestAuth_Session_DeleteByUser_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		// Generate random email
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")

		// Create user
		user, err := svc.userSvc.FindOrCreateByEmail(ctx, emailAddr)
		if err != nil {
			rt.Fatalf("FindOrCreateByEmail failed: %v", err)
		}

		// Create multiple sessions
		numSessions := rapid.IntRange(2, 5).Draw(rt, "numSessions")
		sessionIDs := make([]string, 0, numSessions)

		for i := 0; i < numSessions; i++ {
			sessionID, err := svc.sessionSvc.Create(ctx, user.ID)
			if err != nil {
				rt.Fatalf("Session create %d failed: %v", i, err)
			}
			sessionIDs = append(sessionIDs, sessionID)
		}

		// Delete all sessions for user
		if err := svc.sessionSvc.DeleteByUserID(ctx, user.ID); err != nil {
			rt.Fatalf("DeleteByUserID failed: %v", err)
		}

		// Property: All sessions should be invalid
		for _, sessionID := range sessionIDs {
			_, err := svc.sessionSvc.Validate(ctx, sessionID)
			if err == nil {
				rt.Fatalf("Session %s should be invalid after DeleteByUserID", sessionID)
			}
		}
	})
}

func FuzzAuth_Session_DeleteByUser_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(rt, "email")
		user, _ := svc.userSvc.FindOrCreateByEmail(ctx, emailAddr)
		numSessions := rapid.IntRange(2, 5).Draw(rt, "numSessions")
		sessionIDs := make([]string, 0, numSessions)
		for i := 0; i < numSessions; i++ {
			sessionID, _ := svc.sessionSvc.Create(ctx, user.ID)
			sessionIDs = append(sessionIDs, sessionID)
		}
		_ = svc.sessionSvc.DeleteByUserID(ctx, user.ID)
		for _, sessionID := range sessionIDs {
			_, err := svc.sessionSvc.Validate(ctx, sessionID)
			if err == nil {
				rt.Fatalf("Session should be invalid after DeleteByUserID")
			}
		}
	}))
}

// =============================================================================
// Property 18: Invalid Token Rejected
// Property: Random tokens are rejected
// =============================================================================

func TestAuth_MagicToken_Invalid_Rejected_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		// Generate random token (not a real magic token)
		invalidToken := rapid.StringN(20, 60, 100).Draw(rt, "invalidToken")

		// Property: Invalid token should be rejected
		_, err := svc.userSvc.VerifyMagicToken(ctx, invalidToken)
		if err == nil {
			rt.Fatal("Invalid token should be rejected")
		}
	})
}

func FuzzAuth_MagicToken_Invalid_Rejected_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		invalidToken := rapid.StringN(20, 60, 100).Draw(rt, "invalidToken")
		_, err := svc.userSvc.VerifyMagicToken(ctx, invalidToken)
		if err == nil {
			rt.Fatal("Invalid token should be rejected")
		}
	}))
}

// =============================================================================
// Property 19: Invalid Session Rejected
// Property: Random session IDs are rejected
// =============================================================================

func TestAuth_Session_Invalid_Rejected_Property(t *testing.T) {
	svc := setupTestServices(t)
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		// Generate random session ID (not a real session)
		invalidSessionID := rapid.StringN(20, 60, 100).Draw(rt, "invalidSessionID")

		// Property: Invalid session should be rejected
		_, err := svc.sessionSvc.Validate(ctx, invalidSessionID)
		if err == nil {
			rt.Fatal("Invalid session should be rejected")
		}
	})
}

func FuzzAuth_Session_Invalid_Rejected_Property(f *testing.F) {
	svc := setupTestServicesF(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ctx := context.Background()
		invalidSessionID := rapid.StringN(20, 60, 100).Draw(rt, "invalidSessionID")
		_, err := svc.sessionSvc.Validate(ctx, invalidSessionID)
		if err == nil {
			rt.Fatal("Invalid session should be rejected")
		}
	}))
}

// =============================================================================
// Property 20: OIDC Mock Reset
// Property: Reset clears all state
// =============================================================================

func TestAuth_OIDC_Reset_Property(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		oidcClient := auth.NewMockOIDCClient()

		// Set up some state
		sub := rapid.StringMatching(`[0-9]{10}`).Draw(rt, "sub")
		emailAddr := rapid.StringMatching(`[a-z]{5}@test\.com`).Draw(rt, "email")
		oidcClient.SetNextSuccess(sub, emailAddr, "Test User", true)
		oidcClient.GetAuthURL("test-state")
		_, _ = oidcClient.ExchangeCode(context.Background(), "test-code")

		// Reset
		oidcClient.Reset()

		// Property: All state should be cleared
		if oidcClient.NextClaims != nil {
			rt.Fatal("NextClaims should be nil after reset")
		}
		if oidcClient.NextError != nil {
			rt.Fatal("NextError should be nil after reset")
		}
		if oidcClient.LastState != "" {
			rt.Fatal("LastState should be empty after reset")
		}
		if oidcClient.LastCode != "" {
			rt.Fatal("LastCode should be empty after reset")
		}
	})
}

func FuzzAuth_OIDC_Reset_Property(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		oidcClient := auth.NewMockOIDCClient()
		sub := rapid.StringMatching(`[0-9]{10}`).Draw(rt, "sub")
		emailAddr := rapid.StringMatching(`[a-z]{5}@test\.com`).Draw(rt, "email")
		oidcClient.SetNextSuccess(sub, emailAddr, "Test User", true)
		oidcClient.GetAuthURL("test-state")
		_, _ = oidcClient.ExchangeCode(context.Background(), "test-code")
		oidcClient.Reset()
		if oidcClient.NextClaims != nil {
			rt.Fatal("NextClaims should be nil after reset")
		}
	}))
}
