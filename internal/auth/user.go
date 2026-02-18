package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	stdtime "time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/sessions"
	"github.com/kuitang/agent-notes/internal/db/userdb"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/urlutil"
)

// Errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountExists      = errors.New("account already exists")
	ErrWeakPassword       = errors.New("password must be at least 8 characters")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrGoogleSubMismatch  = errors.New("google sub mismatch: possible email takeover attempt")
)

// PasswordHasher abstracts password hashing for dependency injection.
// Production uses Argon2Hasher; tests use FakeInsecureHasher.
type PasswordHasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, encodedHash string) bool
}

// Argon2Hasher implements PasswordHasher using Argon2id.
type Argon2Hasher struct{}

func (Argon2Hasher) HashPassword(password string) (string, error) {
	return HashPassword(password)
}

func (Argon2Hasher) VerifyPassword(password, encodedHash string) bool {
	return VerifyPassword(password, encodedHash)
}

// Argon2id parameters (OWASP second recommendation: m=19456, t=2, p=1)
// Reduced from 64 MiB to ~19 MiB to avoid OOM on 256 MB Fly.io VMs.
// Parameters are embedded in each hash string, so existing 64 MiB hashes
// still verify correctly — only new hashes use these lighter params.
const (
	argon2Time    = 2
	argon2Memory  = 19 * 1024 // ~19 MiB (OWASP lighter alternative)
	argon2Threads = 1
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// Token expiry
const (
	MagicTokenExpiry = 15 * stdtime.Minute
)

// Clock abstracts time for testability.
type Clock interface {
	Now() stdtime.Time
}

// realClock implements Clock using the real system stdtime.
type realClock struct{}

func (realClock) Now() stdtime.Time { return stdtime.Now() }

// User represents a user account.
type User struct {
	ID                 string
	Email              string
	Name               string
	GoogleSub          string // Google OIDC subject ID if linked
	SubscriptionStatus string // "free", "active", "past_due", "canceled"
	StripeCustomerID   string
	CreatedAt          stdtime.Time
}

// UserService handles user management operations.
type UserService struct {
	db           *db.SessionsDB
	keyManager   *crypto.KeyManager
	emailService email.EmailService
	hasher       PasswordHasher
	baseURL      string // Base URL for magic link generation
	clock        Clock  // Clock for time operations (defaults to real time)
}

// NewUserService creates a new user service.
func NewUserService(sessionsDB *db.SessionsDB, keyManager *crypto.KeyManager, emailSvc email.EmailService, baseURL string, hasher PasswordHasher) *UserService {
	return &UserService{
		db:           sessionsDB,
		keyManager:   keyManager,
		emailService: emailSvc,
		hasher:       hasher,
		baseURL:      baseURL,
		clock:        realClock{},
	}
}

// VerifyPasswordHash delegates to the injected hasher.
func (s *UserService) VerifyPasswordHash(password, encodedHash string) bool {
	return s.hasher.VerifyPassword(password, encodedHash)
}

// SetClock replaces the clock used by the service. Intended for testing.
func (s *UserService) SetClock(c Clock) {
	s.clock = c
}

// RegisterWithPassword creates a new account with email/password.
// Returns ErrAccountExists if an account record already exists in the user DB.
// Handles orphaned DEKs (DEK exists but no account record) by creating the account.
func (s *UserService) RegisterWithPassword(ctx context.Context, emailAddr, password string) (*User, error) {
	regStart := stdtime.Now()
	userID := generateUserID(emailAddr)

	// Get or create DEK (idempotent — safe even if DEK already exists)
	dekStart := stdtime.Now()
	dek, err := s.keyManager.GetOrCreateUserDEK(userID)
	if err != nil {
		return nil, fmt.Errorf("get or create user DEK: %w", err)
	}
	log.Printf("[REGISTER] GetOrCreateUserDEK took %s", stdtime.Since(dekStart))

	// Open user DB
	dbStart := stdtime.Now()
	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return nil, fmt.Errorf("open user DB: %w", err)
	}
	log.Printf("[REGISTER] OpenUserDBWithDEK took %s", stdtime.Since(dbStart))

	// Check if account record actually exists (not just DEK)
	_, err = userDB.Queries().GetAccountByEmail(ctx, emailAddr)
	if err == nil {
		return nil, ErrAccountExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("check account existence: %w", err)
	}

	// Hash password
	passwordHash, err := s.hasher.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// Create account record in user DB
	now := s.clock.Now()
	err = userDB.Queries().CreateAccount(ctx, userdb.CreateAccountParams{
		UserID:             userID,
		Email:              emailAddr,
		PasswordHash:       sql.NullString{String: passwordHash, Valid: true},
		CreatedAt:          now.Unix(),
		SubscriptionStatus: sql.NullString{String: "free", Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("create account: %w", err)
	}

	// Check and apply any pending subscription (Milestone 2g)
	user := &User{
		ID:                 userID,
		Email:              emailAddr,
		SubscriptionStatus: "free",
		CreatedAt:          now,
	}
	if pendingStatus, pendingCustID, _ := s.applyPendingSubscription(ctx, userDB, userID, emailAddr); pendingStatus != "" {
		user.SubscriptionStatus = pendingStatus
		user.StripeCustomerID = pendingCustID
	}

	log.Printf("[REGISTER] Total RegisterWithPassword took %s", stdtime.Since(regStart))
	return user, nil
}

// VerifyLogin verifies email/password credentials for an existing account.
// Returns ErrInvalidCredentials if user doesn't exist or password is wrong.
func (s *UserService) VerifyLogin(ctx context.Context, emailAddr, password string) (*User, error) {
	loginStart := stdtime.Now()
	userID := generateUserID(emailAddr)

	// Check if user exists (has a DEK)
	dekStart := stdtime.Now()
	dek, err := s.keyManager.GetUserDEK(userID)
	if err != nil {
		if errors.Is(err, crypto.ErrUserKeyNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get user DEK: %w", err)
	}
	log.Printf("[LOGIN] GetUserDEK took %s", stdtime.Since(dekStart))

	// Open user DB
	dbStart := stdtime.Now()
	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return nil, fmt.Errorf("open user DB: %w", err)
	}
	log.Printf("[LOGIN] OpenUserDBWithDEK took %s", stdtime.Since(dbStart))

	// Get account by email
	account, err := userDB.Queries().GetAccountByEmail(ctx, emailAddr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get account: %w", err)
	}

	// Check password hash is set (account may have been created via OIDC/magic link)
	if !account.PasswordHash.Valid || account.PasswordHash.String == "" {
		return nil, ErrInvalidCredentials
	}

	// Verify password
	if !s.hasher.VerifyPassword(password, account.PasswordHash.String) {
		return nil, ErrInvalidCredentials
	}

	log.Printf("[LOGIN] Total VerifyLogin took %s", stdtime.Since(loginStart))
	subStatus := "free"
	if account.SubscriptionStatus.Valid && account.SubscriptionStatus.String != "" {
		subStatus = account.SubscriptionStatus.String
	}
	return &User{
		ID:                 userID,
		Email:              emailAddr,
		SubscriptionStatus: subStatus,
		StripeCustomerID:   account.StripeCustomerID.String,
		CreatedAt:          stdtime.Unix(account.CreatedAt, 0),
	}, nil
}

// FindOrCreateByProvider finds or creates a user account for OIDC/magic link auth.
// Auto-creates the account with NULL password_hash if it doesn't exist.
func (s *UserService) FindOrCreateByProvider(ctx context.Context, emailAddr string) (*User, error) {
	userID := generateUserID(emailAddr)

	// Get or create DEK (auto-creates user_keys entry if needed)
	dek, err := s.keyManager.GetOrCreateUserDEK(userID)
	if err != nil {
		return nil, fmt.Errorf("get or create user DEK: %w", err)
	}

	// Open user DB
	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return nil, fmt.Errorf("open user DB: %w", err)
	}

	// Try to get existing account
	account, err := userDB.Queries().GetAccountByEmail(ctx, emailAddr)
	if err == nil {
		subStatus := "free"
		if account.SubscriptionStatus.Valid && account.SubscriptionStatus.String != "" {
			subStatus = account.SubscriptionStatus.String
		}
		return &User{
			ID:                 userID,
			Email:              emailAddr,
			SubscriptionStatus: subStatus,
			StripeCustomerID:   account.StripeCustomerID.String,
			CreatedAt:          stdtime.Unix(account.CreatedAt, 0),
		}, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("get account: %w", err)
	}

	// Account doesn't exist — create with NULL password_hash
	now := s.clock.Now()
	err = userDB.Queries().CreateAccount(ctx, userdb.CreateAccountParams{
		UserID:             userID,
		Email:              emailAddr,
		CreatedAt:          now.Unix(),
		SubscriptionStatus: sql.NullString{String: "free", Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("create account: %w", err)
	}

	// Check and apply any pending subscription (Milestone 2g)
	user := &User{
		ID:                 userID,
		Email:              emailAddr,
		SubscriptionStatus: "free",
		CreatedAt:          now,
	}
	if pendingStatus, pendingCustID, _ := s.applyPendingSubscription(ctx, userDB, userID, emailAddr); pendingStatus != "" {
		user.SubscriptionStatus = pendingStatus
		user.StripeCustomerID = pendingCustID
	}

	return user, nil
}

// applyPendingSubscription checks for a pending subscription for the given email
// and applies it to the newly created account. Returns the subscription status,
// stripe customer ID, and subscription ID if a pending subscription was applied.
func (s *UserService) applyPendingSubscription(ctx context.Context, userDB *db.UserDB, userID, emailAddr string) (subStatus, custID, subID string) {
	pending, err := s.db.Queries().GetPendingSubscription(ctx, emailAddr)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("[REGISTER] Warning: failed to check pending subscription for %s: %v", emailAddr, err)
		}
		return "", "", ""
	}

	// Found a pending subscription — apply it to the user's account
	log.Printf("[REGISTER] Applying pending subscription for %s: customer=%s sub=%s status=%s",
		emailAddr, pending.StripeCustomerID, pending.SubscriptionID, pending.SubscriptionStatus)

	// Update the user DB account record with subscription info
	err = userDB.Queries().UpdateAccountSubscriptionFull(ctx, userdb.UpdateAccountSubscriptionFullParams{
		SubscriptionStatus: sql.NullString{String: pending.SubscriptionStatus, Valid: true},
		SubscriptionID:     sql.NullString{String: pending.SubscriptionID, Valid: true},
		StripeCustomerID:   sql.NullString{String: pending.StripeCustomerID, Valid: true},
		UserID:             userID,
	})
	if err != nil {
		log.Printf("[REGISTER] Warning: failed to update account subscription for %s: %v", emailAddr, err)
		return "", "", ""
	}

	// Insert stripe customer map in sessions DB
	err = s.db.Queries().CreateStripeCustomerMap(ctx, sessions.CreateStripeCustomerMapParams{
		StripeCustomerID: pending.StripeCustomerID,
		UserID:           userID,
	})
	if err != nil {
		log.Printf("[REGISTER] Warning: failed to create stripe customer map for %s: %v", emailAddr, err)
		// Continue — the account update already succeeded
	}

	// Delete the pending record
	err = s.db.Queries().DeletePendingSubscription(ctx, emailAddr)
	if err != nil {
		log.Printf("[REGISTER] Warning: failed to delete pending subscription for %s: %v", emailAddr, err)
	}

	return pending.SubscriptionStatus, pending.StripeCustomerID, pending.SubscriptionID
}

// LinkGoogleAccount links a Google account to an existing user.
// Returns ErrGoogleSubMismatch if the account is already linked to a different Google sub.
func (s *UserService) LinkGoogleAccount(ctx context.Context, userID, googleSub string) error {
	dek, err := s.keyManager.GetUserDEK(userID)
	if err != nil {
		return fmt.Errorf("get user DEK: %w", err)
	}
	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return fmt.Errorf("open user DB: %w", err)
	}

	// Check existing google_sub
	account, err := userDB.Queries().GetAccount(ctx, userID)
	if err != nil {
		return fmt.Errorf("get account: %w", err)
	}

	if account.GoogleSub.Valid && account.GoogleSub.String != "" && account.GoogleSub.String != googleSub {
		return ErrGoogleSubMismatch
	}

	// Already linked with same sub — no-op
	if account.GoogleSub.Valid && account.GoogleSub.String == googleSub {
		return nil
	}

	return userDB.Queries().UpdateAccountGoogleSub(ctx, userdb.UpdateAccountGoogleSubParams{
		GoogleSub: sql.NullString{String: googleSub, Valid: true},
		UserID:    userID,
	})
}

// UnlinkGoogleAccount removes the Google account link from a user.
func (s *UserService) UnlinkGoogleAccount(ctx context.Context, userID string) error {
	dek, err := s.keyManager.GetUserDEK(userID)
	if err != nil {
		return fmt.Errorf("get user DEK: %w", err)
	}
	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return fmt.Errorf("open user DB: %w", err)
	}
	return userDB.Queries().UpdateAccountGoogleSub(ctx, userdb.UpdateAccountGoogleSubParams{
		GoogleSub: sql.NullString{Valid: false},
		UserID:    userID,
	})
}

// SetPassword sets a new password for a user (used by account settings).
func (s *UserService) SetPassword(ctx context.Context, userID, newPassword string) error {
	// Validate
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}
	// Hash
	passwordHash, err := s.hasher.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	// Open user DB
	dek, err := s.keyManager.GetUserDEK(userID)
	if err != nil {
		return fmt.Errorf("get user DEK: %w", err)
	}
	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return fmt.Errorf("open user DB: %w", err)
	}
	// Update
	return userDB.Queries().UpdateAccountPasswordHash(ctx, userdb.UpdateAccountPasswordHashParams{
		PasswordHash: sql.NullString{String: passwordHash, Valid: true},
		UserID:       userID,
	})
}

// GetAccountInfo retrieves account information for the settings page.
func (s *UserService) GetAccountInfo(ctx context.Context, userID string) (*userdb.Account, error) {
	dek, err := s.keyManager.GetUserDEK(userID)
	if err != nil {
		return nil, fmt.Errorf("get user DEK: %w", err)
	}
	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return nil, fmt.Errorf("open user DB: %w", err)
	}
	account, err := userDB.Queries().GetAccount(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	return &account, nil
}

// SendMagicLink generates and sends a magic login link.
func (s *UserService) SendMagicLink(ctx context.Context, emailAddr string, baseURLs ...string) error {
	// Generate random token
	token, err := generateSecureToken(32)
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	// Hash token for storage
	tokenHash := hashToken(token)

	// Compute user ID (magic links auto-create on verification)
	userID := generateUserID(emailAddr)

	// Store hashed token
	now := s.clock.Now()
	expiresAt := now.Add(MagicTokenExpiry)
	err = s.db.Queries().UpsertMagicToken(ctx, sessions.UpsertMagicTokenParams{
		TokenHash: tokenHash,
		Email:     emailAddr,
		UserID:    sql.NullString{String: userID, Valid: true},
		ExpiresAt: expiresAt.Unix(),
		CreatedAt: now.Unix(),
	})
	if err != nil {
		return fmt.Errorf("store magic token: %w", err)
	}

	// Send email with magic link
	baseURL := s.resolveBaseURL(baseURLs...)
	link := fmt.Sprintf("%s/auth/magic/verify?token=%s", baseURL, token)
	err = s.emailService.Send(emailAddr, email.TemplateMagicLink, email.MagicLinkData{
		Link:      link,
		ExpiresIn: "15 minutes",
	})
	if err != nil {
		return fmt.Errorf("send magic link email: %w", err)
	}

	return nil
}

// VerifyMagicToken verifies a magic login token and returns the user.
// The token is consumed (deleted) after successful verification.
func (s *UserService) VerifyMagicToken(ctx context.Context, token string) (*User, error) {
	// Hash the provided token
	tokenHash := hashToken(token)

	// Look up the token (without SQL-level time filtering so the clock is testable)
	magicToken, err := s.db.Queries().GetMagicToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("get magic token: %w", err)
	}

	// Check expiry using the service clock
	if magicToken.ExpiresAt <= s.clock.Now().Unix() {
		// Token is expired; delete it and return error
		_ = s.db.Queries().DeleteMagicToken(ctx, tokenHash)
		return nil, ErrInvalidToken
	}

	// Delete the token (consume it)
	if err := s.db.Queries().DeleteMagicToken(ctx, tokenHash); err != nil {
		return nil, fmt.Errorf("delete magic token: %w", err)
	}

	// Return the user
	return &User{
		ID:        magicToken.UserID.String,
		Email:     magicToken.Email,
		CreatedAt: stdtime.Unix(magicToken.CreatedAt, 0),
	}, nil
}

func (s *UserService) resolveBaseURL(baseURLs ...string) string {
	baseURL := s.baseURL
	if len(baseURLs) > 0 && strings.TrimSpace(baseURLs[0]) != "" {
		baseURL = baseURLs[0]
	}
	return strings.TrimRight(urlutil.OriginFromRequest(nil, baseURL), "/")
}

// ValidatePasswordStrength checks if a password meets minimum requirements.
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword
	}
	return nil
}

// HashPassword hashes a password using Argon2id.
func HashPassword(password string) (string, error) {
	// Generate salt
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Hash password
	start := stdtime.Now()
	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	log.Printf("[ARGON2] HashPassword: m=%d KiB, t=%d, p=%d, took %s", argon2Memory, argon2Time, argon2Threads, stdtime.Since(start))

	// Encode as: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory, argon2Time, argon2Threads, encodedSalt, encodedHash), nil
}

// VerifyPassword checks if a password matches a hash.
func VerifyPassword(password, encodedHash string) bool {
	// Parse the encoded hash
	// Format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}

	if parts[1] != "argon2id" {
		return false
	}

	if parts[2] != "v=19" {
		return false
	}

	// Parse parameters
	var memory, time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false
	}

	salt := parts[4]
	hash := parts[5]

	// Decode salt
	saltBytes, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return false
	}

	// Decode hash
	hashBytes, err := base64.RawStdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}

	// Validate hash length is reasonable (Argon2 output is typically 32 bytes)
	hashLen := len(hashBytes)
	if hashLen <= 0 || hashLen > argon2KeyLen*2 {
		return false
	}

	// Compute hash of provided password
	start := stdtime.Now()
	computedHash := argon2.IDKey([]byte(password), saltBytes, time, memory, threads, uint32(hashLen))
	log.Printf("[ARGON2] VerifyPassword: m=%d KiB, t=%d, p=%d, took %s", memory, time, threads, stdtime.Since(start))

	// Constant-time comparison
	return subtle.ConstantTimeCompare(hashBytes, computedHash) == 1
}

// SendPasswordReset sends a password reset email.
func (s *UserService) SendPasswordReset(ctx context.Context, emailAddr string, baseURLs ...string) error {
	// Generate random token
	token, err := generateSecureToken(32)
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	// Hash token for storage
	tokenHash := hashToken(token)

	// Compute user ID (always succeed to prevent email enumeration)
	userID := generateUserID(emailAddr)

	// Store hashed token
	now := s.clock.Now()
	expiresAt := now.Add(MagicTokenExpiry)
	err = s.db.Queries().UpsertMagicToken(ctx, sessions.UpsertMagicTokenParams{
		TokenHash: tokenHash,
		Email:     emailAddr,
		UserID:    sql.NullString{String: userID, Valid: true},
		ExpiresAt: expiresAt.Unix(),
		CreatedAt: now.Unix(),
	})
	if err != nil {
		return fmt.Errorf("store reset token: %w", err)
	}

	// Send email with reset link
	baseURL := s.resolveBaseURL(baseURLs...)
	link := fmt.Sprintf("%s/auth/password-reset-confirm?token=%s", baseURL, token)
	err = s.emailService.Send(emailAddr, email.TemplatePasswordReset, email.PasswordResetData{
		Link:      link,
		ExpiresIn: "15 minutes",
	})
	if err != nil {
		return fmt.Errorf("send reset email: %w", err)
	}

	return nil
}

// ResetPassword resets a user's password using a reset token.
func (s *UserService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Validate password strength
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}

	// Verify and consume the token
	user, err := s.VerifyMagicToken(ctx, token)
	if err != nil {
		return err
	}

	// Hash the new password
	passwordHash, err := s.hasher.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// Open user DB and update the password hash
	dek, err := s.keyManager.GetUserDEK(user.ID)
	if err != nil {
		return fmt.Errorf("get user DEK: %w", err)
	}

	userDB, err := db.OpenUserDBWithDEK(user.ID, dek)
	if err != nil {
		return fmt.Errorf("open user DB: %w", err)
	}

	err = userDB.Queries().UpdateAccountPasswordHash(ctx, userdb.UpdateAccountPasswordHashParams{
		PasswordHash: sql.NullString{String: passwordHash, Valid: true},
		UserID:       user.ID,
	})
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}

	// Verify the update actually affected a row
	account, verifyErr := userDB.Queries().GetAccountByEmail(ctx, user.Email)
	if verifyErr != nil {
		return fmt.Errorf("password reset failed: no account record for user %s (orphaned DEK)", user.ID)
	}
	if !s.hasher.VerifyPassword(newPassword, account.PasswordHash.String) {
		return fmt.Errorf("password reset verification failed: hash mismatch after update")
	}

	return nil
}

// Helper functions

func generateUserID(email string) string {
	return "user-" + uuid.NewSHA1(uuid.NameSpaceDNS, []byte(email)).String()
}

// GenerateUserID is the exported version of generateUserID for use in tests.
func GenerateUserID(email string) string {
	return generateUserID(email)
}

func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(hash[:])
}
