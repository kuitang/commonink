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
)

// Errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountExists      = errors.New("account already exists")
	ErrWeakPassword       = errors.New("password must be at least 8 characters")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrEmailNotVerified   = errors.New("email not verified")
)

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
	ID        string
	Email     string
	Name      string
	GoogleSub string // Google OIDC subject ID if linked
	CreatedAt stdtime.Time
}

// UserService handles user management operations.
type UserService struct {
	db           *db.SessionsDB
	keyManager   *crypto.KeyManager
	emailService email.EmailService
	baseURL      string // Base URL for magic link generation
	clock        Clock  // Clock for time operations (defaults to real time)
}

// NewUserService creates a new user service.
func NewUserService(sessionsDB *db.SessionsDB, keyManager *crypto.KeyManager, emailSvc email.EmailService, baseURL string) *UserService {
	return &UserService{
		db:           sessionsDB,
		keyManager:   keyManager,
		emailService: emailSvc,
		baseURL:      baseURL,
		clock:        realClock{},
	}
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
	passwordHash, err := HashPassword(password)
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

	log.Printf("[REGISTER] Total RegisterWithPassword took %s", stdtime.Since(regStart))
	return &User{
		ID:        userID,
		Email:     emailAddr,
		CreatedAt: now,
	}, nil
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
	if !VerifyPassword(password, account.PasswordHash.String) {
		return nil, ErrInvalidCredentials
	}

	log.Printf("[LOGIN] Total VerifyLogin took %s", stdtime.Since(loginStart))
	return &User{
		ID:        userID,
		Email:     emailAddr,
		CreatedAt: stdtime.Unix(account.CreatedAt, 0),
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
		return &User{
			ID:        userID,
			Email:     emailAddr,
			CreatedAt: stdtime.Unix(account.CreatedAt, 0),
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

	return &User{
		ID:        userID,
		Email:     emailAddr,
		CreatedAt: now,
	}, nil
}

// FindByGoogleSub finds a user by their Google OIDC subject ID.
func (s *UserService) FindByGoogleSub(ctx context.Context, googleSub string) (*User, error) {
	// In a full implementation, we'd query the users table
	// For now, return not found
	return nil, ErrUserNotFound
}

// LinkGoogleAccount links a Google account to an existing user.
func (s *UserService) LinkGoogleAccount(ctx context.Context, userID, googleSub string) error {
	// In a full implementation, we'd update the users table
	return nil
}

// SendMagicLink generates and sends a magic login link.
func (s *UserService) SendMagicLink(ctx context.Context, emailAddr string) error {
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
	link := fmt.Sprintf("%s/auth/magic/verify?token=%s", s.baseURL, token)
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
func (s *UserService) SendPasswordReset(ctx context.Context, emailAddr string) error {
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
	link := fmt.Sprintf("%s/auth/password-reset-confirm?token=%s", s.baseURL, token)
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
	passwordHash, err := HashPassword(newPassword)
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
	if !VerifyPassword(newPassword, account.PasswordHash.String) {
		return fmt.Errorf("password reset verification failed: hash mismatch after update")
	}

	return nil
}

// Helper functions

func generateUserID(email string) string {
	return "user-" + uuid.NewSHA1(uuid.NameSpaceDNS, []byte(email)).String()
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
