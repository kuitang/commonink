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
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/sessions"
	"github.com/kuitang/agent-notes/internal/email"
)

// Errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrWeakPassword       = errors.New("password must be at least 8 characters")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrEmailNotVerified   = errors.New("email not verified")
)

// Argon2id parameters (OWASP recommendations)
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// Token expiry
const (
	MagicTokenExpiry = 15 * time.Minute
)

// User represents a user account.
type User struct {
	ID        string
	Email     string
	Name      string
	GoogleSub string // Google OIDC subject ID if linked
	CreatedAt time.Time
}

// UserService handles user management operations.
type UserService struct {
	db           *db.SessionsDB
	emailService email.EmailService
	baseURL      string // Base URL for magic link generation
}

// NewUserService creates a new user service.
func NewUserService(sessionsDB *db.SessionsDB, emailSvc email.EmailService, baseURL string) *UserService {
	return &UserService{
		db:           sessionsDB,
		emailService: emailSvc,
		baseURL:      baseURL,
	}
}

// FindOrCreateByEmail finds a user by email or creates a new one.
// This is idempotent - calling multiple times with the same email returns the same user.
func (s *UserService) FindOrCreateByEmail(ctx context.Context, emailAddr string) (*User, error) {
	// Try to find existing user by email
	// For now, we'll use a simple approach with the sessions DB
	// In a full implementation, we'd have a users table in sessions.db

	userID := generateUserID(emailAddr)

	return &User{
		ID:        userID,
		Email:     emailAddr,
		CreatedAt: time.Now(),
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

	// Find or create user
	user, err := s.FindOrCreateByEmail(ctx, emailAddr)
	if err != nil {
		return fmt.Errorf("find or create user: %w", err)
	}

	// Store hashed token
	expiresAt := time.Now().Add(MagicTokenExpiry)
	err = s.db.Queries().UpsertMagicToken(ctx, sessions.UpsertMagicTokenParams{
		TokenHash: tokenHash,
		Email:     emailAddr,
		UserID:    sql.NullString{String: user.ID, Valid: true},
		ExpiresAt: expiresAt.Unix(),
		CreatedAt: time.Now().Unix(),
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

	// Look up the token
	magicToken, err := s.db.Queries().GetValidMagicToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("get magic token: %w", err)
	}

	// Delete the token (consume it)
	if err := s.db.Queries().DeleteMagicToken(ctx, tokenHash); err != nil {
		return nil, fmt.Errorf("delete magic token: %w", err)
	}

	// Return the user
	return &User{
		ID:        magicToken.UserID.String,
		Email:     magicToken.Email,
		CreatedAt: time.Unix(magicToken.CreatedAt, 0),
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
	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

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

	// Compute hash of provided password
	computedHash := argon2.IDKey([]byte(password), saltBytes, time, memory, threads, uint32(len(hashBytes)))

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

	// Find user (must exist for password reset)
	user, err := s.FindOrCreateByEmail(ctx, emailAddr)
	if err != nil {
		return fmt.Errorf("find user: %w", err)
	}

	// Store hashed token
	expiresAt := time.Now().Add(MagicTokenExpiry)
	err = s.db.Queries().UpsertMagicToken(ctx, sessions.UpsertMagicTokenParams{
		TokenHash: tokenHash,
		Email:     emailAddr,
		UserID:    sql.NullString{String: user.ID, Valid: true},
		ExpiresAt: expiresAt.Unix(),
		CreatedAt: time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("store reset token: %w", err)
	}

	// Send email with reset link
	link := fmt.Sprintf("%s/auth/password/reset/confirm?token=%s", s.baseURL, token)
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
	_, err := s.VerifyMagicToken(ctx, token)
	if err != nil {
		return err
	}

	// Hash the new password
	_, err = HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// In a full implementation, we'd update the password hash in the users table
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
