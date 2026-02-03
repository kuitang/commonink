// Package shorturl provides URL shortening functionality for public notes.
// Short IDs are 6 characters from [a-zA-Z0-9_-] (64 chars = 64^6 = ~69 billion combinations).
package shorturl

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/kuitang/agent-notes/internal/db/sessions"
)

const (
	// ShortIDLength is the length of short URL identifiers
	ShortIDLength = 6

	// MaxCollisionRetries is the maximum number of retries on collision
	MaxCollisionRetries = 10
)

// Charset for short IDs: [a-zA-Z0-9_-] = 64 characters
// Using URL-safe base64 characters for easy embedding in URLs
const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

// Service provides short URL operations.
type Service struct {
	queries *sessions.Queries
}

// NewService creates a new short URL service.
func NewService(queries *sessions.Queries) *Service {
	return &Service{queries: queries}
}

// ShortURL represents a short URL mapping.
type ShortURL struct {
	ID        int64
	ShortID   string
	FullPath  string
	CreatedAt time.Time
}

// GenerateShortID generates a random 6-character short ID.
// Uses cryptographically secure random bytes for uniqueness.
func GenerateShortID() (string, error) {
	// We need 6 characters, each from a 64-character set
	// 6 bits per character = 36 bits total, so we need 5 bytes (40 bits)
	bytes := make([]byte, 8) // Use 8 bytes for easier bit manipulation
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to uint64 for bit extraction
	n := binary.BigEndian.Uint64(bytes)

	// Extract 6 bits at a time to index into charset
	result := make([]byte, ShortIDLength)
	for i := 0; i < ShortIDLength; i++ {
		idx := n & 0x3F // 6 bits = 0-63
		result[i] = charset[idx]
		n >>= 6
	}

	return string(result), nil
}

// ValidateShortID checks if a short ID has the correct format.
func ValidateShortID(shortID string) bool {
	if len(shortID) != ShortIDLength {
		return false
	}
	for _, c := range shortID {
		if !isValidChar(byte(c)) {
			return false
		}
	}
	return true
}

// isValidChar checks if a character is in the valid charset.
func isValidChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '_' || c == '-'
}

// Create creates a new short URL mapping with collision handling.
// If a short ID already exists, it will retry with a new ID up to MaxCollisionRetries times.
// If a mapping for the full path already exists, it returns the existing short ID.
func (s *Service) Create(ctx context.Context, fullPath string) (*ShortURL, error) {
	// Check if mapping already exists for this full path
	existing, err := s.queries.GetShortURLByFullPath(ctx, fullPath)
	if err == nil {
		return &ShortURL{
			ID:        existing.ID,
			ShortID:   existing.ShortID,
			FullPath:  existing.FullPath,
			CreatedAt: time.Unix(existing.CreatedAt, 0).UTC(),
		}, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to check existing short URL: %w", err)
	}

	// Try to create a new short URL with collision handling
	var lastErr error
	for i := 0; i < MaxCollisionRetries; i++ {
		shortID, err := GenerateShortID()
		if err != nil {
			return nil, err
		}

		now := time.Now().UTC().Unix()
		err = s.queries.CreateShortURL(ctx, sessions.CreateShortURLParams{
			ShortID:   shortID,
			FullPath:  fullPath,
			CreatedAt: now,
		})
		if err != nil {
			// Check if it's a unique constraint violation (collision)
			// SQLite UNIQUE constraint violation typically contains "UNIQUE constraint"
			if isUniqueConstraintError(err) {
				lastErr = err
				continue // Retry with a new short ID
			}
			return nil, fmt.Errorf("failed to create short URL: %w", err)
		}

		return &ShortURL{
			ShortID:   shortID,
			FullPath:  fullPath,
			CreatedAt: time.Unix(now, 0).UTC(),
		}, nil
	}

	return nil, fmt.Errorf("failed to create short URL after %d retries: %w", MaxCollisionRetries, lastErr)
}

// Resolve looks up a short URL by its short ID and returns the full path.
func (s *Service) Resolve(ctx context.Context, shortID string) (string, error) {
	if !ValidateShortID(shortID) {
		return "", fmt.Errorf("invalid short ID format")
	}

	result, err := s.queries.GetShortURLByShortID(ctx, shortID)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("short URL not found")
	}
	if err != nil {
		return "", fmt.Errorf("failed to resolve short URL: %w", err)
	}

	return result.FullPath, nil
}

// Delete removes a short URL mapping by short ID.
func (s *Service) Delete(ctx context.Context, shortID string) error {
	return s.queries.DeleteShortURL(ctx, shortID)
}

// DeleteByFullPath removes a short URL mapping by full path.
func (s *Service) DeleteByFullPath(ctx context.Context, fullPath string) error {
	return s.queries.DeleteShortURLByFullPath(ctx, fullPath)
}

// GetByFullPath returns the short URL for a given full path.
func (s *Service) GetByFullPath(ctx context.Context, fullPath string) (*ShortURL, error) {
	result, err := s.queries.GetShortURLByFullPath(ctx, fullPath)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("short URL not found for path")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get short URL: %w", err)
	}

	return &ShortURL{
		ID:        result.ID,
		ShortID:   result.ShortID,
		FullPath:  result.FullPath,
		CreatedAt: time.Unix(result.CreatedAt, 0).UTC(),
	}, nil
}

// isUniqueConstraintError checks if an error is a SQLite unique constraint violation.
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "UNIQUE constraint") || contains(errStr, "unique constraint")
}

// contains is a simple string contains check.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr) >= 0
}

// searchString finds substr in s.
func searchString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
