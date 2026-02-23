package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/sessions"
)

// Consent errors
var (
	ErrConsentNotFound = errors.New("consent not found")
	ErrNoConsentNeeded = errors.New("consent already granted for all requested scopes")
)

// Consent represents a user's consent grant for an OAuth client.
type Consent struct {
	UserID    string
	ClientID  string
	Scopes    []string
	GrantedAt time.Time
}

// ConsentService handles OAuth consent management.
// This service manages user consent grants for OAuth 2.1 clients (AI agents) connecting to us.
type ConsentService struct {
	db *db.SessionsDB
}

// NewConsentService creates a new consent service.
func NewConsentService(sessionsDB *db.SessionsDB) *ConsentService {
	return &ConsentService{
		db: sessionsDB,
	}
}

// GetPendingConsent checks if consent is needed for the given user and client.
// Returns the missing scopes that need to be consented to, or ErrNoConsentNeeded
// if the user has already granted consent for all requested scopes.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: The user's unique identifier
//   - clientID: The OAuth client's identifier
//   - requestedScopes: The scopes the client is requesting
//
// Returns:
//   - *Consent: A consent object with the missing scopes that need to be granted
//   - error: ErrNoConsentNeeded if already consented, or other errors
func (s *ConsentService) GetPendingConsent(ctx context.Context, userID, clientID string, requestedScopes []string) (*Consent, error) {
	existingConsent, err := s.getConsentFromDB(ctx, userID, clientID)
	if err != nil {
		if errors.Is(err, ErrConsentNotFound) {
			// No existing consent - all scopes are pending
			return &Consent{
				UserID:   userID,
				ClientID: clientID,
				Scopes:   requestedScopes,
			}, nil
		}
		return nil, fmt.Errorf("get existing consent: %w", err)
	}

	// Check which scopes are missing
	missingScopes := findMissingScopes(existingConsent.Scopes, requestedScopes)
	if len(missingScopes) == 0 {
		return nil, ErrNoConsentNeeded
	}

	return &Consent{
		UserID:   userID,
		ClientID: clientID,
		Scopes:   missingScopes,
	}, nil
}

// RecordConsent stores the user's consent for a client with the given scopes.
// If consent already exists, the scopes are merged (union of old and new scopes).
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: The user's unique identifier
//   - clientID: The OAuth client's identifier
//   - scopes: The scopes the user is consenting to
//
// Returns:
//   - error: Any error encountered during the operation
func (s *ConsentService) RecordConsent(ctx context.Context, userID, clientID string, scopes []string) error {
	if len(scopes) == 0 {
		return fmt.Errorf("scopes cannot be empty")
	}

	// Normalize and deduplicate scopes
	normalizedScopes := normalizeScopes(scopes)

	// Get existing consent to merge scopes
	existingConsent, err := s.getConsentFromDB(ctx, userID, clientID)
	if err != nil && !errors.Is(err, ErrConsentNotFound) {
		return fmt.Errorf("get existing consent: %w", err)
	}

	var finalScopes []string
	if existingConsent != nil {
		// Merge scopes (union)
		finalScopes = mergeScopes(existingConsent.Scopes, normalizedScopes)
	} else {
		finalScopes = normalizedScopes
	}

	// Store/update consent in database
	return s.upsertConsentInDB(ctx, userID, clientID, finalScopes)
}

// HasConsent checks if the user has already granted consent for all the requested scopes.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: The user's unique identifier
//   - clientID: The OAuth client's identifier
//   - scopes: The scopes to check
//
// Returns:
//   - bool: true if user has consented to all requested scopes
//   - error: Any error encountered during the operation
func (s *ConsentService) HasConsent(ctx context.Context, userID, clientID string, scopes []string) (bool, error) {
	existingConsent, err := s.getConsentFromDB(ctx, userID, clientID)
	if err != nil {
		if errors.Is(err, ErrConsentNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("get consent: %w", err)
	}

	// Check if all requested scopes are covered
	missingScopes := findMissingScopes(existingConsent.Scopes, scopes)
	return len(missingScopes) == 0, nil
}

// RevokeConsent removes consent for a specific client.
// This is typically called when a user wants to disconnect an OAuth client.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: The user's unique identifier
//   - clientID: The OAuth client's identifier
//
// Returns:
//   - error: Any error encountered during the operation
func (s *ConsentService) RevokeConsent(ctx context.Context, userID, clientID string) error {
	// Delete consent from database
	err := s.deleteConsentFromDB(ctx, userID, clientID)
	if err != nil {
		return fmt.Errorf("delete consent: %w", err)
	}

	// Also revoke all tokens for this user/client
	if err := s.db.Queries().DeleteOAuthTokensByUserID(ctx, userID); err != nil {
		return fmt.Errorf("revoke tokens: %w", err)
	}

	return nil
}

// ListConsentsForUser returns all consents granted by a user.
// This is useful for displaying in a user settings page.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: The user's unique identifier
//
// Returns:
//   - []Consent: List of all consents granted by the user
//   - error: Any error encountered during the operation
func (s *ConsentService) ListConsentsForUser(ctx context.Context, userID string) ([]Consent, error) {
	return s.listConsentsFromDB(ctx, userID)
}

// ============================================================================
// Database layer — wired to sqlc-generated queries
// ============================================================================

// getConsentFromDB retrieves a consent record from the database.
func (s *ConsentService) getConsentFromDB(ctx context.Context, userID, clientID string) (*Consent, error) {
	result, err := s.db.Queries().GetConsent(ctx, sessions.GetConsentParams{
		UserID:   userID,
		ClientID: clientID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrConsentNotFound
		}
		return nil, fmt.Errorf("get consent: %w", err)
	}
	return &Consent{
		UserID:    result.UserID,
		ClientID:  result.ClientID,
		Scopes:    StringToScopes(result.Scopes),
		GrantedAt: time.Unix(result.GrantedAt, 0).UTC(),
	}, nil
}

// upsertConsentInDB stores or updates a consent record in the database.
// It tries INSERT first; on UNIQUE constraint conflict, falls back to UPDATE.
func (s *ConsentService) upsertConsentInDB(ctx context.Context, userID, clientID string, scopes []string) error {
	scopeStr := ScopesToString(scopes)
	now := time.Now().UTC().Unix()

	// Try insert first
	err := s.db.Queries().CreateConsent(ctx, sessions.CreateConsentParams{
		ID:        uuid.New().String(),
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    scopeStr,
		GrantedAt: now,
	})
	if err != nil {
		// If UNIQUE constraint violation, update existing record
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return s.db.Queries().UpdateConsentScopes(ctx, sessions.UpdateConsentScopesParams{
				Scopes:    scopeStr,
				GrantedAt: now,
				UserID:    userID,
				ClientID:  clientID,
			})
		}
		return err
	}
	return nil
}

// deleteConsentFromDB removes a consent record from the database.
func (s *ConsentService) deleteConsentFromDB(ctx context.Context, userID, clientID string) error {
	return s.db.Queries().DeleteConsent(ctx, sessions.DeleteConsentParams{
		UserID:   userID,
		ClientID: clientID,
	})
}

// listConsentsFromDB retrieves all consents for a user from the database.
func (s *ConsentService) listConsentsFromDB(ctx context.Context, userID string) ([]Consent, error) {
	results, err := s.db.Queries().ListConsentsForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list consents: %w", err)
	}
	consents := make([]Consent, 0, len(results))
	for _, r := range results {
		consents = append(consents, Consent{
			UserID:    r.UserID,
			ClientID:  r.ClientID,
			Scopes:    StringToScopes(r.Scopes),
			GrantedAt: time.Unix(r.GrantedAt, 0).UTC(),
		})
	}
	return consents, nil
}

// ============================================================================
// Helper functions
// ============================================================================

// normalizeScopes deduplicates and sorts scopes for consistent storage.
func normalizeScopes(scopes []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(scopes))

	for _, scope := range scopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			result = append(result, trimmed)
		}
	}

	sort.Strings(result)
	return result
}

// mergeScopes returns the union of two scope lists, normalized and sorted.
func mergeScopes(existing, new []string) []string {
	combined := make([]string, 0, len(existing)+len(new))
	combined = append(combined, existing...)
	combined = append(combined, new...)
	return normalizeScopes(combined)
}

// findMissingScopes returns scopes in requested that are not in existing.
func findMissingScopes(existing, requested []string) []string {
	existingSet := make(map[string]bool)
	for _, scope := range existing {
		existingSet[scope] = true
	}

	missing := make([]string, 0)
	for _, scope := range requested {
		if !existingSet[scope] {
			missing = append(missing, scope)
		}
	}

	return missing
}

// ScopesToString converts a slice of scopes to a space-separated string (OAuth standard format).
func ScopesToString(scopes []string) string {
	return strings.Join(scopes, " ")
}

// StringToScopes converts a space-separated string to a slice of scopes.
func StringToScopes(scopeString string) []string {
	if scopeString == "" {
		return []string{}
	}
	return strings.Fields(scopeString)
}
