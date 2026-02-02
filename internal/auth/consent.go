package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
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
	// TODO: Replace with actual DB query once sessions_consent.sql is implemented
	// Example query: SELECT scopes FROM oauth_consents WHERE user_id = ? AND client_id = ?
	//
	// For now, check the in-memory/placeholder logic:
	// The actual implementation will query the oauth_consents table

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
	// TODO: Replace with actual DB query once sessions_consent.sql is implemented
	// Example queries:
	// 1. Try to get existing consent
	// 2. If exists, merge scopes and update
	// 3. If not exists, insert new consent
	//
	// SQL for upsert:
	// INSERT INTO oauth_consents (user_id, client_id, scopes, granted_at)
	// VALUES (?, ?, ?, ?)
	// ON CONFLICT(user_id, client_id) DO UPDATE SET
	//   scopes = ?,
	//   granted_at = ?

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
	// TODO: Replace with actual DB query once sessions_consent.sql is implemented
	// Example query: SELECT scopes FROM oauth_consents WHERE user_id = ? AND client_id = ?

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
	// TODO: Replace with actual DB query once sessions_consent.sql is implemented
	// Example query: DELETE FROM oauth_consents WHERE user_id = ? AND client_id = ?
	//
	// Additionally, should also revoke all active tokens for this user/client:
	// DELETE FROM oauth_tokens WHERE user_id = ? AND client_id = ?

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
	// TODO: Replace with actual DB query once sessions_consent.sql is implemented
	// Example query: SELECT client_id, scopes, granted_at FROM oauth_consents WHERE user_id = ?

	return s.listConsentsFromDB(ctx, userID)
}

// ============================================================================
// Database layer placeholders
// These methods will be replaced with actual sqlc-generated queries
// once sessions_consent.sql is implemented in Layer 2
// ============================================================================

// getConsentFromDB retrieves a consent record from the database.
// TODO: Replace with actual sqlc query: s.db.Queries().GetOAuthConsent(ctx, params)
func (s *ConsentService) getConsentFromDB(ctx context.Context, userID, clientID string) (*Consent, error) {
	// TODO: Implement with actual DB query
	// query := `SELECT user_id, client_id, scopes, granted_at FROM oauth_consents WHERE user_id = ? AND client_id = ?`
	//
	// For now, return not found as placeholder
	// This forces consumers to handle the "no consent" case
	return nil, ErrConsentNotFound
}

// upsertConsentInDB stores or updates a consent record in the database.
// TODO: Replace with actual sqlc query: s.db.Queries().UpsertOAuthConsent(ctx, params)
func (s *ConsentService) upsertConsentInDB(ctx context.Context, userID, clientID string, scopes []string) error {
	// TODO: Implement with actual DB query
	// query := `
	//   INSERT INTO oauth_consents (user_id, client_id, scopes, granted_at)
	//   VALUES (?, ?, ?, ?)
	//   ON CONFLICT(user_id, client_id) DO UPDATE SET
	//     scopes = excluded.scopes,
	//     granted_at = excluded.granted_at
	// `
	//
	// For now, log and return nil as placeholder
	_ = userID
	_ = clientID
	_ = scopes
	return nil
}

// deleteConsentFromDB removes a consent record from the database.
// TODO: Replace with actual sqlc query: s.db.Queries().DeleteOAuthConsent(ctx, params)
func (s *ConsentService) deleteConsentFromDB(ctx context.Context, userID, clientID string) error {
	// TODO: Implement with actual DB query
	// query := `DELETE FROM oauth_consents WHERE user_id = ? AND client_id = ?`
	//
	// For now, return nil as placeholder
	_ = userID
	_ = clientID
	return nil
}

// listConsentsFromDB retrieves all consents for a user from the database.
// TODO: Replace with actual sqlc query: s.db.Queries().ListOAuthConsentsByUser(ctx, userID)
func (s *ConsentService) listConsentsFromDB(ctx context.Context, userID string) ([]Consent, error) {
	// TODO: Implement with actual DB query
	// query := `SELECT user_id, client_id, scopes, granted_at FROM oauth_consents WHERE user_id = ?`
	//
	// For now, return empty list as placeholder
	_ = userID
	return []Consent{}, nil
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
