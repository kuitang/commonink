// Package testutil provides shared rapid generators for property-based tests.
// All e2e tests should use these generators instead of defining their own.
package testutil

import "pgregory.net/rapid"

// =============================================================================
// Email/Password Generators
// =============================================================================

// EmailGenerator generates valid email addresses for testing.
func EmailGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z]{5,10}@example\.com`)
}

// PasswordGenerator generates valid passwords (8+ chars with mix of types).
func PasswordGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9!@#]{12,20}`)
}

// WeakPasswordGenerator generates weak passwords (less than 8 chars) for testing validation.
func WeakPasswordGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z]{1,7}`)
}

// =============================================================================
// Note Generators
// =============================================================================

// NoteTitleGenerator generates valid note titles (non-empty strings).
func NoteTitleGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z][A-Za-z0-9 ]{4,49}`)
}

// NoteContentGenerator generates note content (can be empty).
func NoteContentGenerator() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.Just(""),
		rapid.StringMatching(`[A-Za-z0-9 .,!?]{1,200}`),
	)
}

// NoteSearchTermGenerator generates valid search terms.
func NoteSearchTermGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z]{4,15}`)
}

// =============================================================================
// OAuth Generators
// =============================================================================

// StateGenerator generates valid OAuth state parameters.
func StateGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-zA-Z0-9_-]{16,64}`)
}

// ScopeGenerator generates valid OAuth scopes.
func ScopeGenerator() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{"notes:read", "notes:write", "notes:read notes:write"})
}

// ClientNameGenerator generates valid OAuth client names.
func ClientNameGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z][A-Za-z0-9 _-]{2,30}`)
}

// PKCEVerifierGenerator generates valid PKCE verifiers (43-128 chars, URL-safe).
func PKCEVerifierGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9_-]{43,128}`)
}

// =============================================================================
// OIDC Generators
// =============================================================================

// OIDCSubjectGenerator generates valid OIDC subject identifiers.
func OIDCSubjectGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z0-9]{20,40}`)
}

// OIDCNameGenerator generates valid OIDC user names.
func OIDCNameGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z][A-Za-z ]{2,30}`)
}

// =============================================================================
// Shared Fixture Constants
// =============================================================================

// SharedFixtureSessionTables is the canonical list of session DB tables that
// must be cleared when resetting a shared test fixture. Used by both e2e and
// browser test packages to avoid duplicating the table list.
var SharedFixtureSessionTables = []string{
	"sessions",
	"magic_tokens",
	"user_keys",
	"oauth_clients",
	"oauth_tokens",
	"oauth_codes",
	"oauth_consents",
	"short_urls",
}
