package auth

import (
	"context"
	"sort"
	"testing"

	"github.com/kuitang/agent-notes/internal/testdb"
	"pgregory.net/rapid"
)

// setupConsentTestDB creates a fresh in-memory sessions database for consent testing.
func setupConsentTestDB(t *rapid.T) *ConsentService {
	sessionsDB, err := testdb.NewSessionsDBInMemory()
	if err != nil {
		t.Fatalf("failed to create in-memory sessions database: %v", err)
	}
	return NewConsentService(sessionsDB)
}

// validScopeGen generates valid OAuth scope strings (no whitespace, no empty).
func validScopeGen() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z]{1,8}:[a-z]{1,8}`)
}

// validScopeListGen generates a non-empty list of unique valid scopes.
func validScopeListGen() *rapid.Generator[[]string] {
	return rapid.Custom(func(t *rapid.T) []string {
		n := rapid.IntRange(1, 5).Draw(t, "numScopes")
		seen := make(map[string]bool)
		scopes := make([]string, 0, n)
		for len(scopes) < n {
			s := validScopeGen().Draw(t, "scope")
			if !seen[s] {
				seen[s] = true
				scopes = append(scopes, s)
			}
		}
		sort.Strings(scopes)
		return scopes
	})
}

// validIDGen generates valid user/client IDs.
func validIDGen() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z]{2,10}-[0-9]{1,5}`)
}

// TestConsent_RecordThenHas_Roundtrip tests the core property:
// recording consent and then checking it returns true for the same scopes.
func TestConsent_RecordThenHas_Roundtrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		svc := setupConsentTestDB(t)
		ctx := context.Background()

		userID := validIDGen().Draw(t, "userID")
		clientID := validIDGen().Draw(t, "clientID")
		scopes := validScopeListGen().Draw(t, "scopes")

		// Record consent
		err := svc.RecordConsent(ctx, userID, clientID, scopes)
		if err != nil {
			t.Fatalf("RecordConsent failed: %v", err)
		}

		// Property: HasConsent returns true for the recorded scopes
		has, err := svc.HasConsent(ctx, userID, clientID, scopes)
		if err != nil {
			t.Fatalf("HasConsent failed: %v", err)
		}
		if !has {
			t.Fatalf("HasConsent returned false after RecordConsent for scopes %v", scopes)
		}
	})
}

// TestConsent_HasConsent_FalseBeforeRecord tests that HasConsent returns false
// when no consent has been recorded.
func TestConsent_HasConsent_FalseBeforeRecord(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		svc := setupConsentTestDB(t)
		ctx := context.Background()

		userID := validIDGen().Draw(t, "userID")
		clientID := validIDGen().Draw(t, "clientID")
		scopes := validScopeListGen().Draw(t, "scopes")

		// Property: HasConsent returns false when no consent exists
		has, err := svc.HasConsent(ctx, userID, clientID, scopes)
		if err != nil {
			t.Fatalf("HasConsent failed: %v", err)
		}
		if has {
			t.Fatalf("HasConsent returned true before any RecordConsent")
		}
	})
}

// TestConsent_RecordMergesScopes tests that recording consent twice merges scopes.
func TestConsent_RecordMergesScopes(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		svc := setupConsentTestDB(t)
		ctx := context.Background()

		userID := validIDGen().Draw(t, "userID")
		clientID := validIDGen().Draw(t, "clientID")

		// Generate two disjoint scope sets
		allScopes := rapid.SliceOfNDistinct(validScopeGen(), 2, 6, rapid.ID[string]).Draw(t, "allScopes")
		mid := len(allScopes) / 2
		if mid == 0 {
			mid = 1
		}
		scopes1 := allScopes[:mid]
		scopes2 := allScopes[mid:]

		// Record first set
		err := svc.RecordConsent(ctx, userID, clientID, scopes1)
		if err != nil {
			t.Fatalf("first RecordConsent failed: %v", err)
		}

		// Record second set
		err = svc.RecordConsent(ctx, userID, clientID, scopes2)
		if err != nil {
			t.Fatalf("second RecordConsent failed: %v", err)
		}

		// Property: HasConsent returns true for the union of both sets
		has, err := svc.HasConsent(ctx, userID, clientID, allScopes)
		if err != nil {
			t.Fatalf("HasConsent failed: %v", err)
		}
		if !has {
			t.Fatalf("HasConsent returned false for union of scopes %v after two RecordConsent calls", allScopes)
		}
	})
}

// TestConsent_RevokeRemovesConsent tests that revoking consent makes HasConsent return false.
func TestConsent_RevokeRemovesConsent(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		svc := setupConsentTestDB(t)
		ctx := context.Background()

		userID := validIDGen().Draw(t, "userID")
		clientID := validIDGen().Draw(t, "clientID")
		scopes := validScopeListGen().Draw(t, "scopes")

		// Record consent
		err := svc.RecordConsent(ctx, userID, clientID, scopes)
		if err != nil {
			t.Fatalf("RecordConsent failed: %v", err)
		}

		// Revoke it
		err = svc.RevokeConsent(ctx, userID, clientID)
		if err != nil {
			t.Fatalf("RevokeConsent failed: %v", err)
		}

		// Property: HasConsent returns false after revocation
		has, err := svc.HasConsent(ctx, userID, clientID, scopes)
		if err != nil {
			t.Fatalf("HasConsent failed: %v", err)
		}
		if has {
			t.Fatalf("HasConsent returned true after RevokeConsent")
		}
	})
}

// TestConsent_ListConsentsRoundtrip tests that listing consents reflects recorded consents.
func TestConsent_ListConsentsRoundtrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		svc := setupConsentTestDB(t)
		ctx := context.Background()

		userID := validIDGen().Draw(t, "userID")
		numClients := rapid.IntRange(1, 4).Draw(t, "numClients")

		type consentEntry struct {
			clientID string
			scopes   []string
		}
		entries := make([]consentEntry, 0, numClients)
		clientIDs := rapid.SliceOfNDistinct(validIDGen(), numClients, numClients, rapid.ID[string]).Draw(t, "clientIDs")

		for _, cid := range clientIDs {
			scopes := validScopeListGen().Draw(t, "scopes")
			err := svc.RecordConsent(ctx, userID, cid, scopes)
			if err != nil {
				t.Fatalf("RecordConsent failed for client %s: %v", cid, err)
			}
			entries = append(entries, consentEntry{clientID: cid, scopes: scopes})
		}

		// Property: ListConsentsForUser returns all recorded consents
		consents, err := svc.ListConsentsForUser(ctx, userID)
		if err != nil {
			t.Fatalf("ListConsentsForUser failed: %v", err)
		}
		if len(consents) != len(entries) {
			t.Fatalf("ListConsentsForUser returned %d consents, expected %d", len(consents), len(entries))
		}

		// Check each entry exists
		consentMap := make(map[string][]string)
		for _, c := range consents {
			consentMap[c.ClientID] = c.Scopes
		}
		for _, e := range entries {
			stored, ok := consentMap[e.clientID]
			if !ok {
				t.Fatalf("consent for client %s not found in list", e.clientID)
			}
			sort.Strings(stored)
			sort.Strings(e.scopes)
			if len(stored) != len(e.scopes) {
				t.Fatalf("scopes mismatch for client %s: got %v, want %v", e.clientID, stored, e.scopes)
			}
			for i := range stored {
				if stored[i] != e.scopes[i] {
					t.Fatalf("scope mismatch for client %s at index %d: got %q, want %q", e.clientID, i, stored[i], e.scopes[i])
				}
			}
		}
	})
}

// TestConsent_Isolation tests that consent for one user/client pair does not affect another.
func TestConsent_Isolation(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		svc := setupConsentTestDB(t)
		ctx := context.Background()

		userID1 := validIDGen().Draw(t, "userID1")
		userID2 := validIDGen().Draw(t, "userID2")
		clientID := validIDGen().Draw(t, "clientID")
		scopes := validScopeListGen().Draw(t, "scopes")

		// Avoid collision
		if userID1 == userID2 {
			return
		}

		// Record consent only for user1
		err := svc.RecordConsent(ctx, userID1, clientID, scopes)
		if err != nil {
			t.Fatalf("RecordConsent failed: %v", err)
		}

		// Property: user2 should NOT have consent
		has, err := svc.HasConsent(ctx, userID2, clientID, scopes)
		if err != nil {
			t.Fatalf("HasConsent failed: %v", err)
		}
		if has {
			t.Fatalf("user2 has consent that was only granted to user1")
		}
	})
}

// TestConsent_GetPendingConsent_AllPendingWithNoRecord tests that GetPendingConsent
// returns all requested scopes when no consent exists.
func TestConsent_GetPendingConsent_AllPendingWithNoRecord(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		svc := setupConsentTestDB(t)
		ctx := context.Background()

		userID := validIDGen().Draw(t, "userID")
		clientID := validIDGen().Draw(t, "clientID")
		scopes := validScopeListGen().Draw(t, "scopes")

		pending, err := svc.GetPendingConsent(ctx, userID, clientID, scopes)
		if err != nil {
			t.Fatalf("GetPendingConsent failed: %v", err)
		}

		// Property: all scopes should be pending
		sort.Strings(pending.Scopes)
		sort.Strings(scopes)
		if len(pending.Scopes) != len(scopes) {
			t.Fatalf("pending scopes count mismatch: got %d, want %d", len(pending.Scopes), len(scopes))
		}
		for i := range pending.Scopes {
			if pending.Scopes[i] != scopes[i] {
				t.Fatalf("pending scope mismatch at index %d: got %q, want %q", i, pending.Scopes[i], scopes[i])
			}
		}
	})
}

// TestConsent_GetPendingConsent_NoneNeededAfterRecord tests that GetPendingConsent
// returns ErrNoConsentNeeded when all scopes are already consented.
func TestConsent_GetPendingConsent_NoneNeededAfterRecord(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		svc := setupConsentTestDB(t)
		ctx := context.Background()

		userID := validIDGen().Draw(t, "userID")
		clientID := validIDGen().Draw(t, "clientID")
		scopes := validScopeListGen().Draw(t, "scopes")

		// Record consent
		err := svc.RecordConsent(ctx, userID, clientID, scopes)
		if err != nil {
			t.Fatalf("RecordConsent failed: %v", err)
		}

		// Property: GetPendingConsent returns ErrNoConsentNeeded
		_, err = svc.GetPendingConsent(ctx, userID, clientID, scopes)
		if err != ErrNoConsentNeeded {
			t.Fatalf("GetPendingConsent should return ErrNoConsentNeeded, got: %v", err)
		}
	})
}
