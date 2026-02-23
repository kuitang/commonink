package auth

import (
	"testing"

	"pgregory.net/rapid"
)

// TestSessionID_HighEntropy tests that session IDs have high entropy.
func TestSessionID_HighEntropy(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		id1, err := generateSessionID()
		if err != nil {
			t.Fatalf("first generateSessionID failed: %v", err)
		}

		id2, err := generateSessionID()
		if err != nil {
			t.Fatalf("second generateSessionID failed: %v", err)
		}

		// Session IDs should never collide
		if id1 == id2 {
			t.Fatalf("session IDs collided: %s", id1)
		}

		// Should be base64 encoded 32 bytes = 44 characters (with padding)
		// or 43 without padding in URL encoding
		if len(id1) < 43 {
			t.Fatalf("session ID too short: %d chars", len(id1))
		}
	})
}

// TestSessionID_Length tests that session IDs have correct length.
func TestSessionID_Length(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		id, err := generateSessionID()
		if err != nil {
			t.Fatalf("generateSessionID failed: %v", err)
		}

		// Base64 encoding of 32 bytes = ceil(32 * 4 / 3) = 43 chars (URL encoding no padding)
		// or 44 with padding
		expectedMinLen := 43
		if len(id) < expectedMinLen {
			t.Fatalf("session ID length %d < expected min %d", len(id), expectedMinLen)
		}
	})
}
