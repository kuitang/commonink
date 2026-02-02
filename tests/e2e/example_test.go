package e2e

import (
	"testing"

	"pgregory.net/rapid"
)

// =============================================================================
// Property: Basic arithmetic properties (placeholder for E2E tests)
// =============================================================================

// testArithmetic_Commutative_Properties tests the commutative property of addition
// This is a placeholder demonstrating property-based testing for E2E tests.
// Real E2E tests should test HTTP endpoints with the notes API.
func testArithmetic_Commutative_Properties(t *rapid.T) {
	a := rapid.Int().Draw(t, "a")
	b := rapid.Int().Draw(t, "b")

	// Property: Addition is commutative (a + b == b + a)
	if a+b != b+a {
		t.Fatalf("Commutative property violated: %d + %d != %d + %d", a, b, b, a)
	}
}

func TestArithmetic_Commutative_Properties(t *testing.T) {
	rapid.Check(t, testArithmetic_Commutative_Properties)
}

func FuzzArithmetic_Commutative_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testArithmetic_Commutative_Properties))
}

// =============================================================================
// Property: Associative property of addition
// =============================================================================

func testArithmetic_Associative_Properties(t *rapid.T) {
	a := rapid.IntRange(-1000, 1000).Draw(t, "a")
	b := rapid.IntRange(-1000, 1000).Draw(t, "b")
	c := rapid.IntRange(-1000, 1000).Draw(t, "c")

	// Property: Addition is associative ((a + b) + c == a + (b + c))
	if (a+b)+c != a+(b+c) {
		t.Fatalf("Associative property violated: (%d + %d) + %d != %d + (%d + %d)", a, b, c, a, b, c)
	}
}

func TestArithmetic_Associative_Properties(t *testing.T) {
	rapid.Check(t, testArithmetic_Associative_Properties)
}

func FuzzArithmetic_Associative_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testArithmetic_Associative_Properties))
}
