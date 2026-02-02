package e2e

import (
	"testing"
)

func TestExample(t *testing.T) {
	// Simple test to verify CI works
	if 1+1 != 2 {
		t.Fatal("math is broken")
	}
}
