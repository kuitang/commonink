// Package spriteutil provides shared navigation and timeout helpers for
// Playwright browser tests that exercise Sprite-backed applications.
package spriteutil

import (
	"testing"

	"github.com/playwright-community/playwright-go"
)

// SpriteTimeoutMS is the canonical timeout for all sprite-related Playwright
// waits and navigations. Do not use a different value in browser tests.
const SpriteTimeoutMS = 5000

// NavigateSprite navigates to baseURL+path with DomContentLoaded wait strategy
// and the canonical sprite timeout. Fails the test on error.
func NavigateSprite(t *testing.T, page playwright.Page, baseURL, path string) {
	t.Helper()
	_, err := page.Goto(baseURL+path, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(SpriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to %s: %v", path, err)
	}
}
