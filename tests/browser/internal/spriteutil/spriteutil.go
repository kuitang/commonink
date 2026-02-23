// Package spriteutil provides shared Playwright navigation helpers for browser
// tests that interact with Sprite-backed app management pages.
package spriteutil

import (
	"testing"

	"github.com/playwright-community/playwright-go"
)

// TimeoutMS is the Playwright timeout (ms) for waits that depend on Sprite API
// calls (file listing, log fetching, bash commands) which go over the network.
// Sprite bash commands can take up to 120 s.
const TimeoutMS float64 = 120000

// Navigate goes to baseURL+path using DOMContentLoaded and the sprite timeout.
func Navigate(t *testing.T, page playwright.Page, baseURL, path string) {
	t.Helper()
	_, err := page.Goto(baseURL+path, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(TimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to %s: %v", path, err)
	}
}

// SetPageTimeouts sets both default and navigation timeouts to TimeoutMS.
func SetPageTimeouts(page playwright.Page) {
	page.SetDefaultTimeout(TimeoutMS)
	page.SetDefaultNavigationTimeout(TimeoutMS)
}
