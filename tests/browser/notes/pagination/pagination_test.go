package browser

import (
	"fmt"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestBrowser_NotesCRUD_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	testEmail := GenerateUniqueEmail("test-pagination")
	env.LoginUser(t, ctx, testEmail)

	// Use UI-only note creation for pagination coverage.
	// Notes page size is 12; 13 is the minimum count that produces page 2.
	for i := 1; i <= 13; i++ {
		CreateNoteViaUI(
			t,
			page,
			env.BaseURL,
			fmt.Sprintf("Pagination Test Note %02d", i),
			fmt.Sprintf("Content for pagination test note %d", i),
		)
	}

	// Set desktop viewport to ensure pagination buttons are visible
	page.SetViewportSize(1280, 800)

	// Navigate to notes list
	Navigate(t, page, env.BaseURL, "/notes")

	// Wait for page to load
	WaitForSelector(t, page, "h1:has-text('My Notes')")

	// Verify pagination is shown
	paginationNav := page.Locator("nav[aria-label='Pagination']")
	err = paginationNav.First().WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		// Debug: show page content
		content, _ := page.Content()
		if len(content) > 1000 {
			content = content[:1000] + "..."
		}
		t.Fatalf("Pagination should be visible with 13 notes. Page content: %s", content)
	}

	// Click "Next" to go to page 2 - target the visible desktop button
	nextButton := page.Locator("nav[aria-label='Pagination'] nav a[href*='page=2']")

	err = nextButton.First().Click()
	if err != nil {
		t.Fatalf("Failed to click next button: %v", err)
	}

	// Wait for page 2 to load by waiting for previous button to be visible
	prevButton := page.Locator("nav[aria-label='Pagination'] nav a[href*='page=1']")
	err = prevButton.First().WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		currentURL := page.URL()
		t.Fatalf("Failed to navigate to page 2 - prev button not visible. Current URL: %s, error: %v", currentURL, err)
	}

	// Verify we're actually on page 2
	currentURL := page.URL()
	if !strings.Contains(currentURL, "page=2") {
		t.Errorf("Expected URL to contain 'page=2', got: %s", currentURL)
	}
}

// =============================================================================
// Test: Empty State
// =============================================================================

