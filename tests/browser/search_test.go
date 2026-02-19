// Package browser contains Playwright E2E tests for browser-based UI flows.
// This file tests the typeahead search bar on the notes list page.
//
// Regression coverage:
// - FTS5 Porter stemming (searching "runs" finds notes containing "running")
// - Prefix matching (searching "pub" finds notes containing "publish", "publishing")
// - Multi-word prefix matching (searching "pub test" finds notes with both prefixes)
// - No-results empty state
// - Search clears and restores original grid
// - Keyboard shortcuts (/ to focus, Escape to clear)
package browser

import (
	"strings"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

// TestBrowser_Search_PorterStemming tests that FTS5 Porter stemming works through
// the search UI. Searching for a different inflection of a word should find notes
// containing the original form.
func TestBrowser_Search_PorterStemming(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()

	email := GenerateUniqueEmail("search-stem")
	userID := env.LoginUser(t, ctx, email)

	// Seed notes with specific words for stemming and prefix tests
	env.CreateNoteForUser(t, userID, "Algorithm Performance", "The algorithm is running efficiently on large datasets.")
	env.CreateNoteForUser(t, userID, "Deployment Guide", "We deployed the application to production servers yesterday.")
	env.CreateNoteForUser(t, userID, "Unrelated Note", "This note has nothing to do with the others.")
	env.CreateNoteForUser(t, userID, "Publishing Workflow", "We are publishing the testing framework to the internal registry.")
	env.CreateNoteForUser(t, userID, "Public API Docs", "The public endpoint accepts authenticated requests only.")

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("failed to create page: %v", err)
	}
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/notes")

	// Verify search bar is present
	searchInput := WaitForSelector(t, page, "input#search-input")

	// === Test 1: Porter stemming — "runs" should match "running" ===
	err = searchInput.Fill("runs")
	if err != nil {
		t.Fatalf("failed to fill search: %v", err)
	}
	// Wait for debounce (250ms) + network
	time.Sleep(500 * time.Millisecond)

	results := page.Locator("#notes-search-results")
	err = results.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("search results did not appear: %v", err)
	}

	// Should find "Algorithm Performance" (contains "running", stems to "run")
	resultCards := results.Locator("article.themed-card")
	count, err := resultCards.Count()
	if err != nil {
		t.Fatalf("failed to count result cards: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 result for 'runs' (stemming → running), got %d", count)
	}

	resultText, err := results.TextContent()
	if err != nil {
		t.Fatalf("failed to get results text: %v", err)
	}
	if !strings.Contains(resultText, "Algorithm Performance") {
		t.Errorf("expected result to contain 'Algorithm Performance', got: %s", resultText)
	}

	// === Test 2: Porter stemming — "deploy" should match "deployed" ===
	err = searchInput.Fill("deploy")
	if err != nil {
		t.Fatalf("failed to fill search: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	resultCards = results.Locator("article.themed-card")
	count, err = resultCards.Count()
	if err != nil {
		t.Fatalf("failed to count result cards: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 result for 'deploy' (stemming → deployed), got %d", count)
	}

	resultText, err = results.TextContent()
	if err != nil {
		t.Fatalf("failed to get results text: %v", err)
	}
	if !strings.Contains(resultText, "Deployment Guide") {
		t.Errorf("expected result to contain 'Deployment Guide', got: %s", resultText)
	}

	// === Test 3: No results for gibberish ===
	err = searchInput.Fill("xyzqwerty9999")
	if err != nil {
		t.Fatalf("failed to fill search: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	noResultsMsg := results.Locator("p")
	isVisible, err := noResultsMsg.IsVisible()
	if err != nil {
		t.Fatalf("failed to check no-results message: %v", err)
	}
	if !isVisible {
		t.Error("expected 'No notes matching' message for gibberish query")
	}
	noResultsText, err := noResultsMsg.TextContent()
	if err != nil {
		t.Fatalf("failed to get no-results text: %v", err)
	}
	if !strings.Contains(noResultsText, "No notes matching") {
		t.Errorf("expected no-results message, got: %s", noResultsText)
	}

	// === Test 4: Prefix matching — "pub" should match "publishing" and "public" ===
	err = searchInput.Fill("pub")
	if err != nil {
		t.Fatalf("failed to fill search: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	resultCards = results.Locator("article.themed-card")
	count, err = resultCards.Count()
	if err != nil {
		t.Fatalf("failed to count result cards: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 results for prefix 'pub' (matching 'publishing' and 'public'), got %d", count)
	}

	resultText, err = results.TextContent()
	if err != nil {
		t.Fatalf("failed to get results text: %v", err)
	}
	if !strings.Contains(resultText, "Publishing Workflow") {
		t.Errorf("expected prefix 'pub' to match 'Publishing Workflow', got: %s", resultText)
	}
	if !strings.Contains(resultText, "Public API Docs") {
		t.Errorf("expected prefix 'pub' to match 'Public API Docs', got: %s", resultText)
	}

	// === Test 5: Multi-word prefix — "pub test" should match notes with both prefixes ===
	err = searchInput.Fill("pub test")
	if err != nil {
		t.Fatalf("failed to fill search: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	resultCards = results.Locator("article.themed-card")
	count, err = resultCards.Count()
	if err != nil {
		t.Fatalf("failed to count result cards: %v", err)
	}
	// "Publishing Workflow" contains "publishing" (matches "pub*") and "testing" (matches "test*")
	// "Public API Docs" has "public" (matches "pub*") but no word starting with "test"
	if count != 1 {
		t.Errorf("expected 1 result for multi-word prefix 'pub test' (matching 'publishing' + 'testing'), got %d", count)
	}

	resultText, err = results.TextContent()
	if err != nil {
		t.Fatalf("failed to get results text: %v", err)
	}
	if !strings.Contains(resultText, "Publishing Workflow") {
		t.Errorf("expected multi-word prefix 'pub test' to match 'Publishing Workflow', got: %s", resultText)
	}
}

// TestBrowser_Search_RestoreOnClear tests that clearing the search input restores
// the original notes grid and pagination.
func TestBrowser_Search_RestoreOnClear(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()

	email := GenerateUniqueEmail("search-restore")
	userID := env.LoginUser(t, ctx, email)

	// Seed 3 notes
	env.CreateNoteForUser(t, userID, "First Note", "Alpha content")
	env.CreateNoteForUser(t, userID, "Second Note", "Beta content")
	env.CreateNoteForUser(t, userID, "Third Note", "Gamma content")

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("failed to create page: %v", err)
	}
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/notes")

	// Count original cards
	originalGrid := page.Locator("#notes-original")
	originalCards := originalGrid.Locator("article.themed-card")
	origCount, err := originalCards.Count()
	if err != nil {
		t.Fatalf("failed to count original cards: %v", err)
	}
	if origCount != 3 {
		t.Fatalf("expected 3 original cards, got %d", origCount)
	}

	// Search for something
	searchInput := WaitForSelector(t, page, "input#search-input")
	err = searchInput.Fill("Alpha")
	if err != nil {
		t.Fatalf("failed to fill search: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Original grid should be hidden
	isOrigHidden, err := originalGrid.IsHidden()
	if err != nil {
		t.Fatalf("failed to check original grid visibility: %v", err)
	}
	if !isOrigHidden {
		t.Error("original grid should be hidden during search")
	}

	// Clear the search input
	err = searchInput.Fill("")
	if err != nil {
		t.Fatalf("failed to clear search: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Original grid should be restored
	isOrigVisible, err := originalGrid.IsVisible()
	if err != nil {
		t.Fatalf("failed to check original grid restored: %v", err)
	}
	if !isOrigVisible {
		t.Error("original grid should be visible after clearing search")
	}

	// All 3 cards should still be there (originals never destroyed)
	restoredCount, err := originalCards.Count()
	if err != nil {
		t.Fatalf("failed to count restored cards: %v", err)
	}
	if restoredCount != 3 {
		t.Errorf("expected 3 cards after restore, got %d", restoredCount)
	}
}

// TestBrowser_Search_KeyboardShortcuts tests / to focus and Escape to clear+blur.
func TestBrowser_Search_KeyboardShortcuts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()

	email := GenerateUniqueEmail("search-keys")
	userID := env.LoginUser(t, ctx, email)

	env.CreateNoteForUser(t, userID, "Keyboard Test", "Testing keyboard shortcuts")

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("failed to create page: %v", err)
	}
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/notes")
	WaitForSelector(t, page, "input#search-input")

	// Press / to focus the search input
	err = page.Keyboard().Press("/")
	if err != nil {
		t.Fatalf("failed to press /: %v", err)
	}

	// Verify search input is focused
	focused, err := page.Evaluate("document.activeElement.id")
	if err != nil {
		t.Fatalf("failed to check focused element: %v", err)
	}
	if focused != "search-input" {
		t.Errorf("expected search-input to be focused after /, got: %v", focused)
	}

	// Type a query
	err = page.Keyboard().Type("Keyboard")
	if err != nil {
		t.Fatalf("failed to type query: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Verify search results appeared
	results := page.Locator("#notes-search-results")
	isResultsVisible, err := results.IsVisible()
	if err != nil {
		t.Fatalf("failed to check results: %v", err)
	}
	if !isResultsVisible {
		t.Error("search results should be visible after typing")
	}

	// Press Escape to clear and blur
	err = page.Keyboard().Press("Escape")
	if err != nil {
		t.Fatalf("failed to press Escape: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Verify input is cleared
	inputValue, err := page.Locator("#search-input").InputValue()
	if err != nil {
		t.Fatalf("failed to get input value: %v", err)
	}
	if inputValue != "" {
		t.Errorf("expected empty input after Escape, got: %s", inputValue)
	}

	// Verify original grid is restored
	isOrigVisible, err := page.Locator("#notes-original").IsVisible()
	if err != nil {
		t.Fatalf("failed to check original grid: %v", err)
	}
	if !isOrigVisible {
		t.Error("original grid should be visible after Escape")
	}

	// Verify search input is blurred
	focused, err = page.Evaluate("document.activeElement.id")
	if err != nil {
		t.Fatalf("failed to check focused element after Escape: %v", err)
	}
	if focused == "search-input" {
		t.Error("search input should be blurred after Escape")
	}
}
