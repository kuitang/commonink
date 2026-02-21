// Package browser contains Playwright E2E tests for copy-to-clipboard buttons.
// These are deterministic scenario tests (NOT property-based) as per CLAUDE.md.
//
// This file tests that copy-to-clipboard buttons work correctly, including
// in non-HTTPS contexts where navigator.clipboard may be undefined.
//
// Prerequisites:
// - Install Playwright browsers: go run github.com/playwright-community/playwright-go/cmd/playwright install chromium
// - Run tests with: go test -v -run TestCopyButton ./tests/browser/...
package browser

import (
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// =============================================================================
// Test: Copy Button on API Key Created Page
// =============================================================================

func TestCopyButton_APIKeyCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// Create a browser context with clipboard permissions
	ctx := env.NewContext(t)
	defer ctx.Close()

	// Grant clipboard permissions
	err := ctx.GrantPermissions([]string{"clipboard-read", "clipboard-write"})
	if err != nil {
		t.Fatalf("Failed to grant clipboard permissions: %v", err)
	}

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(browserMaxTimeoutMS)

	testEmail := GenerateUniqueEmail("copy-apikey")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to /api-keys/new and submit the form.
	Navigate(t, page, env.BaseURL, "/api-keys/new")

	// Wait for form to load and fill in the key name
	nameInput := WaitForSelector(t, page, "input#name")
	err = nameInput.Fill("Test Copy Key")
	if err != nil {
		t.Fatalf("Failed to fill key name: %v", err)
	}

	// Submit the form using the specific Create API Key button
	submitButton := page.Locator("button[type='submit']:has-text('Create API Key')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Wait for the created page to render (it renders inline, not a redirect)
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Wait for the token value and copy button to be visible
	tokenElement := WaitForSelector(t, page, "code#token-value")
	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get token value: %v", err)
	}
	tokenValue = strings.TrimSpace(tokenValue)

	if !strings.HasPrefix(tokenValue, "agentnotes_key_") {
		t.Fatalf("Expected token to start with 'agentnotes_key_', got: %s", tokenValue)
	}

	// Wait for copy button to be visible
	WaitForSelector(t, page, "#copy-text")

	// Click the copy button (the parent button wrapping #copy-text)
	copyParent := page.Locator("button:has(#copy-text)")
	err = copyParent.Click()
	if err != nil {
		t.Fatalf("Failed to click copy button: %v", err)
	}

	// Wait for the button text to change to "Copied!"
	copiedText := page.Locator("#copy-text")
	_, err = page.WaitForFunction(`() => {
		var el = document.getElementById('copy-text');
		return el && el.textContent.trim() === 'Copied!';
	}`, nil, playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		currentText, _ := copiedText.TextContent()
		t.Fatalf("Copy button text did not change to 'Copied!'. Current text: %q, error: %v", currentText, err)
	}

	// Read the clipboard and verify
	clipboardResult, err := page.Evaluate("() => navigator.clipboard.readText()")
	if err != nil {
		t.Fatalf("Failed to read clipboard: %v", err)
	}

	clipboardValue, ok := clipboardResult.(string)
	if !ok {
		t.Fatalf("Clipboard result is not a string: %T", clipboardResult)
	}

	if !strings.HasPrefix(clipboardValue, "agentnotes_key_") {
		t.Errorf("Clipboard should contain API key starting with 'agentnotes_key_', got: %q", clipboardValue)
	}

	if strings.TrimSpace(clipboardValue) != tokenValue {
		t.Errorf("Clipboard value %q does not match token value %q", clipboardValue, tokenValue)
	}
}

// =============================================================================
// Test: Copy Button on Note Share URL
// =============================================================================

func TestCopyButton_NoteShareURL(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// Create a browser context with clipboard permissions
	ctx := env.NewContext(t)
	defer ctx.Close()

	// Grant clipboard permissions
	err := ctx.GrantPermissions([]string{"clipboard-read", "clipboard-write"})
	if err != nil {
		t.Fatalf("Failed to grant clipboard permissions: %v", err)
	}

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(browserMaxTimeoutMS)

	testEmail := GenerateUniqueEmail("copy-shareurl")
	env.LoginUser(t, ctx, testEmail)

	// Create a note via the UI
	CreateNoteViaUI(t, page, env.BaseURL, "Copy Share Test", "Test content for share URL copy")

	// Now we're on the note view page. Click "Make Public" to publish.
	shareURL := PublishNoteViaUI(t, page)

	if shareURL == "" {
		t.Fatal("Share URL is empty after publishing")
	}

	// Click the copy share URL button
	copyButton := WaitForSelector(t, page, "#copy-share-url")
	err = copyButton.Click()
	if err != nil {
		t.Fatalf("Failed to click copy share URL button: %v", err)
	}

	// Wait for the check icon to become visible (indicates copy success)
	// The JS toggles hidden class: copy-icon gets hidden, copy-check-icon gets unhidden
	_, err = page.WaitForFunction(`() => {
		var checkIcon = document.getElementById('copy-check-icon');
		return checkIcon && !checkIcon.classList.contains('hidden');
	}`, nil, playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Check icon did not become visible after clicking copy: %v", err)
	}

	// Read clipboard and verify
	clipboardResult, err := page.Evaluate("() => navigator.clipboard.readText()")
	if err != nil {
		t.Fatalf("Failed to read clipboard: %v", err)
	}

	clipboardValue, ok := clipboardResult.(string)
	if !ok {
		t.Fatalf("Clipboard result is not a string: %T", clipboardResult)
	}

	if clipboardValue != shareURL {
		t.Errorf("Clipboard value %q does not match share URL %q", clipboardValue, shareURL)
	}

	// The share URL should contain the note info (either note ID or short URL)
	if !strings.Contains(clipboardValue, "/") {
		t.Errorf("Clipboard value should be a URL, got: %q", clipboardValue)
	}
}
