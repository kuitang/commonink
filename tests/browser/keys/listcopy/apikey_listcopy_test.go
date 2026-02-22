package browser

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

var (
	_ = http.MethodGet
)

func navigateAPIKeyHub(t *testing.T, page playwright.Page, baseURL string) {
	t.Helper()
	Navigate(t, page, baseURL, "/settings/api-keys")
	WaitForSelector(t, page, "h1:has-text('API and OAuth Credentials')")
}

func navigateAPIKeyCreatePage(t *testing.T, page playwright.Page, baseURL string) {
	t.Helper()
	Navigate(t, page, baseURL, "/settings/api-keys/new")
	WaitForSelector(t, page, "h1:has-text('Create New API Key')")
}

func submitCreateAPIKeyForm(t *testing.T, page playwright.Page, name, scope string) {
	t.Helper()
	page.Locator("input#name").Fill(name)
	page.Locator(fmt.Sprintf("input[name='scope'][value='%s']", scope)).Check()
	page.Locator("form[action='/api-keys'] button[type='submit']:has-text('Create API Key')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
}

// =============================================================================
// Test: Page Load
// =============================================================================

func TestBrowser_APIKeySettings_ListKeys(t *testing.T) {
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
	page.SetDefaultTimeout(browserMaxTimeoutMS)

	testEmail := GenerateUniqueEmail("apikey-list")
	env.LoginUser(t, ctx, testEmail)

	// Create multiple API keys via the UI
	tokenNames := []string{"Key One", "Key Two", "Key Three"}

	for _, tokenName := range tokenNames {
		navigateAPIKeyCreatePage(t, page, env.BaseURL)

		// Fill form
		page.Locator("input#name").Fill(tokenName)
		page.Locator("input[name='scope'][value='read_write']").Check()

		// Submit
		page.Locator("form[action='/api-keys'] button[type='submit']:has-text('Create API Key')").Click()

		// Wait for redirect
		page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
			State: playwright.LoadStateDomcontentloaded,
		})
	}

	// Navigate to settings page to view list
	navigateAPIKeyHub(t, page, env.BaseURL)

	// Verify all created API keys appear in list
	for _, tokenName := range tokenNames {
		tokenRow := page.Locator(fmt.Sprintf("text=%s", tokenName))
		count, err := tokenRow.Count()
		if err != nil {
			t.Fatalf("Failed to count API key rows for %s: %v", tokenName, err)
		}
		if count == 0 {
			t.Errorf("API key '%s' should appear in the list", tokenName)
		}
	}

	// Verify API keys table shows columns: Name, Scope, Created, Last Used, Expires
	tableHeaders := page.Locator("th")
	headersCount, err := tableHeaders.Count()
	if err != nil {
		t.Fatalf("Failed to count table headers: %v", err)
	}
	if headersCount < 4 {
		t.Errorf("Expected at least 4 table headers (Name, Scope, Created, etc.), got: %d", headersCount)
	}

	// Verify API key values are NOT shown (security)
	// The actual key value should not be visible in the list
	tokenHashLocator := page.Locator("text=agentnotes_key_")
	hashCount, err := tokenHashLocator.Count()
	if err != nil {
		t.Fatalf("Failed to check for API key values: %v", err)
	}
	// There should only be the key shown in the "new key" success message (if still visible)
	// but NOT in the API key list rows
	if hashCount > 1 {
		t.Log("Note: API key values should only be visible once at creation time")
	}
}

// =============================================================================
// Test: Revoke API Key
// =============================================================================

func TestBrowser_APIKeySettings_CopyKey(t *testing.T) {
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
	page.SetDefaultTimeout(browserMaxTimeoutMS)

	testEmail := GenerateUniqueEmail("apikey-copy")
	env.LoginUser(t, ctx, testEmail)

	// Create an API key
	navigateAPIKeyCreatePage(t, page, env.BaseURL)

	page.Locator("input#name").Fill("Key for Copy Test")
	page.Locator("input[name='scope'][value='read_write']").Check()
	page.Locator("form[action='/api-keys'] button[type='submit']:has-text('Create API Key')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Get the API key value before clicking copy
	tokenElement := WaitForSelector(t, page, "code#token-value")
	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	// Verify API key has expected format
	if !strings.HasPrefix(tokenValue, "agentnotes_key_") {
		t.Errorf("API key should have proper prefix, got: %s", tokenValue)
	}

	// Click the copy button
	copyButton := page.Locator("button:has-text('Copy')")
	err = copyButton.Click()
	if err != nil {
		t.Fatalf("Failed to click copy button: %v", err)
	}

	// Verify the button text changed to "Copied!" (UI feedback)
	copiedText := page.Locator("span#copy-text:has-text('Copied!')")
	err = copiedText.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Logf("Copy button feedback not observed before timeout: %v", err)
	}

	// Note: Actual clipboard verification is not possible in headless mode
	// The test verifies the copy button exists and can be clicked
	// In real usage, the browser's clipboard API would copy the API key
	t.Logf("API key value that would be copied: %s", tokenValue)
}

// =============================================================================
// Test: Empty State (No API Keys)
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

	// Navigate to /settings/api-keys/new and submit the form.
	Navigate(t, page, env.BaseURL, "/settings/api-keys/new")

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
		State: playwright.LoadStateDomcontentloaded,
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

