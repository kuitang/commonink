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

func TestBrowser_APIKeySettings_UseKeyForAPICall(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-api-call")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to /settings/api-keys/new
	navigateAPIKeyCreatePage(t, page, env.BaseURL)

	// Create an API key
	page.Locator("input#name").Fill("Key for API Test")
	page.Locator("input[name='scope'][value='read_write']").Check()
	page.Locator("form[action='/api-keys'] button[type='submit']:has-text('Create API Key')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Get the API key value
	tokenElement := WaitForSelector(t, page, "code#token-value")
	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	// Verify API key has expected format
	if !strings.HasPrefix(tokenValue, "agentnotes_key_") {
		t.Fatalf("API key should have proper prefix, got: %s", tokenValue)
	}

	// Use the API key for an API call (GET /api/notes)
	// We need to make a direct HTTP request to the test server
	req, err := http.NewRequest("GET", env.BaseURL+"/api/notes", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenValue)

	client := &http.Client{Timeout: browserMaxTimeout}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make API request: %v", err)
	}
	defer resp.Body.Close()

	// The API should accept the API key
	// Note: The actual response depends on whether /api/notes is registered
	// but we should at least not get a 401 Unauthorized
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("API call with valid API key should not return 401, got status: %d", resp.StatusCode)
	}

	t.Logf("API call with API key returned status: %d", resp.StatusCode)
}

// =============================================================================
// Test: Revoked API Key Fails API Call
// =============================================================================

func TestBrowser_APIKeySettings_RevokedKeyFailsAPI(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-revoke-api")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to /settings/api-keys/new
	navigateAPIKeyCreatePage(t, page, env.BaseURL)

	// Create an API key
	tokenName := "Key to Revoke for API"
	nameInput := WaitForSelector(t, page, "input#name")
	err = nameInput.Fill(tokenName)
	if err != nil {
		t.Fatalf("Failed to fill API key name: %v", err)
	}

	scopeSelect := WaitForSelector(t, page, "input[name='scope'][value='read_write']")
	err = scopeSelect.Check()
	if err != nil {
		t.Fatalf("Failed to select scope: %v", err)
	}

	submitButton := page.Locator("form[action='/api-keys'] button[type='submit']:has-text('Create API Key')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Wait for page to reload with new API key
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not reload: %v", err)
	}

	// Wait for API key element to appear with extended timeout
	// The key is displayed in code#token-value on the created key page.
	tokenElement := page.Locator("code#token-value")
	err = tokenElement.First().WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		// Debug: log page content
		pageContent, _ := page.Content()
		t.Logf("Page content (first 500 chars): %s", pageContent[:min(500, len(pageContent))])
		t.Fatalf("API key value element not found: %v", err)
	}

	tokenValue, err := tokenElement.First().TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	// Verify the API key works before revocation
	req1, err := http.NewRequest("GET", env.BaseURL+"/api/notes", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req1.Header.Set("Authorization", "Bearer "+tokenValue)

	client := &http.Client{Timeout: browserMaxTimeout}
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("Failed to make API request before revocation: %v", err)
	}
	resp1.Body.Close()

	if resp1.StatusCode == http.StatusUnauthorized {
		t.Errorf("API key should work before revocation, got status: %d", resp1.StatusCode)
	}
	t.Logf("Before revocation, API returned status: %d", resp1.StatusCode)

	// Navigate to API keys page to revoke
	navigateAPIKeyHub(t, page, env.BaseURL)

	// Set up dialog handler for confirmation
	page.OnDialog(func(dialog playwright.Dialog) {
		dialog.Accept()
	})

	// Click "Revoke" button for the API key
	revokeButton := page.Locator(fmt.Sprintf("tr:has-text('%s') button:has-text('Revoke')", tokenName))
	err = revokeButton.Click()
	if err != nil {
		t.Fatalf("Failed to click Revoke button: %v", err)
	}

	// Wait for page to reload
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Verify API key no longer works via API
	req2, err := http.NewRequest("GET", env.BaseURL+"/api/notes", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req2.Header.Set("Authorization", "Bearer "+tokenValue)

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("Failed to make API request after revocation: %v", err)
	}
	defer resp2.Body.Close()

	// The API should reject the revoked API key with 401 Unauthorized
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("API call with revoked API key should return 401, got status: %d", resp2.StatusCode)
	}

	t.Logf("After revocation, API returned status: %d (expected 401)", resp2.StatusCode)
}

// =============================================================================
// Test: Navigate Away and Back - API Key Masked
// =============================================================================

func TestBrowser_APIKeySettings_NavigateAwayMasksKey(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-navigate-mask")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to /settings/api-keys/new
	navigateAPIKeyCreatePage(t, page, env.BaseURL)

	// Create an API key
	tokenName := "Key for Navigate Test"
	page.Locator("input#name").Fill(tokenName)
	page.Locator("input[name='scope'][value='read_write']").Check()
	page.Locator("form[action='/api-keys'] button[type='submit']:has-text('Create API Key')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Verify API key is displayed
	tokenElement := WaitForSelector(t, page, "code#token-value")
	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	if !strings.HasPrefix(tokenValue, "agentnotes_key_") {
		t.Errorf("API key should be visible immediately after creation")
	}

	// Navigate away to /notes
	Navigate(t, page, env.BaseURL, "/notes")
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Navigate back to /settings/api-keys
	navigateAPIKeyHub(t, page, env.BaseURL)

	// The API key element should not be visible on the settings page after navigation.
	newTokenElement := page.Locator("code#token-value")
	err = newTokenElement.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})

	// We EXPECT this to timeout/fail because the API key should NOT be visible
	if err == nil {
		// The element is visible - check if it contains the actual API key
		displayedToken, _ := newTokenElement.TextContent()
		if displayedToken == tokenValue {
			t.Error("Full API key value should NOT be visible after navigating away and back")
		}
	}

	// Verify the API key is listed but not in raw form
	tokenRow := page.Locator(fmt.Sprintf("text=%s", tokenName))
	count, err := tokenRow.Count()
	if err != nil {
		t.Fatalf("Failed to count API key rows: %v", err)
	}
	if count == 0 {
		t.Error("API key should still appear in the list by name")
	}

	// API key list should show masked values (not full key)
	// Look for "agentnotes_key_" prefix in the table - there should be none
	// because the list shows key names, not raw values
	listContent := page.Locator("table")
	tableContent, _ := listContent.TextContent()
	if strings.Contains(tableContent, tokenValue) {
		t.Error("API key list should not contain the full raw key value")
	}
}
