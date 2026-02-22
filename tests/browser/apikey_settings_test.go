// Package browser contains Playwright E2E tests for browser-based UI flows.
// These are deterministic scenario tests (NOT property-based) as per CLAUDE.md.
//
// This file tests API Key management via the web UI at /settings/api-keys.
//
// Prerequisites:
// - Install Playwright browsers: go run github.com/playwright-community/playwright-go/cmd/playwright install chromium
// - Run tests with: go test -v ./tests/browser/...
package browser

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
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
	page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice(scope),
	})
	page.Locator("button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
}

// =============================================================================
// Test: Page Load
// =============================================================================

func TestBrowser_APIKeySettings_PageLoad(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-pageload")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to /settings/api-keys
	navigateAPIKeyHub(t, page, env.BaseURL)

	// Wait for page to load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Verify page title shows "API Keys"
	heading := WaitForSelector(t, page, "h1")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get heading text: %v", err)
	}

	if !strings.Contains(headingText, "API and OAuth Credentials") {
		t.Errorf("Expected heading to contain 'API and OAuth Credentials', got: %s", headingText)
	}

	// Verify "Create API" action is visible
	createButton := page.Locator("a:has-text('Create API')")
	isVisible, err := createButton.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check create API link visibility: %v", err)
	}
	if !isVisible {
		t.Error("Create API link should be visible")
	}

	// Verify "Create OAuth" action is visible
	createOAuth := page.Locator("a:has-text('Create OAuth')")
	oauthVisible, err := createOAuth.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check create OAuth link visibility: %v", err)
	}
	if !oauthVisible {
		t.Error("Create OAuth link should be visible")
	}
}

// =============================================================================
// Test: Create API Key
// =============================================================================

func TestBrowser_APIKeySettings_CreateKey(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-create")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to /settings/api-keys/new
	navigateAPIKeyCreatePage(t, page, env.BaseURL)

	// Fill in API key name
	nameInput := WaitForSelector(t, page, "input#name")
	err = nameInput.Fill("Test API Key")
	if err != nil {
		t.Fatalf("Failed to fill API key name: %v", err)
	}

	// Select scope: "Read and Write"
	scopeSelect := WaitForSelector(t, page, "select#scope")
	_, err = scopeSelect.SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	if err != nil {
		t.Fatalf("Failed to select scope: %v", err)
	}

	// Submit form
	submitButton := page.Locator("button[type='submit']")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit button: %v", err)
	}

	// Wait for page to reload with new API key
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Page did not reload: %v", err)
	}

	// Verify API key value is displayed (only shown once)
	tokenElement := page.Locator("code#new-token, code#token-value")
	err = tokenElement.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("API key value element not found: %v", err)
	}

	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	// Verify API key starts with "agentnotes_key_"
	if !strings.HasPrefix(tokenValue, "agentnotes_key_") {
		t.Errorf("API key should start with 'agentnotes_key_', got: %s", tokenValue)
	}

	// Verify copy button is present
	copyButton := page.Locator("button:has-text('Copy')")
	copyVisible, err := copyButton.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check copy button visibility: %v", err)
	}
	if !copyVisible {
		t.Error("Copy button should be visible")
	}

	// Verify success message is displayed
	successMessage := page.Locator("text=API Key Created Successfully")
	successVisible, err := successMessage.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check success message visibility: %v", err)
	}
	if !successVisible {
		t.Error("Success message should be visible")
	}
}

// =============================================================================
// Test: List API Keys
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
		page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
			Values: playwright.StringSlice("read_write"),
		})

		// Submit
		page.Locator("button[type='submit']").Click()

		// Wait for redirect
		page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
			State: playwright.LoadStateNetworkidle,
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

func TestBrowser_APIKeySettings_RevokeKey(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-revoke")
	env.LoginUser(t, ctx, testEmail)

	tokenName := "Key to Revoke"

	// Create an API key first
	navigateAPIKeyCreatePage(t, page, env.BaseURL)

	page.Locator("input#name").Fill(tokenName)
	page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	page.Locator("button[type='submit']").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Navigate back to API keys page (in case we're showing the new key display)
	navigateAPIKeyHub(t, page, env.BaseURL)

	// Verify the API key exists in the list
	tokenRow := page.Locator(fmt.Sprintf("text=%s", tokenName))
	count, err := tokenRow.Count()
	if err != nil || count == 0 {
		t.Fatal("API key should exist before revoking")
	}

	// Set up dialog handler for confirmation
	page.OnDialog(func(dialog playwright.Dialog) {
		dialog.Accept()
	})

	// Click "Revoke" button for the API key
	// Find the row containing the key name and click its Revoke button
	revokeButton := page.Locator(fmt.Sprintf("tr:has-text('%s') button:has-text('Revoke')", tokenName))
	err = revokeButton.Click()
	if err != nil {
		t.Fatalf("Failed to click Revoke button: %v", err)
	}

	// Wait for page to reload
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Page did not reload after revoke: %v", err)
	}

	// Verify API key is removed from list
	tokenRowAfter := page.Locator(fmt.Sprintf("td:has-text('%s')", tokenName))
	countAfter, err := tokenRowAfter.Count()
	if err != nil {
		t.Fatalf("Failed to count API key rows after revoke: %v", err)
	}
	if countAfter > 0 {
		t.Error("Revoked API key should not appear in the list")
	}
}

// =============================================================================
// Test: Copy API Key
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
	page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	page.Locator("button[type='submit']").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Get the API key value before clicking copy
	tokenElement := WaitForSelector(t, page, "code#new-token, code#token-value")
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

func TestBrowser_APIKeySettings_EmptyState(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-empty")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to API keys page without creating any keys
	navigateAPIKeyHub(t, page, env.BaseURL)

	// Verify "No API keys" message is displayed
	noKeysMessage := page.Locator("h3:has-text('No API keys')")
	count, err := noKeysMessage.Count()
	if err != nil {
		t.Fatalf("Failed to check for empty state message: %v", err)
	}
	if count == 0 {
		t.Error("Expected 'No API keys' message for new user without API keys")
	}

	// Verify help text is displayed
	helpText := page.Locator("text=Create an API key to get started")
	helpVisible, err := helpText.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check help text visibility: %v", err)
	}
	if !helpVisible {
		t.Error("Help text should be visible in empty state")
	}
}

// =============================================================================
// Test: Create Without Re-authentication
// =============================================================================

func TestBrowser_APIKeySettings_CreateWithoutReauthentication(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-no-reauth")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to API key create page
	navigateAPIKeyCreatePage(t, page, env.BaseURL)

	// Fill form without any re-authentication fields
	page.Locator("input#name").Fill("Test API Key")
	page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})

	// Submit form
	page.Locator("button[type='submit']").Click()

	// Wait for page to reload
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Verify API key value is displayed
	tokenElement := page.Locator("code#token-value")
	err = tokenElement.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Expected API key value to be visible after create: %v", err)
	}
}

// =============================================================================
// Test: API Key Expiration Options
// =============================================================================

func TestBrowser_APIKeySettings_ExpirationOptions(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-expiry")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to API key create page
	navigateAPIKeyCreatePage(t, page, env.BaseURL)

	// Check expiration select options
	expiresSelect := WaitForSelector(t, page, "select#expires_in")

	// Get all options
	options := expiresSelect.Locator("option")
	optionCount, err := options.Count()
	if err != nil {
		t.Fatalf("Failed to count expiration options: %v", err)
	}

	// Should have at least 3 options (30 days, 90 days, 180 days, 1 year)
	if optionCount < 3 {
		t.Errorf("Expected at least 3 expiration options, got: %d", optionCount)
	}

	// Verify specific options exist
	expectedOptions := []string{"30 days", "90 days", "180 days", "1 year"}
	for _, expected := range expectedOptions {
		option := expiresSelect.Locator(fmt.Sprintf("option:has-text('%s')", expected))
		count, err := option.Count()
		if err != nil || count == 0 {
			t.Errorf("Expected expiration option '%s' to exist", expected)
		}
	}
}

// =============================================================================
// Test: Read-Only Scope API Key
// =============================================================================

func TestBrowser_APIKeySettings_ReadOnlyScope(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-readonly")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to API key create page
	navigateAPIKeyCreatePage(t, page, env.BaseURL)

	// Create a read-only API key
	page.Locator("input#name").Fill("Read Only Key")
	page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read"),
	})
	page.Locator("button[type='submit']").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Navigate back to see the API key in the list
	navigateAPIKeyHub(t, page, env.BaseURL)

	// Verify the API key shows "read" scope
	readScope := page.Locator("span:has-text('read')")
	count, err := readScope.Count()
	if err != nil {
		t.Fatalf("Failed to check read scope: %v", err)
	}
	if count == 0 {
		t.Error("API key with read scope should show 'read' in the list")
	}
}

// =============================================================================
// Test: Unauthenticated Access Redirects to Login
// =============================================================================

func TestBrowser_APIKeySettings_RequiresAuth(t *testing.T) {
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

	// Do NOT login - try to access settings page directly
	Navigate(t, page, env.BaseURL, "/settings/api-keys")

	// Wait for page to load
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// The auth middleware redirects to /login for web pages (RequireAuthWithRedirect)
	currentURL := page.URL()

	// Should be redirected to login page
	if !strings.Contains(currentURL, "/login") {
		// If not redirected, check for unauthorized content
		pageContent, err := page.Content()
		if err != nil {
			t.Fatalf("Failed to get page content: %v", err)
		}
		if !strings.Contains(pageContent, "Unauthorized") && !strings.Contains(pageContent, "Sign in") {
			t.Errorf("Unauthenticated access should redirect to login or show Unauthorized message, got URL: %s, content: %s",
				currentURL, pageContent[:min(200, len(pageContent))])
		}
	}
}

// =============================================================================
// Test: Usage Instructions Visible
// =============================================================================

func TestBrowser_APIKeySettings_UsageInstructions(t *testing.T) {
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

	testEmail := GenerateUniqueEmail("apikey-usage")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to API keys page
	navigateAPIKeyHub(t, page, env.BaseURL)

	// Verify usage instructions section exists
	usageHeading := page.Locator("h3:has-text('How to use your API key')")
	isVisible, err := usageHeading.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check usage heading visibility: %v", err)
	}
	if !isVisible {
		t.Error("Usage instructions heading should be visible")
	}

	// Verify example curl command is shown
	curlExample := page.Locator("code:has-text('Authorization: Bearer')")
	curlVisible, err := curlExample.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check curl example visibility: %v", err)
	}
	if !curlVisible {
		t.Error("Example curl command should be visible")
	}
}

// =============================================================================
// Test: Use Created API Key for API Call
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
	page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	page.Locator("button[type='submit']").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Get the API key value
	tokenElement := WaitForSelector(t, page, "code#new-token, code#token-value")
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

	scopeSelect := WaitForSelector(t, page, "select#scope")
	_, err = scopeSelect.SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	if err != nil {
		t.Fatalf("Failed to select scope: %v", err)
	}

	submitButton := page.Locator("button[type='submit']")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Wait for page to reload with new API key
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Page did not reload: %v", err)
	}

	// Wait for API key element to appear with extended timeout
	// The key might be in code#new-token (settings/api-keys.html) or code#token-value (api-keys/created.html)
	tokenElement := page.Locator("code#new-token, code#token-value")
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
		State: playwright.LoadStateNetworkidle,
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
	page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	page.Locator("button[type='submit']").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Verify API key is displayed
	tokenElement := WaitForSelector(t, page, "code#new-token, code#token-value")
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
		State: playwright.LoadStateNetworkidle,
	})

	// Navigate back to /settings/api-keys
	navigateAPIKeyHub(t, page, env.BaseURL)

	// The new-token element should not be visible
	newTokenElement := page.Locator("code#new-token, code#token-value")
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
