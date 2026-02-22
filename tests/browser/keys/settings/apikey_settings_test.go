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
	scopeSelect := WaitForSelector(t, page, "input[name='scope'][value='read_write']")
	err = scopeSelect.Check()
	if err != nil {
		t.Fatalf("Failed to select scope: %v", err)
	}

	// Submit form
	submitButton := page.Locator("form[action='/api-keys'] button[type='submit']:has-text('Create API Key')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit button: %v", err)
	}

	// Wait for page to reload with new API key
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not reload: %v", err)
	}

	// Verify API key value is displayed (only shown once)
	tokenElement := page.Locator("code#token-value")
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
	page.Locator("input[name='scope'][value='read_write']").Check()
	page.Locator("form[action='/api-keys'] button[type='submit']:has-text('Create API Key')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
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
		State: playwright.LoadStateDomcontentloaded,
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
	page.Locator("input[name='scope'][value='read_write']").Check()

	// Submit form
	page.Locator("form[action='/api-keys'] button[type='submit']:has-text('Create API Key')").Click()

	// Wait for page to reload
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
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
	page.Locator("input[name='scope'][value='read']").Check()
	page.Locator("form[action='/api-keys'] button[type='submit']:has-text('Create API Key')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
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
		State: playwright.LoadStateDomcontentloaded,
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
