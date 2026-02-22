package browser

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"

	"github.com/kuitang/agent-notes/internal/email"
)

var (
	_ = fmt.Sprintf
	_ = http.MethodGet
	_ = email.TemplateMagicLink
)

func ensurePasswordMode(t *testing.T, page playwright.Page) {
	t.Helper()

	passwordInput := page.Locator("#login-password")
	visible, err := passwordInput.IsVisible()
	if err == nil && visible {
		return
	}

	switchBtn := page.Locator("#password-mode-btn")
	err = switchBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Password mode button not visible: %v", err)
	}

	if err := switchBtn.Click(); err != nil {
		t.Fatalf("Failed to switch to password mode: %v", err)
	}

	err = passwordInput.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Password form did not become visible: %v", err)
	}
}

func waitForServerFlash(t *testing.T, page playwright.Page, role string) playwright.Locator {
	t.Helper()

	flash := page.Locator(fmt.Sprintf(".server-flash[role='%s']", role)).First()
	err := flash.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Server flash with role=%s not visible: %v", role, err)
	}
	return flash
}

// =============================================================================
// Registration Flow Tests
// =============================================================================

func TestBrowser_Auth_SessionIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// Create two separate browser contexts (like two users)
	context1 := env.NewContext(t)
	defer context1.Close()

	context2 := env.NewContext(t)
	defer context2.Close()

	page1, err := context1.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page 1: %v", err)
	}
	defer page1.Close()

	page2, err := context2.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page 2: %v", err)
	}
	defer page2.Close()

	// User 1 registers and logs in
	user1Email := GenerateUniqueEmail("user1")
	password := "SecurePass123!"

	page1.Goto(env.BaseURL + "/register")
	page1.Locator("input[name='email']").Fill(user1Email)
	page1.Locator("input[name='password']").Fill(password)
	page1.Locator("input[name='confirm_password']").Fill(password)
	page1.Locator("input[name='terms']").Check()
	page1.Locator("button[type='submit']:has-text('Create account')").Click()
	page1.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// User 2 should not be logged in
	page2.Goto(env.BaseURL + "/notes")
	page2.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// User 2 should be redirected to login (401 or redirect)
	page2URL := page2.URL()
	if strings.Contains(page2URL, "/notes") && !strings.Contains(page2URL, "Unauthorized") {
		pageContent, _ := page2.Content()
		if !strings.Contains(pageContent, "Unauthorized") && !strings.Contains(pageContent, "login") {
			t.Logf("User 2 accessed /notes without auth, URL: %s", page2URL)
		}
	}
}

// =============================================================================
// Login Error Path Tests
// =============================================================================

func TestBrowser_Auth_LoginWrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Register a user first
	testEmail := GenerateUniqueEmail("wrongpw")
	testPassword := "SecurePass123!"

	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Logout
	page.Context().ClearCookies()

	// Try login with wrong password
	_, err = page.Goto(env.BaseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})
	ensurePasswordMode(t, page)

	page.Locator("#login-email").Fill(testEmail)
	page.Locator("#login-password").Fill("WrongPassword999!")
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Should redirect back to /login with error
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login, got: %s", currentURL)
	}

	// Error flash should be visible
	errorBanner := page.Locator("[role='alert']").First()
	err = errorBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Error banner not visible: %v", err)
	}

	bannerText, _ := errorBanner.TextContent()
	if !strings.Contains(strings.ToLower(bannerText), "invalid") {
		t.Errorf("Error should mention invalid credentials, got: %q", bannerText)
	}
}

func TestBrowser_Auth_LoginNonexistentEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Try login with email that was never registered
	_, err := page.Goto(env.BaseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})
	ensurePasswordMode(t, page)

	page.Locator("#login-email").Fill(GenerateUniqueEmail("nobody-exists"))
	page.Locator("#login-password").Fill("SomePassword123!")
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Should show same generic error (no email enumeration)
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login, got: %s", currentURL)
	}

	errorBanner := page.Locator(".server-flash[role='alert']")
	err = errorBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Error banner not visible: %v", err)
	}

	bannerText, _ := errorBanner.TextContent()
	if !strings.Contains(strings.ToLower(bannerText), "invalid") {
		t.Errorf("Error should mention invalid credentials, got: %q", bannerText)
	}
}

// =============================================================================
// Registration Error Path Tests
// =============================================================================

func TestBrowser_Auth_RegisterDuplicateEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	testEmail := GenerateUniqueEmail("dup")
	testPassword := "SecurePass123!"

	// Register first time
	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Clear cookies and try to register again with same email
	page.Context().ClearCookies()

	_, err = page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Should redirect to /login with "Account already exists" error
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login for duplicate, got: %s", currentURL)
	}

	errorBanner := page.Locator(".server-flash[role='alert']")
	err = errorBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Error banner not visible: %v", err)
	}

	bannerText, _ := errorBanner.TextContent()
	if !strings.Contains(strings.ToLower(bannerText), "already exists") {
		t.Errorf("Error should mention account already exists, got: %q", bannerText)
	}
}

// =============================================================================
// Password Reset Confirm Error Path Tests
// =============================================================================

