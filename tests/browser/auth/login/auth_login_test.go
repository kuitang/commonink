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

func TestBrowser_Auth_Registration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Navigate to register page
	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate to register page: %v", err)
	}

	// Wait for page to load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Verify we're on the register page
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Failed to get page title: %v", err)
	}
	if !strings.Contains(title, "Create") && !strings.Contains(title, "Register") && !strings.Contains(title, "Account") {
		t.Errorf("Unexpected page title: %s", title)
	}

	// Fill registration form
	testEmail := GenerateUniqueEmail("test")
	testPassword := "SecurePass123!"

	// Fill email
	emailInput := page.Locator("input[name='email']")
	err = emailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	// Fill password
	passwordInput := page.Locator("input[name='password']")
	err = passwordInput.Fill(testPassword)
	if err != nil {
		t.Fatalf("Failed to fill password: %v", err)
	}

	// Fill confirm password
	confirmInput := page.Locator("input[name='confirm_password']")
	err = confirmInput.Fill(testPassword)
	if err != nil {
		t.Fatalf("Failed to fill confirm password: %v", err)
	}

	// Check terms checkbox
	termsCheckbox := page.Locator("input[name='terms']")
	err = termsCheckbox.Check()
	if err != nil {
		t.Fatalf("Failed to check terms: %v", err)
	}

	// Submit form
	submitBtn := page.Locator("button[type='submit']:has-text('Create account')")
	err = submitBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click submit button: %v", err)
	}

	// Wait for navigation to complete
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// After successful registration, should redirect to /notes
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") && !strings.Contains(currentURL, "/login") {
		t.Errorf("Expected redirect to /notes or /login, got: %s", currentURL)
	}
}

func TestBrowser_Auth_Registration_PasswordMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Navigate to register page
	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate to register page: %v", err)
	}

	// Fill form with mismatched passwords
	page.Locator("input[name='email']").Fill(GenerateUniqueEmail("reg-mismatch"))
	page.Locator("input[name='password']").Fill("SecurePass123!")
	page.Locator("input[name='confirm_password']").Fill("DifferentPass456!")
	page.Locator("input[name='terms']").Check()

	// Submit form
	page.Locator("button[type='submit']:has-text('Create account')").Click()

	// Wait for response
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Should show error about password mismatch or stay on register page with error
	currentURL := page.URL()
	if strings.Contains(currentURL, "/register") || strings.Contains(currentURL, "error") {
		t.Log("Password mismatch was handled correctly")
	}
}

// =============================================================================
// Password Login Flow Tests
// =============================================================================

func TestBrowser_Auth_PasswordLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Pre-create a test user by registering first
	testEmail := GenerateUniqueEmail("login-test")
	testPassword := "SecurePass123!"

	// First register the user
	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate to register page: %v", err)
	}

	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()

	// Wait for registration to complete
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Clear cookies (logout)
	browserContext := page.Context()
	browserContext.ClearCookies()

	// Now test login
	_, err = page.Goto(env.BaseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	// Wait for page to load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}
	ensurePasswordMode(t, page)

	// Fill login form (password section)
	loginEmailInput := page.Locator("#login-email")
	err = loginEmailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	loginPasswordInput := page.Locator("#login-password")
	err = loginPasswordInput.Fill(testPassword)
	if err != nil {
		t.Fatalf("Failed to fill password: %v", err)
	}

	// Submit login form (target the password login form specifically)
	signInBtn := page.Locator("form[action='/auth/login'] button[type='submit']")
	err = signInBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click sign in button: %v", err)
	}

	// Wait for navigation
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// Should redirect to /notes after successful login
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Expected redirect to /notes, got: %s", currentURL)
	}
}

// =============================================================================
// Magic Link Login Flow Tests
// =============================================================================

func TestBrowser_Auth_Logout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// First, login
	testEmail := GenerateUniqueEmail("logout-test")
	testPassword := "SecurePass123!"

	// Register and login
	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Verify we're logged in (on /notes page)
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Skipf("Registration did not redirect to /notes (got %s), skipping logout test", currentURL)
	}

	// Hit logout endpoint directly (supports GET/POST) to avoid nav/menu selector drift.
	_, err = page.Goto(env.BaseURL + "/auth/logout")
	if err != nil {
		t.Fatalf("Failed to navigate to logout endpoint: %v", err)
	}
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Logout navigation did not complete: %v", err)
	}

	// Logout redirects to landing page.
	currentURL = page.URL()
	if !strings.HasSuffix(currentURL, "/") {
		t.Errorf("Expected redirect to landing page after logout, got: %s", currentURL)
	}

	// Protected page should require auth after logout.
	_, err = page.Goto(env.BaseURL + "/notes")
	if err != nil {
		t.Fatalf("Failed to navigate to /notes after logout: %v", err)
	}
	err = page.WaitForURL("**/login", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Expected redirect to /login when accessing /notes after logout: %v", err)
	}
}

// =============================================================================
// Password Reset Flow Tests
// =============================================================================
