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

func TestBrowser_Auth_ReturnTo_LoginRedirect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Register user
	testEmail := GenerateUniqueEmail("returnto")
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

	page.Context().ClearCookies()

	// Visit login page with return_to
	_, err = page.Goto(env.BaseURL + "/login?return_to=/notes")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})
	ensurePasswordMode(t, page)

	// Verify hidden return_to field exists in the password form
	returnToInput := page.Locator("form[action='/auth/login'] input[name='return_to']")
	count, err := returnToInput.Count()
	if err != nil || count == 0 {
		t.Error("Hidden return_to input not found in login form")
	} else {
		val, _ := returnToInput.GetAttribute("value")
		if val != "/notes" {
			t.Errorf("return_to input should have value '/notes', got: %q", val)
		}
	}

	// Login and verify redirect to return_to path
	page.Locator("#login-email").Fill(testEmail)
	page.Locator("#login-password").Fill(testPassword)
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Expected redirect to /notes (return_to), got: %s", currentURL)
	}
}

func TestBrowser_Auth_ReturnTo_RegisterPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Visit login page with return_to, then click "create a new account"
	_, err := page.Goto(env.BaseURL + "/login?return_to=/notes")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Click "create a new account" link — should propagate return_to
	createLink := page.Locator("a:has-text('create a new account')")
	href, err := createLink.GetAttribute("href")
	if err != nil {
		t.Fatalf("Failed to get create account href: %v", err)
	}
	if !strings.Contains(href, "return_to") {
		t.Errorf("'create a new account' link should include return_to, got: %q", href)
	}

	err = createLink.Click()
	if err != nil {
		t.Fatalf("Failed to click create account link: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Verify we're on /register with return_to preserved
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/register") || !strings.Contains(currentURL, "return_to") {
		t.Errorf("Expected /register with return_to, got: %s", currentURL)
	}

	// Register and verify redirect goes to return_to
	testEmail := GenerateUniqueEmail("regreturn")
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill("SecurePass123!")
	page.Locator("input[name='confirm_password']").Fill("SecurePass123!")
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	currentURL = page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Expected redirect to /notes (return_to), got: %s", currentURL)
	}
}

// =============================================================================
// Logout → Protected Page Tests
// =============================================================================

func TestBrowser_Auth_LogoutThenAccessProtected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Register and login
	testEmail := GenerateUniqueEmail("logoutprot")
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

	// Verify we're on /notes
	if !strings.Contains(page.URL(), "/notes") {
		t.Skipf("Registration didn't redirect to /notes, got: %s", page.URL())
	}

	// Navigate to logout
	_, err = page.Goto(env.BaseURL + "/auth/logout")
	if err != nil {
		t.Fatalf("Failed to navigate to logout: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Try to access /notes — should redirect to /login
	_, err = page.Goto(env.BaseURL + "/notes")
	if err != nil {
		t.Fatalf("Failed to navigate to /notes: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Errorf("Expected redirect to /login after logout, got: %s", currentURL)
	}
}

// =============================================================================
// Landing Page Redirect Tests
// =============================================================================

func TestBrowser_Auth_LandingRedirect_Unauthenticated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Visit / without auth
	_, err := page.Goto(env.BaseURL + "/")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	currentURL := page.URL()
	if !strings.HasSuffix(currentURL, "/") {
		t.Errorf("Unauthenticated / should stay on landing page, got: %s", currentURL)
	}

	heading := page.Locator("h1")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to read landing page heading: %v", err)
	}
	if !strings.Contains(headingText, "Ink") {
		t.Errorf("Landing page heading missing expected text, got: %q", headingText)
	}
}

func TestBrowser_Auth_LandingRedirect_Authenticated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Register to get authenticated
	testEmail := GenerateUniqueEmail("landing")

	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill("SecurePass123!")
	page.Locator("input[name='confirm_password']").Fill("SecurePass123!")
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Now visit / — should redirect to /notes
	_, err = page.Goto(env.BaseURL + "/")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Authenticated / should redirect to /notes, got: %s", currentURL)
	}
}

// =============================================================================
// Magic Link Dialog Close Tests
// =============================================================================

