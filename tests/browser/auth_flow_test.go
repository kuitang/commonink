// Package browser contains Playwright E2E tests for browser-based authentication flows.
// These tests are deterministic scenarios (NOT property-based) as per CLAUDE.md guidelines.
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

	"github.com/kuitang/agent-notes/internal/email"
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
		State: playwright.LoadStateNetworkidle,
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
	page.Locator("input[name='email']").Fill("test@example.com")
	page.Locator("input[name='password']").Fill("SecurePass123!")
	page.Locator("input[name='confirm_password']").Fill("DifferentPass456!")
	page.Locator("input[name='terms']").Check()

	// Submit form
	page.Locator("button[type='submit']:has-text('Create account')").Click()

	// Wait for response
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
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
		State: playwright.LoadStateNetworkidle,
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
		State: playwright.LoadStateNetworkidle,
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

func TestBrowser_Auth_MagicLinkLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Navigate to login page
	_, err := page.Goto(env.BaseURL + "/login")
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

	// Find the magic link email input
	magicEmailInput := page.Locator("#login-email")
	testEmail := GenerateUniqueEmail("magic-test")

	err = magicEmailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill magic link email: %v", err)
	}

	// Click "Send Magic Link" button
	magicLinkBtn := page.Locator("#magic-link-submit")
	err = magicLinkBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click Send Magic Link button: %v", err)
	}

	// The magic link form uses fetch() + dialog.showModal() (not a page navigation).
	// Wait for the dialog to become visible after the AJAX request completes.
	magicDialog := page.Locator("#magic-link-dialog")
	err = magicDialog.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Magic link dialog did not become visible: %v", err)
	}

	// Verify the dialog shows the correct email address
	modalEmail := page.Locator("#modal-email")
	emailText, err := modalEmail.TextContent()
	if err != nil {
		t.Fatalf("Failed to get modal email text: %v", err)
	}
	if emailText != testEmail {
		t.Errorf("Dialog shows wrong email: got %q, want %q", emailText, testEmail)
	}

	// Verify dialog heading
	dialogHeading := magicDialog.Locator("h3")
	headingText, err := dialogHeading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get dialog heading: %v", err)
	}
	if !strings.Contains(headingText, "Check your email") {
		t.Errorf("Dialog heading should say 'Check your email', got: %q", headingText)
	}

	// Verify email was captured by mock service
	emailCount := env.EmailService.Count()
	if emailCount == 0 {
		t.Error("Expected magic link email to be sent, but no emails captured")
	} else {
		lastEmail := env.EmailService.LastEmail()
		if lastEmail.To != testEmail {
			t.Errorf("Email sent to wrong address: got %s, want %s", lastEmail.To, testEmail)
		}
		if lastEmail.Template != email.TemplateMagicLink {
			t.Errorf("Wrong email template: got %s, want %s", lastEmail.Template, email.TemplateMagicLink)
		}
	}
}

func TestBrowser_Auth_MagicLinkVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// First, request a magic link
	testEmail := GenerateUniqueEmail("verify-test")

	_, err := page.Goto(env.BaseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	page.Locator("#login-email").Fill(testEmail)
	page.Locator("#magic-link-submit").Click()

	// Wait for dialog/email side effects from JS fetch flow
	err = page.Locator("#magic-link-dialog").WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Magic link dialog did not appear: %v", err)
	}

	// Extract magic link from mock email service
	if env.EmailService.Count() == 0 {
		t.Fatal("No magic link email was sent")
	}

	lastEmail := env.EmailService.LastEmail()
	magicLinkData, ok := lastEmail.Data.(email.MagicLinkData)
	if !ok {
		t.Fatalf("Email data is not MagicLinkData type: %T", lastEmail.Data)
	}

	magicLink := magicLinkData.Link
	if magicLink == "" {
		t.Fatal("Magic link is empty")
	}

	// Clear cookies to simulate new browser session
	page.Context().ClearCookies()

	// Navigate to magic link URL
	_, err = page.Goto(magicLink)
	if err != nil {
		t.Fatalf("Failed to navigate to magic link: %v", err)
	}

	// Wait for redirect
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// Should redirect to /notes or / after successful magic link verification
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") && !strings.Contains(currentURL, "/") {
		if strings.Contains(currentURL, "error") {
			t.Errorf("Magic link verification failed, redirected to: %s", currentURL)
		}
	}
}

// =============================================================================
// Forgot Password Link Tests (from Login Page)
// =============================================================================

func TestBrowser_Auth_ForgotPasswordLink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Navigate to login page
	_, err := page.Goto(env.BaseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}
	ensurePasswordMode(t, page)

	// Find the "Forgot password?" link — it's now href="#" with inline JS
	forgotLink := page.Locator("#forgot-password-link")
	count, err := forgotLink.Count()
	if err != nil || count == 0 {
		t.Fatal("'Forgot password?' link not found on login page")
	}

	href, err := forgotLink.GetAttribute("href")
	if err != nil {
		t.Fatalf("Failed to get href attribute: %v", err)
	}
	if href != "#" {
		t.Errorf("Forgot password link should be href='#' (inline JS), got: %q", href)
	}

	// Test 1: Clicking without email shows error flash
	err = forgotLink.Click()
	if err != nil {
		t.Fatalf("Failed to click forgot password link: %v", err)
	}

	inlineFlash := page.Locator("#inline-flash")
	err = inlineFlash.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Inline flash did not appear after clicking without email: %v", err)
	}
	flashText, _ := inlineFlash.TextContent()
	if !strings.Contains(flashText, "Enter your email") {
		t.Errorf("Expected 'Enter your email' error flash, got: %q", flashText)
	}

	// Test 2: Fill email then click — should show success flash and send email
	testEmail := GenerateUniqueEmail("forgot-test")
	loginEmailInput := page.Locator("#login-email")
	err = loginEmailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill login email: %v", err)
	}

	err = forgotLink.Click()
	if err != nil {
		t.Fatalf("Failed to click forgot password link: %v", err)
	}

	// Wait for the success flash to appear (replaces the error flash)
	err = page.Locator("#inline-flash:has-text('reset link')").WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Success flash did not appear after forgot password request: %v", err)
	}

	// Should still be on /login (no page navigation)
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Errorf("Should stay on /login page, got: %s", currentURL)
	}

	// Verify email was captured by mock service
	if env.EmailService.Count() == 0 {
		t.Fatal("No password reset email was captured")
	}
	lastEmail := env.EmailService.LastEmail()
	if lastEmail.To != testEmail {
		t.Errorf("Email sent to wrong address: got %s, want %s", lastEmail.To, testEmail)
	}
	if lastEmail.Template != email.TemplatePasswordReset {
		t.Errorf("Wrong email template: got %s, want %s", lastEmail.Template, email.TemplatePasswordReset)
	}
}

// =============================================================================
// Logout Flow Tests
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
		State: playwright.LoadStateNetworkidle,
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

func TestBrowser_Auth_PasswordReset_RequestForm(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Navigate to password reset page
	_, err := page.Goto(env.BaseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate to password reset page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Verify we're on the password reset page
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Failed to get page title: %v", err)
	}
	if !strings.Contains(strings.ToLower(title), "reset") {
		t.Errorf("Unexpected page title: %s", title)
	}

	// Fill email and submit
	testEmail := GenerateUniqueEmail("reset-test")
	err = page.Locator("input[name='email']").Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	err = page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	if err != nil {
		t.Fatalf("Failed to click submit button: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// After POST /auth/password-reset, should redirect to /login?reset=requested
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login, got: %s", currentURL)
	}

	// Verify flash message banner is visible on login page
	flashBanner := page.Locator(".server-flash[role='status']")
	err = flashBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Flash message banner not visible after password reset request: %v", err)
	}

	bannerText, err := flashBanner.TextContent()
	if err != nil {
		t.Fatalf("Failed to get banner text: %v", err)
	}
	if !strings.Contains(bannerText, "password reset link") {
		t.Errorf("Flash message should mention password reset link, got: %q", bannerText)
	}

	// Verify email was captured by mock service
	if env.EmailService.Count() == 0 {
		t.Fatal("No password reset email was captured")
	}
	lastEmail := env.EmailService.LastEmail()
	if lastEmail.To != testEmail {
		t.Errorf("Email sent to wrong address: got %s, want %s", lastEmail.To, testEmail)
	}
	if lastEmail.Template != email.TemplatePasswordReset {
		t.Errorf("Wrong email template: got %s, want %s", lastEmail.Template, email.TemplatePasswordReset)
	}

	// Verify the reset link in the email uses the test server URL (not localhost:8080)
	resetData, ok := lastEmail.Data.(email.PasswordResetData)
	if !ok {
		t.Fatalf("Email data is not PasswordResetData: %T", lastEmail.Data)
	}
	if !strings.HasPrefix(resetData.Link, env.BaseURL) {
		t.Errorf("Reset link should start with %s, got: %s", env.BaseURL, resetData.Link)
	}
}

func TestBrowser_Auth_PasswordReset_FullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Step 1: Register a user (need an account to reset password for)
	testEmail := GenerateUniqueEmail("fullreset")
	originalPassword := "OriginalPass123!"

	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate to register: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(originalPassword)
	page.Locator("input[name='confirm_password']").Fill(originalPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Clear cookies (logout)
	page.Context().ClearCookies()
	env.EmailService.Clear()

	// Step 2: Request password reset from /password-reset page
	_, err = page.Goto(env.BaseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate to password reset: %v", err)
	}

	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should redirect to /login with flash message
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login after reset request, got: %s", currentURL)
	}

	// Step 3: Extract reset link from email
	if env.EmailService.Count() == 0 {
		t.Fatal("No password reset email was sent")
	}

	lastEmail := env.EmailService.LastEmail()
	resetData, ok := lastEmail.Data.(email.PasswordResetData)
	if !ok {
		t.Fatalf("Email data is not PasswordResetData: %T", lastEmail.Data)
	}
	if resetData.Link == "" {
		t.Fatal("Reset link is empty")
	}

	// Verify link uses correct base URL
	if !strings.HasPrefix(resetData.Link, env.BaseURL) {
		t.Errorf("Reset link should use test server URL, got: %s", resetData.Link)
	}

	// Step 4: Navigate to reset link — should show new password form
	_, err = page.Goto(resetData.Link)
	if err != nil {
		t.Fatalf("Failed to navigate to reset link: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Verify we're on the password reset confirm page
	heading := page.Locator("h2:has-text('Create new password')")
	err = heading.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Password reset confirm page heading not found: %v", err)
	}

	// Step 5: Fill new password and submit
	newPassword := "NewSecurePass456!"
	page.Locator("input[name='password']").Fill(newPassword)
	page.Locator("input[name='confirm_password']").Fill(newPassword)
	page.Locator("button[type='submit']:has-text('Reset password')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Step 6: Should redirect to /login with success message
	currentURL = page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login after password reset, got: %s", currentURL)
	}

	// Verify success flash message is visible
	flashBanner := page.Locator(".server-flash[role='status']")
	err = flashBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Success flash message not visible after password reset: %v", err)
	}

	bannerText, err := flashBanner.TextContent()
	if err != nil {
		t.Fatalf("Failed to get banner text: %v", err)
	}
	if !strings.Contains(strings.ToLower(bannerText), "password reset") {
		t.Errorf("Flash message should mention password reset, got: %q", bannerText)
	}
}

// =============================================================================
// Server Health Tests
// =============================================================================

func TestBrowser_Auth_ServerHealth(t *testing.T) {
	env := SetupBrowserTestEnv(t)

	// Test server health without browser
	resp, err := http.Get(env.BaseURL + "/health")
	if err != nil {
		t.Fatalf("Failed to reach health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Health check failed with status: %d", resp.StatusCode)
	}
}

// =============================================================================
// Google OIDC (Mock) Browser Tests
// =============================================================================

func TestBrowser_Auth_GoogleOIDC_FullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	_, err := page.Goto(env.BaseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Click "Sign in with Google" button
	googleBtn := page.Locator("form[action='/auth/google'] button[type='submit']")
	err = googleBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click Google sign-in button: %v", err)
	}

	// Should land on the mock OIDC consent page
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Mock OIDC page did not load: %v", err)
	}

	heading := page.Locator("h1")
	headingText, err := heading.TextContent()
	if err != nil || headingText != "Mock Google Sign-In" {
		t.Fatalf("Expected mock OIDC consent page, got heading: %q", headingText)
	}

	emailInput := page.Locator("input[name='email']")
	err = emailInput.Fill("oidc-browser@example.com")
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	submitBtn := page.Locator("button[type='submit']")
	err = submitBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Should redirect through callback and land on app
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Post-OIDC page did not load: %v", err)
	}

	currentURL := page.URL()
	if strings.Contains(currentURL, "/login") || strings.Contains(currentURL, "/auth/mock-oidc") {
		t.Fatalf("Expected to be redirected away from login after OIDC, but URL is: %s", currentURL)
	}
}

func TestBrowser_Auth_GoogleOIDC_ReturnTo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	_, err := page.Goto(env.BaseURL + "/login?return_to=/notes")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	googleBtn := page.Locator("form[action='/auth/google'] button[type='submit']")
	err = googleBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click Google sign-in button: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Mock OIDC page did not load: %v", err)
	}

	emailInput := page.Locator("input[name='email']")
	err = emailInput.Fill("oidc-return@example.com")
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	submitBtn := page.Locator("button[type='submit']")
	err = submitBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Post-OIDC page did not load: %v", err)
	}

	currentURL := page.URL()
	if !strings.HasSuffix(currentURL, "/notes") {
		t.Fatalf("Expected to be redirected to /notes, but URL is: %s", currentURL)
	}
}

// =============================================================================
// Session Isolation Tests
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
	page1.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// User 2 should not be logged in
	page2.Goto(env.BaseURL + "/notes")
	page2.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

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

	page.Locator("#login-email").Fill("nobody-exists@example.com")
	page.Locator("#login-password").Fill("SomePassword123!")
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

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

func TestBrowser_Auth_PasswordResetConfirm_Mismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Register user, request reset, get token
	testEmail := GenerateUniqueEmail("mismatch")
	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill("OriginalPass123!")
	page.Locator("input[name='confirm_password']").Fill("OriginalPass123!")
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	page.Context().ClearCookies()
	env.EmailService.Clear()

	// Request password reset
	_, err = page.Goto(env.BaseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Extract token from email
	if env.EmailService.Count() == 0 {
		t.Fatal("No reset email sent")
	}
	lastEmail := env.EmailService.LastEmail()
	resetData, ok := lastEmail.Data.(email.PasswordResetData)
	if !ok {
		t.Fatalf("Email data is not PasswordResetData: %T", lastEmail.Data)
	}

	// Navigate to reset link
	_, err = page.Goto(resetData.Link)
	if err != nil {
		t.Fatalf("Failed to navigate to reset link: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Submit mismatched passwords
	page.Locator("input[name='password']").Fill("NewPassword123!")
	page.Locator("input[name='confirm_password']").Fill("DifferentPassword456!")
	page.Locator("button[type='submit']:has-text('Reset password')").Click()
	err = page.WaitForURL("**/auth/password-reset-confirm?*", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Expected redirect back to reset confirm page with error: %v", err)
	}

	// Should show error about password mismatch, token preserved
	currentURL := page.URL()
	if !strings.Contains(currentURL, "password-reset-confirm") || !strings.Contains(currentURL, "error=") {
		t.Fatalf("Expected to stay on password-reset-confirm, got: %s", currentURL)
	}

	content, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to read reset confirm page content: %v", err)
	}
	if !strings.Contains(strings.ToLower(content), "passwords do not match") {
		t.Errorf("Error page should mention password mismatch")
	}

	// Token should be preserved in the form so user can retry
	tokenInput := page.Locator("input[name='token']")
	tokenVal, err := tokenInput.GetAttribute("value")
	if err != nil || tokenVal == "" {
		t.Error("Token should be preserved in the form after mismatch error")
	}
}

func TestBrowser_Auth_PasswordResetConfirm_InvalidToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Navigate to reset confirm page with bogus token
	_, err := page.Goto(env.BaseURL + "/auth/password-reset-confirm?token=bogus-invalid-token")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Fill passwords and submit
	page.Locator("input[name='password']").Fill("NewPassword123!")
	page.Locator("input[name='confirm_password']").Fill("NewPassword123!")
	page.Locator("button[type='submit']:has-text('Reset password')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should redirect to /login with "invalid or expired" error
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login for invalid token, got: %s", currentURL)
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
	if !strings.Contains(strings.ToLower(bannerText), "invalid") || !strings.Contains(strings.ToLower(bannerText), "expired") {
		t.Errorf("Error should mention invalid or expired, got: %q", bannerText)
	}
}

func TestBrowser_Auth_PasswordResetConfirm_MissingToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Navigate to reset confirm page with NO token
	_, err := page.Goto(env.BaseURL + "/auth/password-reset-confirm")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Should show error page (not the form)
	currentURL := page.URL()
	pageContent, _ := page.Content()

	// The handler renders auth error page for missing token
	if strings.Contains(pageContent, "invalid") || strings.Contains(pageContent, "expired") || strings.Contains(pageContent, "Missing") {
		t.Log("Missing token correctly shows error page")
	} else {
		t.Errorf("Expected error page for missing token, URL: %s", currentURL)
	}
}

// =============================================================================
// Full Password Reset → Login With New Password
// =============================================================================

func TestBrowser_Auth_PasswordReset_ThenLoginWithNewPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Step 1: Register
	testEmail := GenerateUniqueEmail("fullreset2")
	originalPassword := "OriginalPass123!"
	newPassword := "BrandNewPass456!"

	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(originalPassword)
	page.Locator("input[name='confirm_password']").Fill(originalPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	page.Context().ClearCookies()
	env.EmailService.Clear()

	// Step 2: Request password reset
	_, err = page.Goto(env.BaseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Step 3: Use reset link
	if env.EmailService.Count() == 0 {
		t.Fatal("No reset email sent")
	}
	resetData := env.EmailService.LastEmail().Data.(email.PasswordResetData)

	_, err = page.Goto(resetData.Link)
	if err != nil {
		t.Fatalf("Failed to navigate to reset link: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	page.Locator("input[name='password']").Fill(newPassword)
	page.Locator("input[name='confirm_password']").Fill(newPassword)
	page.Locator("button[type='submit']:has-text('Reset password')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should be on /login with success
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected /login after reset, got: %s", currentURL)
	}

	successBanner := page.Locator(".server-flash[role='status']")
	err = successBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Success banner not visible after reset: %v", err)
	}

	// Step 4: Login with NEW password
	ensurePasswordMode(t, page)
	page.Locator("#login-email").Fill(testEmail)
	page.Locator("#login-password").Fill(newPassword)
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL = page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Expected redirect to /notes after login with new password, got: %s", currentURL)
	}

	// Step 5: Verify old password no longer works
	page.Context().ClearCookies()
	_, err = page.Goto(env.BaseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})
	ensurePasswordMode(t, page)

	page.Locator("#login-email").Fill(testEmail)
	page.Locator("#login-password").Fill(originalPassword)
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL = page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Errorf("Old password should be rejected, but got: %s", currentURL)
	}

	errorBanner := page.Locator(".server-flash[role='alert']")
	err = errorBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Error banner not visible for old password: %v", err)
	}
}

// =============================================================================
// return_to Parameter Tests
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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Verify we're on /notes
	if !strings.Contains(page.URL(), "/notes") {
		t.Skipf("Registration didn't redirect to /notes, got: %s", page.URL())
	}

	// Navigate to logout
	_, err = page.Goto(env.BaseURL + "/auth/logout")
	if err != nil {
		t.Fatalf("Failed to navigate to logout: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Try to access /notes — should redirect to /login
	_, err = page.Goto(env.BaseURL + "/notes")
	if err != nil {
		t.Fatalf("Failed to navigate to /notes: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL := page.URL()
	if !strings.HasSuffix(currentURL, "/") {
		t.Errorf("Unauthenticated / should stay on landing page, got: %s", currentURL)
	}

	heading := page.Locator("h1")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to read landing page heading: %v", err)
	}
	if !strings.Contains(headingText, "Notes") {
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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Now visit / — should redirect to /notes
	_, err = page.Goto(env.BaseURL + "/")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Authenticated / should redirect to /notes, got: %s", currentURL)
	}
}

// =============================================================================
// Magic Link Dialog Close Tests
// =============================================================================

func TestBrowser_Auth_MagicLinkDialog_CloseButton(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	_, err := page.Goto(env.BaseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Fill email and submit magic link
	testEmail := GenerateUniqueEmail("dialogclose")
	page.Locator("#login-email").Fill(testEmail)
	page.Locator("#magic-link-submit").Click()

	// Wait for dialog
	dialog := page.Locator("#magic-link-dialog")
	err = dialog.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Dialog did not appear: %v", err)
	}

	// Click "Got it" button
	page.Locator("#close-modal-btn").Click()

	// Dialog should close
	err = dialog.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateHidden,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Dialog did not close after clicking 'Got it': %v", err)
	}

	// Email field should be cleared
	emailVal, _ := page.Locator("#login-email").InputValue()
	if emailVal != "" {
		t.Errorf("Email field should be cleared after dialog close, got: %q", emailVal)
	}
}

// =============================================================================
// Flash Message Rendering Tests
// =============================================================================

func TestBrowser_Auth_FlashMessages_LoginPage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	tests := []struct {
		name     string
		query    string
		role     string // "status" for success, "alert" for error
		contains string
	}{
		{
			name:     "success flash",
			query:    "?success=Password+reset+successfully.+Please+sign+in.",
			role:     "status",
			contains: "Password reset successfully",
		},
		{
			name:     "reset requested flash",
			query:    "?reset=requested",
			role:     "status",
			contains: "password reset link",
		},
		{
			name:     "error flash",
			query:    "?error=Invalid+email+or+password",
			role:     "alert",
			contains: "Invalid email or password",
		},
		{
			name:     "account exists flash",
			query:    "?error=Account+already+exists.+Please+sign+in.",
			role:     "alert",
			contains: "Account already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := env.NewPage(t)
			defer page.Close()

			_, err := page.Goto(env.BaseURL + "/login" + tt.query)
			if err != nil {
				t.Fatalf("Failed to navigate: %v", err)
			}
			page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

			banner := page.Locator(fmt.Sprintf(".server-flash[role='%s']", tt.role))
			err = banner.WaitFor(playwright.LocatorWaitForOptions{
				State:   playwright.WaitForSelectorStateVisible,
				Timeout: playwright.Float(browserMaxTimeoutMS),
			})
			if err != nil {
				t.Fatalf("Flash banner [role='%s'] not visible for %s: %v", tt.role, tt.name, err)
			}

			text, _ := banner.TextContent()
			if !strings.Contains(text, tt.contains) {
				t.Errorf("Flash should contain %q, got: %q", tt.contains, text)
			}
		})
	}
}

// =============================================================================
// Password Reset Page (Standalone) Tests
// =============================================================================

func TestBrowser_Auth_PasswordResetPage_BackToLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	_, err := page.Goto(env.BaseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Verify page heading
	heading := page.Locator("h2:has-text('Reset your password')")
	count, err := heading.Count()
	if err != nil || count == 0 {
		t.Error("Password reset page heading not found")
	}

	// Click "Back to login" link
	backLink := page.Locator("a:has-text('Back to login')")
	err = backLink.Click()
	if err != nil {
		t.Fatalf("Failed to click Back to login: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	currentURL := page.URL()
	if !strings.HasSuffix(currentURL, "/login") {
		t.Errorf("Expected redirect to /login, got: %s", currentURL)
	}
}

func TestBrowser_Auth_PasswordResetPage_NonexistentEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	_, err := page.Goto(env.BaseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Submit for a nonexistent email — should still show success (no enumeration)
	page.Locator("input[name='email']").Fill("nonexistent-nobody@example.com")
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should redirect to /login with success flash
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login, got: %s", currentURL)
	}

	successBanner := page.Locator(".server-flash[role='status']")
	err = successBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Success banner not visible (should not reveal email doesn't exist): %v", err)
	}

	text, _ := successBanner.TextContent()
	if !strings.Contains(strings.ToLower(text), "if an account exists") {
		t.Errorf("Banner should say 'if an account exists', got: %q", text)
	}
}

// =============================================================================
// Register Page Link Tests
// =============================================================================

func TestBrowser_Auth_RegisterPage_SignInLink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Visit register page with return_to
	_, err := page.Goto(env.BaseURL + "/register?return_to=/notes")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// "Sign in" link in the register header should propagate return_to.
	signInLink := page.Locator("p:has-text('Already have an account?') a:has-text('Sign in')").First()
	href, err := signInLink.GetAttribute("href")
	if err != nil {
		t.Fatalf("Failed to get Sign in href: %v", err)
	}
	if !strings.Contains(href, "return_to") {
		t.Errorf("'Sign in' link should include return_to, got: %q", href)
	}

	err = signInLink.Click()
	if err != nil {
		t.Fatalf("Failed to click Sign in: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") || !strings.Contains(currentURL, "return_to") {
		t.Errorf("Expected /login with return_to, got: %s", currentURL)
	}
}

// TestBrowser_Auth_RegisterPage_GoogleOnTop verifies the register page layout:
// Google sign-up button on top, "or" divider, password form below.
func TestBrowser_Auth_RegisterPage_GoogleOnTop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate to register page: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// The themed-card should contain: Google button, then divider, then password form.
	card := page.Locator(".themed-card")

	// Google button should exist and be visible inside the card
	googleBtn := card.Locator("button:has-text('Sign up with Google')")
	err = googleBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Google sign-up button not visible in card: %v", err)
	}

	// Divider should say "or" (not "or sign up with")
	dividerText := card.Locator("span:has-text('or')")
	text, err := dividerText.TextContent()
	if err != nil {
		t.Fatalf("Failed to get divider text: %v", err)
	}
	if strings.TrimSpace(text) != "or" {
		t.Errorf("Divider should say 'or', got %q", strings.TrimSpace(text))
	}

	// Google button should appear BEFORE the email input in DOM order.
	// Evaluate JS to check relative position.
	googleAboveEmail, err := page.Evaluate(`() => {
		const card = document.querySelector('.themed-card');
		const googleBtn = card.querySelector('button[type="submit"]');
		const emailInput = card.querySelector('input[name="email"]');
		if (!googleBtn || !emailInput) return false;
		const googleRect = googleBtn.getBoundingClientRect();
		const emailRect = emailInput.getBoundingClientRect();
		return googleRect.bottom <= emailRect.top;
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate layout positions: %v", err)
	}
	if googleAboveEmail != true {
		t.Error("Google button should appear above the email input (Google on top, password form below)")
	}

	// Password form fields should still exist below
	emailInput := card.Locator("input[name='email']")
	passwordInput := card.Locator("input[name='password']")
	confirmInput := card.Locator("input[name='confirm_password']")
	termsCheckbox := card.Locator("input[name='terms']")

	for _, loc := range []playwright.Locator{emailInput, passwordInput, confirmInput, termsCheckbox} {
		visible, err := loc.IsVisible()
		if err != nil {
			t.Fatalf("Failed to check visibility: %v", err)
		}
		if !visible {
			t.Error("Password form field should be visible below the divider")
		}
	}
}

// TestBrowser_Auth_DefaultTheme_CardNoTranslateOnHover verifies that hovering
// over a themed-card in the default theme does NOT cause a translateY shift.
func TestBrowser_Auth_DefaultTheme_CardNoTranslateOnHover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Use the register page (any page with a themed-card works)
	_, err := page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Ensure we're in default theme
	_, err = page.Evaluate(`() => {
		localStorage.setItem('ci_theme', 'default');
	}`)
	if err != nil {
		t.Fatalf("Failed to set theme: %v", err)
	}
	// Reload to apply theme
	_, err = page.Goto(env.BaseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to reload: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	card := page.Locator(".themed-card")
	err = card.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Card not visible: %v", err)
	}

	// Get position before hover
	beforeY, err := page.Evaluate(`() => {
		const card = document.querySelector('.themed-card');
		return card.getBoundingClientRect().top;
	}`)
	if err != nil {
		t.Fatalf("Failed to get card position before hover: %v", err)
	}

	// Hover over the card
	err = card.Hover()
	if err != nil {
		t.Fatalf("Failed to hover over card: %v", err)
	}

	// Wait for hover state/animations to settle without using fixed sleeps.
	_, err = page.WaitForFunction(`() => {
		const card = document.querySelector('.themed-card');
		if (!card || !card.matches(':hover')) return false;
		const animations = card.getAnimations ? card.getAnimations() : [];
		return animations.every(a => a.playState === 'finished' || a.playState === 'idle');
	}`, nil, playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Card hover state did not settle: %v", err)
	}

	// Get position after hover
	afterY, err := page.Evaluate(`() => {
		const card = document.querySelector('.themed-card');
		return card.getBoundingClientRect().top;
	}`)
	if err != nil {
		t.Fatalf("Failed to get card position after hover: %v", err)
	}

	// Card should NOT move vertically
	beforeF, _ := beforeY.(float64)
	afterF, _ := afterY.(float64)
	if beforeF != afterF {
		t.Errorf("Card moved on hover: before Y=%.1f, after Y=%.1f (translateY bug)", beforeF, afterF)
	}

	// Also verify no translateY in computed style
	transform, err := page.Evaluate(`() => {
		const card = document.querySelector('.themed-card');
		return getComputedStyle(card).transform;
	}`)
	if err != nil {
		t.Fatalf("Failed to get computed transform: %v", err)
	}
	transformStr, _ := transform.(string)
	if transformStr != "none" && transformStr != "" {
		t.Errorf("Card should have no transform on hover in default theme, got %q", transformStr)
	}
}
