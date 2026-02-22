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
	lastEmail, ok := env.EmailService.LastEmailForRecipient(testEmail)
	if !ok {
		t.Fatal("No password reset email was captured")
	}
	if lastEmail.Template != email.TemplatePasswordReset {
		t.Errorf("Wrong email template: got %s, want %s", lastEmail.Template, email.TemplatePasswordReset)
	}
}

// =============================================================================
// Logout Flow Tests
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
		State: playwright.LoadStateDomcontentloaded,
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
	lastEmail, ok := env.EmailService.LastEmailForRecipient(testEmail)
	if !ok {
		t.Fatal("No password reset email was captured")
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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Clear cookies (logout)
	page.Context().ClearCookies()

	// Step 2: Request password reset from /password-reset page
	_, err = page.Goto(env.BaseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate to password reset: %v", err)
	}

	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Should redirect to /login with flash message
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login after reset request, got: %s", currentURL)
	}

	// Step 3: Extract reset link from email
	lastEmail, ok := env.EmailService.LastEmailForRecipient(testEmail)
	if !ok {
		t.Fatal("No password reset email was sent")
	}
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

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

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
	page.Locator("input[name='email']").Fill(GenerateUniqueEmail("nonexistent-nobody"))
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

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

