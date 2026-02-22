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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	page.Context().ClearCookies()

	// Request password reset
	_, err = page.Goto(env.BaseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Extract token from email
	lastEmail, ok := env.EmailService.LastEmailForRecipient(testEmail)
	if !ok {
		t.Fatal("No reset email sent")
	}
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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	page.Context().ClearCookies()

	// Step 2: Request password reset
	_, err = page.Goto(env.BaseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Step 3: Use reset link
	lastEmail, ok := env.EmailService.LastEmailForRecipient(testEmail)
	if !ok {
		t.Fatal("No reset email sent")
	}
	resetData := lastEmail.Data.(email.PasswordResetData)

	_, err = page.Goto(resetData.Link)
	if err != nil {
		t.Fatalf("Failed to navigate to reset link: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	page.Locator("input[name='password']").Fill(newPassword)
	page.Locator("input[name='confirm_password']").Fill(newPassword)
	page.Locator("button[type='submit']:has-text('Reset password')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

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
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

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

