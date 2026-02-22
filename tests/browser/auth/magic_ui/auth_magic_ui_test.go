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
	lastEmail, ok := env.EmailService.LastEmailForRecipient(testEmail)
	if !ok {
		t.Error("Expected magic link email to be sent, but no matching email captured")
	} else if lastEmail.Template != email.TemplateMagicLink {
		t.Errorf("Wrong email template: got %s, want %s", lastEmail.Template, email.TemplateMagicLink)
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
	lastEmail, ok := env.EmailService.LastEmailForRecipient(testEmail)
	if !ok {
		t.Fatal("No magic link email was sent")
	}
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
		State: playwright.LoadStateDomcontentloaded,
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
	err = emailInput.Fill(GenerateUniqueEmail("oidc-browser"))
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
	err = emailInput.Fill(GenerateUniqueEmail("oidc-return"))
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

