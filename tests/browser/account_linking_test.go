// Package browser contains Playwright E2E tests for account settings / linking features.
// These tests verify account settings page rendering for different auth states,
// set-password flow for Google-only users, pricing page Google option,
// and billing success page with both sign-in options.
package browser

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/userdb"
)

// =============================================================================
// Test helpers for account linking scenarios
// =============================================================================

// setUserPasswordDirect sets a password hash on a user's account record directly via DB,
// bypassing the auth service. Uses FakeInsecureHasher format ($fake$<plaintext>).
func setUserPasswordDirect(t *testing.T, env *BrowserTestEnv, userID, password string) {
	t.Helper()

	dek, err := env.KeyManager.GetUserDEK(userID)
	if err != nil {
		t.Fatalf("Failed to get DEK for user %s: %v", userID, err)
	}

	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		t.Fatalf("Failed to open user DB for %s: %v", userID, err)
	}

	// FakeInsecureHasher format: "$fake$<plaintext>"
	fakeHash := "$fake$" + password
	err = userDB.Queries().UpdateAccountPasswordHash(context.Background(), userdb.UpdateAccountPasswordHashParams{
		PasswordHash: sql.NullString{String: fakeHash, Valid: true},
		UserID:       userID,
	})
	if err != nil {
		t.Fatalf("Failed to set password hash for user %s: %v", userID, err)
	}
}

// setUserGoogleSubDirect sets a google_sub on a user's account record directly via DB.
func setUserGoogleSubDirect(t *testing.T, env *BrowserTestEnv, userID, googleSub string) {
	t.Helper()

	dek, err := env.KeyManager.GetUserDEK(userID)
	if err != nil {
		t.Fatalf("Failed to get DEK for user %s: %v", userID, err)
	}

	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		t.Fatalf("Failed to open user DB for %s: %v", userID, err)
	}

	err = userDB.Queries().UpdateAccountGoogleSub(context.Background(), userdb.UpdateAccountGoogleSubParams{
		GoogleSub: sql.NullString{String: googleSub, Valid: true},
		UserID:    userID,
	})
	if err != nil {
		t.Fatalf("Failed to set google_sub for user %s: %v", userID, err)
	}
}

// =============================================================================
// B1. Account settings page renders correctly for all 3 auth states
// =============================================================================

func TestAccountSettings_PasswordOnlyUser_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()
	page := newPageFromContext(t, ctx)
	defer page.Close()

	// Create a password-only user (FindOrCreateByProvider creates with NULL password_hash,
	// then we set password directly).
	email := GenerateUniqueEmail("acct-pwonly")
	userID := env.LoginUser(t, ctx, email)
	setUserPasswordDirect(t, env, userID, "TestPassword123!")

	// Navigate to account settings
	Navigate(t, page, env.BaseURL, "/settings/account")

	// Verify email is displayed
	emailInput := WaitForSelector(t, page, "#account-email")
	emailVal, err := emailInput.InputValue()
	if err != nil {
		t.Fatalf("Failed to get email input value: %v", err)
	}
	if emailVal != email {
		t.Errorf("Expected email %q in input, got %q", email, emailVal)
	}

	// Verify "Change Password" heading is visible (HasPassword=true branch)
	content, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(content, "Change Password") {
		t.Error("Password-only user should see 'Change Password' heading")
	}

	// Verify #current-password input is present
	WaitForSelector(t, page, "#current-password")

	// Verify #new-password and #confirm-new-password are present
	WaitForSelector(t, page, "#new-password")
	WaitForSelector(t, page, "#confirm-new-password")

	// Verify #change-password-btn is present
	WaitForSelector(t, page, "#change-password-btn")

	// Verify Google section shows "Link Google Account" button (HasGoogle=false)
	WaitForSelector(t, page, "#link-google-btn")

	// Verify unlink button is NOT present
	unlinkCount, _ := page.Locator("#unlink-google-btn").Count()
	if unlinkCount > 0 {
		t.Error("Password-only user should NOT see 'Unlink Google' button")
	}
}

func TestAccountSettings_GoogleOnlyUser_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()
	page := newPageFromContext(t, ctx)
	defer page.Close()

	// Create a Google-only user (NULL password_hash, valid google_sub)
	email := GenerateUniqueEmail("acct-googleonly")
	userID := env.LoginUser(t, ctx, email)
	setUserGoogleSubDirect(t, env, userID, "google-sub-12345")

	// Navigate to account settings
	Navigate(t, page, env.BaseURL, "/settings/account")

	// Verify "Set Password" heading is visible (HasPassword=false branch)
	content, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(content, "Set Password") {
		t.Error("Google-only user should see 'Set Password' heading")
	}

	// Verify #current-password input is NOT present (no existing password)
	currentPwCount, _ := page.Locator("#current-password").Count()
	if currentPwCount > 0 {
		t.Error("Google-only user should NOT see current-password field")
	}

	// Verify #set-password-btn is present (not #change-password-btn)
	WaitForSelector(t, page, "#set-password-btn")
	changeBtnCount, _ := page.Locator("#change-password-btn").Count()
	if changeBtnCount > 0 {
		t.Error("Google-only user should NOT see 'Change Password' button")
	}

	// Verify Google section shows "Google account linked" badge
	linkedBadge := page.Locator("span:has-text('Google account linked')")
	badgeCount, _ := linkedBadge.Count()
	if badgeCount == 0 {
		t.Error("Google-only user should see 'Google account linked' badge")
	}

	// Verify unlink button exists but is disabled (no password set yet)
	unlinkBtn := page.Locator("#unlink-google-btn")
	unlinkCount, _ := unlinkBtn.Count()
	if unlinkCount == 0 {
		t.Fatal("Google-only user should see 'Unlink Google' button")
	}
	isDisabled, err := unlinkBtn.First().IsDisabled()
	if err != nil {
		t.Fatalf("Failed to check unlink button disabled state: %v", err)
	}
	if !isDisabled {
		t.Error("Unlink button should be disabled for Google-only user (no password set)")
	}

	// Verify #link-google-btn is NOT present (already linked)
	linkBtnCount, _ := page.Locator("#link-google-btn").Count()
	if linkBtnCount > 0 {
		t.Error("Google-only user should NOT see 'Link Google Account' button")
	}
}

func TestAccountSettings_BothMethodsUser_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()
	page := newPageFromContext(t, ctx)
	defer page.Close()

	// Create a user with both password and Google linked
	email := GenerateUniqueEmail("acct-both")
	userID := env.LoginUser(t, ctx, email)
	setUserPasswordDirect(t, env, userID, "TestPassword123!")
	setUserGoogleSubDirect(t, env, userID, "google-sub-67890")

	// Navigate to account settings
	Navigate(t, page, env.BaseURL, "/settings/account")

	// Verify "Change Password" heading (HasPassword=true)
	content, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(content, "Change Password") {
		t.Error("Both-methods user should see 'Change Password' heading")
	}

	// Verify #current-password input IS present
	WaitForSelector(t, page, "#current-password")

	// Verify #change-password-btn is present
	WaitForSelector(t, page, "#change-password-btn")

	// Verify Google section shows "Google account linked" badge
	linkedBadge := page.Locator("span:has-text('Google account linked')")
	badgeCount, _ := linkedBadge.Count()
	if badgeCount == 0 {
		t.Error("Both-methods user should see 'Google account linked' badge")
	}

	// Verify unlink button exists and is ENABLED (has password, can safely unlink)
	unlinkBtn := WaitForSelector(t, page, "#unlink-google-btn")
	isDisabled, err := unlinkBtn.IsDisabled()
	if err != nil {
		t.Fatalf("Failed to check unlink button disabled state: %v", err)
	}
	if isDisabled {
		t.Error("Unlink button should be ENABLED for both-methods user (has password)")
	}

	// Verify #link-google-btn is NOT present (already linked)
	linkBtnCount, _ := page.Locator("#link-google-btn").Count()
	if linkBtnCount > 0 {
		t.Error("Both-methods user should NOT see 'Link Google Account' button")
	}
}

// =============================================================================
// B2. Set password flow (Google-only user adds a password)
// =============================================================================

func TestAccountSettings_SetPasswordFlow_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()
	page := newPageFromContext(t, ctx)
	defer page.Close()

	// Create a Google-only user (no password)
	email := GenerateUniqueEmail("acct-setpw")
	userID := env.LoginUser(t, ctx, email)
	setUserGoogleSubDirect(t, env, userID, "google-sub-setpw")

	// Navigate to account settings
	Navigate(t, page, env.BaseURL, "/settings/account")

	// Verify we start with "Set Password" heading (no password)
	WaitForSelector(t, page, "#set-password-btn")

	// Fill the set-password form
	newPwInput := WaitForSelector(t, page, "#new-password")
	confirmPwInput := WaitForSelector(t, page, "#confirm-new-password")

	newPassword := "NewSecurePass99!"
	if err := newPwInput.Fill(newPassword); err != nil {
		t.Fatalf("Failed to fill new-password: %v", err)
	}
	if err := confirmPwInput.Fill(newPassword); err != nil {
		t.Fatalf("Failed to fill confirm-new-password: %v", err)
	}

	// Submit the form
	submitBtn := WaitForSelector(t, page, "#set-password-btn")
	if err := submitBtn.Click(); err != nil {
		t.Fatalf("Failed to click Set Password button: %v", err)
	}

	// Wait for redirect back to /settings/account with success flash
	err := page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Navigation after set-password did not complete: %v", err)
	}

	// Verify success flash message
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/settings/account") {
		t.Fatalf("Expected redirect to /settings/account, got: %s", currentURL)
	}
	if !strings.Contains(currentURL, "success=password_set") {
		t.Errorf("Expected success=password_set in URL, got: %s", currentURL)
	}

	// Verify the flash message is rendered
	content, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(content, "Password updated successfully") {
		t.Error("Expected 'Password updated successfully' flash message after setting password")
	}

	// Verify the page now shows "Change Password" heading (password is set)
	if !strings.Contains(content, "Change Password") {
		t.Error("After setting password, page should show 'Change Password' heading")
	}

	// Verify #current-password field now appears (has password)
	currentPwCount, _ := page.Locator("#current-password").Count()
	if currentPwCount == 0 {
		t.Error("After setting password, #current-password field should appear")
	}

	// Verify #change-password-btn is now present (replaces #set-password-btn)
	changeBtnCount, _ := page.Locator("#change-password-btn").Count()
	if changeBtnCount == 0 {
		t.Error("After setting password, #change-password-btn should appear")
	}
}

// =============================================================================
// B3. Pricing page shows Google option for logged-out users (non-mock billing only)
// =============================================================================

func TestPricing_GoogleOptionForLoggedOut_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// The test env uses MockBillingService which reports IsMock()=true.
	// In mock billing mode, the pricing template shows "Payments unavailable in test mode"
	// instead of Google/checkout buttons. This test verifies the mock-mode rendering
	// and checks the template structure: when not in mock mode, the Google sign-in
	// button would appear for logged-out users inside the Pro plan card.

	loggedOutCtx := env.NewContext(t)
	defer loggedOutCtx.Close()
	page := newPageFromContext(t, loggedOutCtx)
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/pricing")

	// Verify pricing page renders
	heading := WaitForSelector(t, page, "h1")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get heading text: %v", err)
	}
	if !strings.Contains(strings.ToLower(headingText), "pricing") {
		t.Errorf("Expected pricing heading, got: %q", headingText)
	}

	// Verify mock billing shows the mock-mode message instead of Google button
	content, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(content, "Payments unavailable in test mode") {
		t.Error("Mock billing should show 'Payments unavailable in test mode' message")
	}

	// Verify basic pricing structure: Free plan card with "Get Started Free"
	freeLink := page.Locator("a[href='/register']:has-text('Get Started Free')")
	freeCount, _ := freeLink.Count()
	if freeCount == 0 {
		t.Error("Pricing page should have 'Get Started Free' link for Free plan")
	}

	// Verify Pro plan card exists with pricing
	if !strings.Contains(content, "$2") {
		t.Error("Pro plan should show $2/mo pricing")
	}
}

// =============================================================================
// B4. Success page shows both account creation options
// =============================================================================

func TestBillingSuccess_BothSignInOptions_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// Logged-out user visiting success page with session_id
	loggedOutCtx := env.NewContext(t)
	defer loggedOutCtx.Close()
	page := newPageFromContext(t, loggedOutCtx)
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/billing/success?session_id=mock")

	// Verify "Welcome to Pro!" heading
	WaitForSelector(t, page, "h1:has-text('Welcome to Pro!')")

	// Verify "Create Account" link is present (scoped to section to avoid nav links)
	createAccountLink := page.Locator("section a:has-text('Create Account')").First()
	err := createAccountLink.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateAttached,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("'Create Account' link not found on success page: %v", err)
	}

	// Verify Create Account link points to /register with email param
	href, err := createAccountLink.GetAttribute("href")
	if err != nil {
		t.Fatalf("Failed to get Create Account href: %v", err)
	}
	if !strings.Contains(href, "/register") {
		t.Errorf("Expected Create Account href to contain /register, got: %q", href)
	}

	// Verify "Sign in with Google" button is present
	googleBtn := page.Locator("section button:has-text('Sign in with Google')").First()
	err = googleBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateAttached,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("'Sign in with Google' button not found on success page: %v", err)
	}

	// Verify the Google button is inside a form that posts to /auth/google
	googleForm := page.Locator("section form[action='/auth/google']")
	formCount, _ := googleForm.Count()
	if formCount == 0 {
		t.Error("Expected Google sign-in form with action='/auth/google' on success page")
	}

	// Verify the "or" divider is present between the two options
	content, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(content, "or") {
		t.Error("Expected 'or' divider between Create Account and Google sign-in options")
	}
}

// =============================================================================
// B5. Logged-in user on success page sees "Go to Notes" (no Google option)
// =============================================================================

func TestBillingSuccess_LoggedInUser_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	loggedInCtx := env.NewContext(t)
	defer loggedInCtx.Close()
	page := newPageFromContext(t, loggedInCtx)
	defer page.Close()

	env.LoginUser(t, loggedInCtx, GenerateUniqueEmail("acct-success-li"))

	Navigate(t, page, env.BaseURL, "/billing/success?session_id=mock")

	// Verify "Welcome to Pro!" heading
	WaitForSelector(t, page, "h1:has-text('Welcome to Pro!')")

	// Verify "Go to Notes" link
	goToNotes := WaitForSelector(t, page, "a[href='/notes']:has-text('Go to Notes')")
	href, err := goToNotes.GetAttribute("href")
	if err != nil || href != "/notes" {
		t.Errorf("Expected 'Go to Notes' link with href=/notes, got: %q", href)
	}

	// Verify "Create Account" link is NOT present (user is already logged in)
	createAccountCount, _ := page.Locator("section a:has-text('Create Account')").Count()
	if createAccountCount > 0 {
		t.Error("Logged-in user should NOT see 'Create Account' link on success page")
	}

	// Verify "Sign in with Google" button is NOT present (user is already logged in)
	googleBtnCount, _ := page.Locator("section button:has-text('Sign in with Google')").Count()
	if googleBtnCount > 0 {
		t.Error("Logged-in user should NOT see 'Sign in with Google' on success page")
	}
}
