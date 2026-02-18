// Package browser contains Playwright E2E tests for billing flow pages.
// These tests verify pricing, billing settings, success page, and the full upgrade journey
// using the mock billing service (billing.NewMockService()).
package browser

import (
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// newPageFromContext creates a page from a browser context with default timeouts.
func newPageFromContext(t *testing.T, ctx playwright.BrowserContext) playwright.Page {
	t.Helper()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page from context: %v", err)
	}
	page.SetDefaultTimeout(browserMaxTimeoutMS)
	page.SetDefaultNavigationTimeout(browserMaxTimeoutMS)
	return page
}

// =============================================================================
// Test 1: Pricing Page Rendering + Nav Links
// =============================================================================

func TestBilling_PricingPage_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// --- Logged-out user ---
	loggedOutCtx := env.NewContext(t)
	defer loggedOutCtx.Close()
	page := newPageFromContext(t, loggedOutCtx)
	defer page.Close()

	// Landing page: verify "Pricing" nav link visible for logged-out users
	Navigate(t, page, env.BaseURL, "/")

	pricingNavLink := page.Locator("nav a[href='/pricing']")
	err := pricingNavLink.First().WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Pricing nav link not visible for logged-out user: %v", err)
	}

	// Landing page: verify pricing section with "View Pricing" link
	viewPricingLink := page.Locator("a[href='/pricing']:has-text('View Pricing')")
	err = viewPricingLink.First().WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Landing page 'View Pricing' link not found: %v", err)
	}

	// Navigate to /pricing
	Navigate(t, page, env.BaseURL, "/pricing")

	// Verify heading
	heading := WaitForSelector(t, page, "h1")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get pricing heading text: %v", err)
	}
	if !strings.Contains(strings.ToLower(headingText), "pricing") {
		t.Errorf("Pricing heading should mention pricing, got: %q", headingText)
	}

	// Verify Free card with "Get Started Free" linking to /register
	freeLink := page.Locator("a[href='/register']:has-text('Get Started Free')")
	count, err := freeLink.Count()
	if err != nil || count == 0 {
		t.Error("Free card should have 'Get Started Free' link to /register")
	}

	// Verify Pro card pricing
	content, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get pricing page content: %v", err)
	}
	if !strings.Contains(content, "$2") {
		t.Error("Pro card should show $2 monthly price")
	}
	if !strings.Contains(content, "$20") {
		t.Error("Pro card should show $20 annual price")
	}

	// Verify mock mode message
	if !strings.Contains(content, "Payments unavailable in test mode") {
		t.Error("Mock billing should show 'Payments unavailable in test mode.'")
	}

	// --- Logged-in user: same content renders ---
	loggedInCtx := env.NewContext(t)
	defer loggedInCtx.Close()
	page2 := newPageFromContext(t, loggedInCtx)
	defer page2.Close()

	env.LoginUser(t, loggedInCtx, GenerateUniqueEmail("billing-pricing"))

	Navigate(t, page2, env.BaseURL, "/pricing")

	content2, err := page2.Content()
	if err != nil {
		t.Fatalf("Failed to get logged-in pricing content: %v", err)
	}
	if !strings.Contains(content2, "Payments unavailable in test mode") {
		t.Error("Mock billing message should appear for logged-in user")
	}
	if !strings.Contains(content2, "Get Started Free") {
		t.Error("Free card should appear for logged-in user")
	}
}

// =============================================================================
// Test 2: Billing Settings for Free vs Pro + Portal Redirect
// =============================================================================

func TestBilling_SettingsAndPortal_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// --- Free user billing settings ---
	ctx1 := env.NewContext(t)
	defer ctx1.Close()
	page := newPageFromContext(t, ctx1)
	defer page.Close()

	email := GenerateUniqueEmail("billing-settings")
	userID := env.LoginUser(t, ctx1, email)

	Navigate(t, page, env.BaseURL, "/settings/billing")

	// Verify "Free" badge is visible
	WaitForSelector(t, page, "span:has-text('Free')")

	// Verify "Upgrade to Pro" link is present
	upgradeLink := WaitForSelector(t, page, "a[href='/pricing']:has-text('Upgrade to Pro')")

	// Verify "Manage Billing" button is NOT present
	manageBillingCount, _ := page.Locator("button:has-text('Manage Billing')").Count()
	if manageBillingCount > 0 {
		t.Error("Free user should NOT see 'Manage Billing' button")
	}

	// Click "Upgrade to Pro" -> should navigate to /pricing
	if err := upgradeLink.Click(); err != nil {
		t.Fatalf("Failed to click 'Upgrade to Pro': %v", err)
	}
	if err := page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	}); err != nil {
		t.Fatalf("Navigation after Upgrade click did not complete: %v", err)
	}
	if !strings.Contains(page.URL(), "/pricing") {
		t.Errorf("Expected /pricing after clicking Upgrade, got: %s", page.URL())
	}

	// --- Pro user billing settings ---
	env.SetUserSubscription(t, userID, "active", "cus_mock123")

	Navigate(t, page, env.BaseURL, "/settings/billing")

	// Verify "Pro" badge is visible
	WaitForSelector(t, page, "span:has-text('Pro')")

	// Verify "Manage Billing" button is present
	manageBilling := WaitForSelector(t, page, "button:has-text('Manage Billing')")

	// Verify "Upgrade to Pro" link is NOT present
	upgradeCount, _ := page.Locator("a:has-text('Upgrade to Pro')").Count()
	if upgradeCount > 0 {
		t.Error("Pro user should NOT see 'Upgrade to Pro' link")
	}

	// Submit portal form -> should redirect to mock portal URL
	if err := manageBilling.Click(); err != nil {
		t.Fatalf("Failed to click 'Manage Billing': %v", err)
	}
	if err := page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	}); err != nil {
		t.Fatalf("Navigation after portal form did not complete: %v", err)
	}
	if !strings.Contains(page.URL(), "mock_portal=true") {
		t.Errorf("Expected redirect to URL with mock_portal=true, got: %s", page.URL())
	}

	// --- Active subscription WITHOUT stripe_customer_id -> portal redirects to /pricing ---
	ctx2 := env.NewContext(t)
	defer ctx2.Close()
	page2 := newPageFromContext(t, ctx2)
	defer page2.Close()

	email2 := GenerateUniqueEmail("billing-noid")
	userID2 := env.LoginUser(t, ctx2, email2)
	env.SetUserSubscription(t, userID2, "active", "")

	Navigate(t, page2, env.BaseURL, "/settings/billing")

	// Template shows "Manage Billing" because subscription_status='active'
	manageBilling2 := WaitForSelector(t, page2, "button:has-text('Manage Billing')")
	if err := manageBilling2.Click(); err != nil {
		t.Fatalf("Failed to click 'Manage Billing' for no-customer user: %v", err)
	}
	if err := page2.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	}); err != nil {
		t.Fatalf("Navigation after portal form did not complete: %v", err)
	}
	if !strings.Contains(page2.URL(), "/pricing") {
		t.Errorf("Expected redirect to /pricing for user without stripe_customer_id, got: %s", page2.URL())
	}
}

// =============================================================================
// Test 3: Billing Success Page in All 3 States
// =============================================================================

func TestBilling_SuccessPage_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// --- State 1: Logged-in + session_id -> "Welcome to Pro!" + "Go to Notes" ---
	loggedInCtx := env.NewContext(t)
	defer loggedInCtx.Close()
	page1 := newPageFromContext(t, loggedInCtx)
	defer page1.Close()

	env.LoginUser(t, loggedInCtx, GenerateUniqueEmail("billing-success-li"))

	Navigate(t, page1, env.BaseURL, "/billing/success?session_id=mock")

	WaitForSelector(t, page1, "h1:has-text('Welcome to Pro!')")

	goToNotesLink := WaitForSelector(t, page1, "a[href='/notes']:has-text('Go to Notes')")
	href, err := goToNotesLink.GetAttribute("href")
	if err != nil || href != "/notes" {
		t.Errorf("Expected 'Go to Notes' link with href=/notes, got: %q", href)
	}

	// --- State 2: Logged-out + session_id -> "Welcome to Pro!" + "Create Account" ---
	// Reuse page1's context after clearing cookies (avoids Tailwind CDN re-download)
	page1.Context().ClearCookies()

	Navigate(t, page1, env.BaseURL, "/billing/success?session_id=mock")

	WaitForSelector(t, page1, "h1:has-text('Welcome to Pro!')")

	// Verify "Create Account" link is present in the main content section
	// (base template nav also has a "Create account" link to /register, so scope to <section>)
	createAccountLink := page1.Locator("section a:has-text('Create Account')").First()
	err = createAccountLink.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateAttached,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		content2, _ := page1.Content()
		t.Fatalf("Create Account link not found in DOM. Content length: %d, has text: %v",
			len(content2), strings.Contains(content2, "Create Account"))
	}
	href2, err := createAccountLink.GetAttribute("href")
	if err != nil {
		t.Fatalf("Failed to get Create Account href: %v", err)
	}
	if !strings.Contains(href2, "/register") || !strings.Contains(href2, "email=mock") {
		t.Errorf("Expected Create Account link to /register with mock email, got: %q", href2)
	}

	// --- State 3: No session_id -> "Payment Incomplete" + "Try Again" ---
	page1.Context().ClearCookies()

	Navigate(t, page1, env.BaseURL, "/billing/success")

	WaitForSelector(t, page1, "h1:has-text('Payment Incomplete')")

	tryAgainLink := page1.Locator("a[href='/pricing']:has-text('Try Again')").First()
	err = tryAgainLink.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateAttached,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Try Again link not found: %v", err)
	}
	href3, err := tryAgainLink.GetAttribute("href")
	if err != nil || href3 != "/pricing" {
		t.Errorf("Expected 'Try Again' link with href=/pricing, got: %q", href3)
	}
}

// =============================================================================
// Test 4: Full Journey - Register -> Billing Settings -> Upgrade -> Success
// =============================================================================

func TestBilling_FullJourney_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()
	page := newPageFromContext(t, ctx)
	defer page.Close()

	// Step 1: Register via browser UI
	testEmail := GenerateUniqueEmail("billing-journey")
	testPassword := "SecurePass123!"

	Navigate(t, page, env.BaseURL, "/register")

	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()

	err := page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Registration did not complete: %v", err)
	}

	if !strings.Contains(page.URL(), "/notes") {
		t.Fatalf("Expected /notes after registration, got: %s", page.URL())
	}

	// Step 2: Open user dropdown and click "Billing"
	userMenuBtn := page.Locator("#user-menu-button")
	if err := userMenuBtn.Click(); err != nil {
		t.Fatalf("Failed to click user menu button: %v", err)
	}

	dropdown := page.Locator("#user-dropdown")
	err = dropdown.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("User dropdown did not appear: %v", err)
	}

	billingLink := dropdown.Locator("a[href='/settings/billing']")
	if err := billingLink.Click(); err != nil {
		t.Fatalf("Failed to click Billing link in dropdown: %v", err)
	}
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Navigation to billing settings did not complete: %v", err)
	}

	// Verify on /settings/billing with "Free" badge
	if !strings.Contains(page.URL(), "/settings/billing") {
		t.Errorf("Expected /settings/billing, got: %s", page.URL())
	}
	WaitForSelector(t, page, "span:has-text('Free')")

	// Step 3: Click "Upgrade to Pro" -> should land on /pricing
	upgradeLink := WaitForSelector(t, page, "a[href='/pricing']:has-text('Upgrade to Pro')")
	if err := upgradeLink.Click(); err != nil {
		t.Fatalf("Failed to click Upgrade to Pro: %v", err)
	}
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Navigation to pricing did not complete: %v", err)
	}
	if !strings.Contains(page.URL(), "/pricing") {
		t.Errorf("Expected /pricing, got: %s", page.URL())
	}

	// Step 4: POST /billing/checkout with plan=monthly -> verify mock response
	checkoutResult, err := page.Evaluate(`async () => {
		const response = await fetch('/billing/checkout', {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({plan: 'monthly'})
		});
		return await response.json();
	}`)
	if err != nil {
		t.Fatalf("Failed to POST /billing/checkout: %v", err)
	}

	resultMap, ok := checkoutResult.(map[string]interface{})
	if !ok {
		t.Fatalf("Checkout result is not a map: %T", checkoutResult)
	}
	clientSecret, ok := resultMap["clientSecret"].(string)
	if !ok || clientSecret != "mock_cs_secret_monthly" {
		t.Errorf("Expected clientSecret='mock_cs_secret_monthly', got: %v", resultMap["clientSecret"])
	}

	// Step 5: Navigate to /billing/success?session_id=test -> verify "Welcome to Pro!"
	Navigate(t, page, env.BaseURL, "/billing/success?session_id=test")

	WaitForSelector(t, page, "h1:has-text('Welcome to Pro!')")
}
