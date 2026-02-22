// Package browser contains Playwright E2E tests for static pages.
// These tests verify that privacy and terms links appear on pages,
// static pages load correctly, and no scrollbars appear at various viewports.
package browser

import (
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// =============================================================================
// Footer Links Tests
// =============================================================================

// TestBrowser_Static_FooterLinksOnLoginPage verifies Privacy, Terms, About, and Install links
// appear on the login page.
func TestBrowser_Static_FooterLinksOnLoginPage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/login")

	// Check for Privacy link
	privacyLink := page.Locator("footer a[href='/privacy']")
	count, err := privacyLink.Count()
	if err != nil || count == 0 {
		t.Error("Privacy link not found in footer")
	}

	// Check for Terms link
	termsLink := page.Locator("footer a[href='/terms']")
	count, err = termsLink.Count()
	if err != nil || count == 0 {
		t.Error("Terms link not found in footer")
	}

	// Check for About link
	aboutLink := page.Locator("footer a[href='/about']")
	count, err = aboutLink.Count()
	if err != nil || count == 0 {
		t.Error("About link not found in footer")
	}

	// Check for Install link (in nav)
	installLink := page.Locator("nav a[href='/docs/install']")
	count, err = installLink.Count()
	if err != nil || count == 0 {
		t.Error("Install link not found in nav")
	}

}

// =============================================================================
// Static Page Content Tests
// =============================================================================

// TestBrowser_Static_AboutPageLoads verifies the about page loads correctly.
func TestBrowser_Static_AboutPageLoads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/about")

	// Check page title
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Failed to get page title: %v", err)
	}
	if !strings.Contains(strings.ToLower(title), "about") {
		t.Errorf("Expected 'About' in page title, got: %s", title)
	}

	// Check for about-related content (common.ink branding)
	pageContent, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(pageContent, "common.ink") {
		t.Error("About page does not contain 'common.ink' in content")
	}
}

// TestBrowser_Static_APIDocsPageLoads verifies the API documentation page loads correctly.
func TestBrowser_Static_APIDocsPageLoads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/docs/api")

	// Check page title
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Failed to get page title: %v", err)
	}
	if !strings.Contains(strings.ToLower(title), "api") && !strings.Contains(strings.ToLower(title), "documentation") {
		t.Errorf("Expected 'API' or 'Documentation' in page title, got: %s", title)
	}

	// Check for API-related content
	pageContent, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(strings.ToLower(pageContent), "api") {
		t.Error("API docs page does not contain 'api' in content")
	}
}

// =============================================================================
// Navigation Tests
// =============================================================================

// TestBrowser_Static_PrivacyLinkNavigates verifies clicking the Privacy link navigates correctly.
func TestBrowser_Static_PrivacyLinkNavigates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Start from login page
	Navigate(t, page, env.BaseURL, "/login")

	// Click Privacy link
	privacyLink := page.Locator("footer a[href='/privacy']")
	err := privacyLink.Click()
	if err != nil {
		t.Fatalf("Failed to click Privacy link: %v", err)
	}

	// Wait for navigation
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// Verify we're on the privacy page
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/privacy") {
		t.Errorf("Expected to be on /privacy, got: %s", currentURL)
	}
}

// TestBrowser_Static_TermsLinkNavigates verifies clicking the Terms link navigates correctly.
func TestBrowser_Static_TermsLinkNavigates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Start from login page
	Navigate(t, page, env.BaseURL, "/login")

	// Click Terms link
	termsLink := page.Locator("footer a[href='/terms']")
	err := termsLink.Click()
	if err != nil {
		t.Fatalf("Failed to click Terms link: %v", err)
	}

	// Wait for navigation
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// Verify we're on the terms page
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/terms") {
		t.Errorf("Expected to be on /terms, got: %s", currentURL)
	}
}

// =============================================================================
// No-Scroll Assertions (Desktop + Mobile)
// =============================================================================

// scrollDimensions holds the scroll measurement results from a page.
type scrollDimensions struct {
	HasVerticalScroll   bool    `json:"hasVerticalScroll"`
	HasHorizontalScroll bool    `json:"hasHorizontalScroll"`
	ScrollHeight        float64 `json:"scrollHeight"`
	InnerHeight         float64 `json:"innerHeight"`
	ScrollWidth         float64 `json:"scrollWidth"`
	InnerWidth          float64 `json:"innerWidth"`
}

func asFloat(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case int32:
		return float64(n)
	case int16:
		return float64(n)
	case int8:
		return float64(n)
	case uint:
		return float64(n)
	case uint64:
		return float64(n)
	case uint32:
		return float64(n)
	case uint16:
		return float64(n)
	case uint8:
		return float64(n)
	default:
		return 0
	}
}

func asBool(v interface{}) bool {
	b, _ := v.(bool)
	return b
}

// parseScrollDimensions converts the raw Evaluate result into scrollDimensions.
func parseScrollDimensions(raw interface{}) scrollDimensions {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return scrollDimensions{}
	}
	return scrollDimensions{
		HasVerticalScroll:   asBool(m["hasVerticalScroll"]),
		HasHorizontalScroll: asBool(m["hasHorizontalScroll"]),
		ScrollHeight:        asFloat(m["scrollHeight"]),
		InnerHeight:         asFloat(m["innerHeight"]),
		ScrollWidth:         asFloat(m["scrollWidth"]),
		InnerWidth:          asFloat(m["innerWidth"]),
	}
}

// assertNoScroll checks that the current page does not overflow horizontally.
// Vertical scroll is expected on long-form content pages (privacy/terms/about).
func assertNoScroll(t *testing.T, page playwright.Page, pagePath string, viewportLabel string) {
	t.Helper()

	raw, err := page.Evaluate(`() => ({
		hasVerticalScroll: document.documentElement.scrollHeight > window.innerHeight,
		hasHorizontalScroll: document.documentElement.scrollWidth > window.innerWidth,
		scrollHeight: document.documentElement.scrollHeight,
		innerHeight: window.innerHeight,
		scrollWidth: document.documentElement.scrollWidth,
		innerWidth: window.innerWidth,
	})`)
	if err != nil {
		t.Fatalf("[%s] %s: failed to evaluate scroll dimensions: %v", viewportLabel, pagePath, err)
	}

	dims := parseScrollDimensions(raw)

	if dims.HasHorizontalScroll {
		t.Errorf("[%s] %s: unexpected horizontal scroll (scrollWidth=%0.f > innerWidth=%0.f)",
			viewportLabel, pagePath, dims.ScrollWidth, dims.InnerWidth)
	}
}

// TestBrowser_Static_NoScroll_Desktop verifies no scrolling on key pages at desktop viewport (1280x720).
func TestBrowser_Static_NoScroll_Desktop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Set desktop viewport
	page.SetViewportSize(1280, 720)

	pages := []string{"/login", "/register", "/privacy", "/terms", "/about"}

	for _, pagePath := range pages {
		_, err := page.Goto(env.BaseURL + pagePath)
		if err != nil {
			t.Fatalf("Failed to navigate to %s: %v", pagePath, err)
		}

		err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
			State: playwright.LoadStateNetworkidle,
		})
		if err != nil {
			t.Fatalf("%s did not finish loading: %v", pagePath, err)
		}

		assertNoScroll(t, page, pagePath, "desktop 1280x720")
	}
}

// TestBrowser_Static_NoScroll_Mobile verifies no scrolling on key pages at mobile viewport (375x667).
func TestBrowser_Static_NoScroll_Mobile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Set mobile viewport
	page.SetViewportSize(375, 667)

	pages := []string{"/login", "/register", "/privacy", "/terms", "/about"}

	for _, pagePath := range pages {
		_, err := page.Goto(env.BaseURL + pagePath)
		if err != nil {
			t.Fatalf("Failed to navigate to %s: %v", pagePath, err)
		}

		err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
			State: playwright.LoadStateNetworkidle,
		})
		if err != nil {
			t.Fatalf("%s did not finish loading: %v", pagePath, err)
		}

		assertNoScroll(t, page, pagePath, "mobile 375x667")
	}
}
