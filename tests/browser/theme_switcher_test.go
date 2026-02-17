// Package browser contains Playwright E2E tests for theme switching and dark mode toggle.
// These tests verify that the appearance controls in the nav bar work correctly,
// persist via localStorage, and survive navigation.
package browser

import (
	"strconv"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// =============================================================================
// Dark Mode Toggle Tests
// =============================================================================

// TestBrowser_DarkMode_ToggleCycles verifies clicking the dark mode toggle
// cycles through system → light → dark, updating the <html> class and icon.
func TestBrowser_DarkMode_ToggleCycles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Navigate to login page (uses base.html with nav bar controls)
	Navigate(t, page, env.BaseURL, "/login")

	// Clear any previous localStorage state
	page.Evaluate(`() => { localStorage.removeItem('ci_darkmode'); localStorage.removeItem('ci_theme'); }`)
	page.Reload()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	toggle := page.Locator("#darkmode-toggle")
	count, err := toggle.Count()
	if err != nil || count == 0 {
		t.Fatal("Dark mode toggle button not found")
	}

	// Default state: system mode — system icon visible
	systemIcon := page.Locator("#dm-icon-system")
	visible, _ := systemIcon.IsVisible()
	if !visible {
		t.Error("System icon should be visible in default (system) mode")
	}

	// Click 1: system → light
	toggle.Click()
	lightIcon := page.Locator("#dm-icon-light")
	visible, _ = lightIcon.IsVisible()
	if !visible {
		t.Error("Light icon should be visible after first click")
	}
	// In light mode, html should NOT have dark class
	htmlClass, _ := page.Locator("html").GetAttribute("class")
	if strings.Contains(htmlClass, "dark") {
		t.Error("html should not have 'dark' class in light mode")
	}

	// Click 2: light → dark
	toggle.Click()
	darkIcon := page.Locator("#dm-icon-dark")
	visible, _ = darkIcon.IsVisible()
	if !visible {
		t.Error("Dark icon should be visible after second click")
	}
	// In dark mode, html SHOULD have dark class
	htmlClass, _ = page.Locator("html").GetAttribute("class")
	if !strings.Contains(htmlClass, "dark") {
		t.Error("html should have 'dark' class in dark mode")
	}

	// Click 3: dark → system (back to start)
	toggle.Click()
	visible, _ = systemIcon.IsVisible()
	if !visible {
		t.Error("System icon should be visible after third click (cycle complete)")
	}
}

// TestBrowser_DarkMode_PersistsAcrossNavigation verifies dark mode preference
// persists when navigating to a different page.
func TestBrowser_DarkMode_PersistsAcrossNavigation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Navigate to login page
	Navigate(t, page, env.BaseURL, "/login")

	// Set dark mode via localStorage directly
	page.Evaluate(`() => localStorage.setItem('ci_darkmode', 'dark')`)

	// Navigate to a different page
	Navigate(t, page, env.BaseURL, "/about")

	// html should have dark class
	htmlClass, _ := page.Locator("html").GetAttribute("class")
	if !strings.Contains(htmlClass, "dark") {
		t.Error("Dark mode should persist across navigation — html missing 'dark' class on /about")
	}

	// Dark icon should be visible
	darkIcon := page.Locator("#dm-icon-dark")
	visible, _ := darkIcon.IsVisible()
	if !visible {
		t.Error("Dark icon should be visible after navigating with dark mode set")
	}
}

// =============================================================================
// Theme Switching Tests
// =============================================================================

// TestBrowser_ThemeSwitcher_SwatchesPresent verifies all three theme swatches exist.
func TestBrowser_ThemeSwitcher_SwatchesPresent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/login")

	for _, theme := range []string{"default", "academic", "neonfizz"} {
		swatch := page.Locator("button[data-theme='" + theme + "']")
		count, err := swatch.Count()
		if err != nil || count == 0 {
			t.Errorf("Theme swatch for '%s' not found", theme)
		}
	}
}

// TestBrowser_ThemeSwitcher_DefaultHasRing verifies the default theme swatch has
// the active ring indicator when no theme is set in localStorage.
func TestBrowser_ThemeSwitcher_DefaultHasRing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/login")

	// Clear localStorage
	page.Evaluate(`() => localStorage.removeItem('ci_theme')`)
	page.Reload()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Default swatch should have ring-2 class
	defaultSwatch := page.Locator("button[data-theme='default']")
	classAttr, err := defaultSwatch.GetAttribute("class")
	if err != nil {
		t.Fatalf("Failed to get class: %v", err)
	}
	if !strings.Contains(classAttr, "ring-2") {
		t.Errorf("Default theme swatch should have ring-2 class, got: %s", classAttr)
	}

	// Other swatches should NOT have ring-2
	for _, theme := range []string{"academic", "neonfizz"} {
		swatch := page.Locator("button[data-theme='" + theme + "']")
		cls, _ := swatch.GetAttribute("class")
		if strings.Contains(cls, "ring-2") {
			t.Errorf("'%s' swatch should NOT have ring-2 when default is active", theme)
		}
	}
}

// TestBrowser_ThemeSwitcher_SetsLocalStorage verifies clicking a theme swatch
// sets localStorage and the page reloads with the correct theme.
func TestBrowser_ThemeSwitcher_SetsLocalStorage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/login")

	// Clear localStorage
	page.Evaluate(`() => localStorage.removeItem('ci_theme')`)
	page.Reload()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Click the academic swatch — page will reload
	academicSwatch := page.Locator("button[data-theme='academic']")
	academicSwatch.Click()

	// Wait for reload
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})

	// Verify localStorage was set
	storedTheme, err := page.Evaluate(`() => localStorage.getItem('ci_theme')`)
	if err != nil {
		t.Fatalf("Failed to read localStorage: %v", err)
	}
	if storedTheme != "academic" {
		t.Errorf("Expected ci_theme='academic' in localStorage, got: %v", storedTheme)
	}

	// Academic swatch should now have the ring
	academicSwatch = page.Locator("button[data-theme='academic']")
	classAttr, _ := academicSwatch.GetAttribute("class")
	if !strings.Contains(classAttr, "ring-2") {
		t.Error("Academic swatch should have ring-2 after being selected")
	}
}

// TestBrowser_ThemeSwitcher_PersistsAcrossNavigation verifies the theme choice
// persists when navigating to a different page.
func TestBrowser_ThemeSwitcher_PersistsAcrossNavigation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Set theme via localStorage
	Navigate(t, page, env.BaseURL, "/login")
	page.Evaluate(`() => localStorage.setItem('ci_theme', 'neonfizz')`)

	// Navigate to a different page
	Navigate(t, page, env.BaseURL, "/about")

	// Verify localStorage still has the theme
	storedTheme, err := page.Evaluate(`() => localStorage.getItem('ci_theme')`)
	if err != nil {
		t.Fatalf("Failed to read localStorage: %v", err)
	}
	if storedTheme != "neonfizz" {
		t.Errorf("Expected ci_theme='neonfizz' after navigation, got: %v", storedTheme)
	}

	// Neon Fizz swatch should have the ring
	neonSwatch := page.Locator("button[data-theme='neonfizz']")
	classAttr, _ := neonSwatch.GetAttribute("class")
	if !strings.Contains(classAttr, "ring-2") {
		t.Error("Neon Fizz swatch should have ring-2 on /about page after being set on /login")
	}
}

// =============================================================================
// Default State Test
// =============================================================================

// TestBrowser_Appearance_DefaultState verifies fresh browser state:
// default blue theme active, system dark mode, correct icons.
func TestBrowser_Appearance_DefaultState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// Create a fresh context to ensure clean localStorage
	ctx := env.NewContext(t)
	defer ctx.Close()

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(browserMaxTimeoutMS)

	Navigate(t, page, env.BaseURL, "/login")

	// Default theme swatch should have ring
	defaultSwatch := page.Locator("button[data-theme='default']")
	classAttr, _ := defaultSwatch.GetAttribute("class")
	if !strings.Contains(classAttr, "ring-2") {
		t.Error("Default swatch should have ring-2 in fresh browser state")
	}

	// System icon should be visible (default dark mode = system)
	systemIcon := page.Locator("#dm-icon-system")
	visible, _ := systemIcon.IsVisible()
	if !visible {
		t.Error("System icon should be visible in fresh browser state")
	}

	// No ci_theme or ci_darkmode in localStorage
	themeVal, _ := page.Evaluate(`() => localStorage.getItem('ci_theme')`)
	if themeVal != nil {
		t.Errorf("ci_theme should be null in fresh state, got: %v", themeVal)
	}
	darkVal, _ := page.Evaluate(`() => localStorage.getItem('ci_darkmode')`)
	if darkVal != nil {
		t.Errorf("ci_darkmode should be null in fresh state, got: %v", darkVal)
	}
}

// =============================================================================
// Appearance Controls Placement Tests
// =============================================================================

// TestBrowser_AppearanceControls_InFooterNotNav verifies that appearance controls
// (dark mode toggle + theme swatches) are in the footer, not in the nav bar.
func TestBrowser_AppearanceControls_InFooterNotNav(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	// Navigate to login page (uses base.html with nav + footer)
	Navigate(t, page, env.BaseURL, "/login")

	// Appearance controls should be inside the footer
	footerToggle := page.Locator("footer #darkmode-toggle")
	count, err := footerToggle.Count()
	if err != nil || count == 0 {
		t.Error("Dark mode toggle should be inside <footer>")
	}

	footerSwatches := page.Locator("footer #theme-swatches")
	count, err = footerSwatches.Count()
	if err != nil || count == 0 {
		t.Error("Theme swatches should be inside <footer>")
	}

	// Appearance controls should NOT be inside the nav
	navToggle := page.Locator("nav #darkmode-toggle")
	count, err = navToggle.Count()
	if err != nil || count != 0 {
		t.Error("Dark mode toggle should NOT be inside <nav>")
	}

	navSwatches := page.Locator("nav #theme-swatches")
	count, err = navSwatches.Count()
	if err != nil || count != 0 {
		t.Error("Theme swatches should NOT be inside <nav>")
	}
}

// =============================================================================
// Per-Theme Visual Assertion Tests
// =============================================================================

func TestBrowser_ThemeVisual_DefaultAttributes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/login")
	page.Evaluate(`() => { localStorage.setItem('ci_theme', 'default'); localStorage.removeItem('ci_darkmode'); }`)
	page.Reload()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// data-theme="default" on html
	dataTheme, err := page.Locator("html").GetAttribute("data-theme")
	if err != nil || dataTheme != "default" {
		t.Errorf("Expected data-theme='default', got: %v", dataTheme)
	}

	// themed-card has border-top-width: 2px
	borderTop, err := page.Evaluate(`() => {
		var card = document.querySelector('.themed-card');
		if (!card) return 'no-card';
		return getComputedStyle(card).borderTopWidth;
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate borderTopWidth: %v", err)
	}
	if borderTop != "2px" {
		t.Errorf("Default themed-card should have border-top-width: 2px, got: %v", borderTop)
	}

	// h2 has negative letter-spacing (tracking-tight)
	letterSpacing, err := page.Evaluate(`() => {
		var h = document.querySelector('h2');
		if (!h) return null;
		return parseFloat(getComputedStyle(h).letterSpacing);
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate letterSpacing: %v", err)
	}
	if ls, ok := letterSpacing.(float64); ok {
		if ls >= 0 {
			t.Errorf("Default h2 should have negative letter-spacing (tracking-tight), got: %v", ls)
		}
	}
}

func TestBrowser_ThemeVisual_AcademicAttributes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	page := env.NewPage(t)
	defer page.Close()

	Navigate(t, page, env.BaseURL, "/login")
	page.Evaluate(`() => { localStorage.setItem('ci_theme', 'academic'); localStorage.removeItem('ci_darkmode'); }`)
	page.Reload()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// data-theme="academic" on html
	dataTheme, err := page.Locator("html").GetAttribute("data-theme")
	if err != nil || dataTheme != "academic" {
		t.Errorf("Expected data-theme='academic', got: %v", dataTheme)
	}

	// themed-card has border-left-width: 4px
	borderLeft, err := page.Evaluate(`() => {
		var card = document.querySelector('.themed-card');
		if (!card) return 'no-card';
		return getComputedStyle(card).borderLeftWidth;
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate borderLeftWidth: %v", err)
	}
	if borderLeft != "4px" {
		t.Errorf("Academic themed-card should have border-left-width: 4px, got: %v", borderLeft)
	}

	// h2 has tracking-tight (negative letter-spacing)
	letterSpacing, err := page.Evaluate(`() => {
		var h = document.querySelector('h2');
		if (!h) return 'no-heading';
		return getComputedStyle(h).letterSpacing;
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate letterSpacing: %v", err)
	}
	if ls, ok := letterSpacing.(string); ok {
		parsed, _ := strconv.ParseFloat(strings.TrimSuffix(ls, "px"), 64)
		if parsed >= 0 {
			t.Errorf("Academic h2 should have negative letter-spacing (tracking-tight), got: %v", letterSpacing)
		}
	}

	// body line-height approximately 1.8
	lineHeight, err := page.Evaluate(`() => {
		var lh = getComputedStyle(document.body).lineHeight;
		var fs = parseFloat(getComputedStyle(document.body).fontSize);
		if (lh === 'normal') return 1.2;
		return parseFloat(lh) / fs;
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate lineHeight: %v", err)
	}
	if lh, ok := lineHeight.(float64); ok {
		if lh < 1.7 || lh > 1.9 {
			t.Errorf("Academic body line-height should be ~1.8, got: %.2f", lh)
		}
	}
}

func TestBrowser_ThemeVisual_NeonfizzAttributes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// Fresh context for clean localStorage
	ctx := env.NewContext(t)
	defer ctx.Close()

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(browserMaxTimeoutMS)

	Navigate(t, page, env.BaseURL, "/login")
	page.Evaluate(`() => { localStorage.setItem('ci_theme', 'neonfizz'); localStorage.removeItem('ci_darkmode'); }`)
	page.Reload()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// data-theme="neonfizz" on html
	dataTheme, err := page.Locator("html").GetAttribute("data-theme")
	if err != nil || dataTheme != "neonfizz" {
		t.Errorf("Expected data-theme='neonfizz', got: %v", dataTheme)
	}

	// Auto-dark: html has 'dark' class
	htmlClass, _ := page.Locator("html").GetAttribute("class")
	if !strings.Contains(htmlClass, "dark") {
		t.Errorf("Neonfizz should auto-enable dark mode, html class: %v", htmlClass)
	}

	// h2 has text-transform: uppercase
	textTransform, err := page.Evaluate(`() => {
		var h = document.querySelector('h2');
		if (!h) return 'no-heading';
		return getComputedStyle(h).textTransform;
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate textTransform: %v", err)
	}
	if textTransform != "uppercase" {
		t.Errorf("Neonfizz h2 should have text-transform: uppercase, got: %v", textTransform)
	}

	// --ci-glow custom property is not "none"
	glowVal, err := page.Evaluate(`() => {
		return getComputedStyle(document.documentElement).getPropertyValue('--ci-glow').trim();
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate --ci-glow: %v", err)
	}
	if gv, ok := glowVal.(string); ok {
		if gv == "none" || gv == "" {
			t.Errorf("Neonfizz --ci-glow should not be 'none', got: %v", glowVal)
		}
	}
}
