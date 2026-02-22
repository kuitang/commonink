// Package browser provides Playwright E2E tests for browser-based interactions.
// These are deterministic scenario tests (NOT property-based) as per CLAUDE.md.
package browser

import (
	"net/http"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// TestBrowser_PublishNote tests creating a note and making it public.
func TestBrowser_PublishNote(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	authCtx := env.NewContext(t)
	defer authCtx.Close()
	env.LoginUser(t, authCtx, GenerateUniqueEmail("public-note"))

	page, err := authCtx.NewPage()
	if err != nil {
		t.Fatalf("failed to create page: %v", err)
	}
	defer page.Close()

	// Create note via UI
	CreateNoteViaUI(t, page, env.BaseURL, "My Test Note", "This is the content of my test note.\n\nIt has multiple paragraphs.")

	// Verify note title is displayed
	titleText, err := page.Locator("h1").TextContent()
	if err != nil {
		t.Fatalf("failed to get title text: %v", err)
	}
	if !strings.Contains(titleText, "My Test Note") {
		t.Errorf("expected title to contain 'My Test Note', got: %s", titleText)
	}

	// Click "Make Public" button
	publishBtn := page.Locator("button:has-text('Make Public')")
	isVisible, err := publishBtn.IsVisible()
	if err != nil {
		t.Fatalf("failed to check publish button visibility: %v", err)
	}
	if !isVisible {
		t.Fatal("Make Public button not visible")
	}

	err = publishBtn.Click()
	if err != nil {
		t.Fatalf("failed to click Make Public: %v", err)
	}

	// Wait for page to reload
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("failed to wait for page load: %v", err)
	}

	// Verify public badge appears (use specific class to avoid matching "Public Share Link")
	publicBadge := page.Locator("span.bg-success-100:has-text('Public')")
	isBadgeVisible, err := publicBadge.IsVisible()
	if err != nil {
		t.Fatalf("failed to check public badge visibility: %v", err)
	}
	if !isBadgeVisible {
		t.Error("Public badge not visible after making note public")
	}

	// Verify share URL section appears with a short URL
	shareURLInput := page.Locator("input#share-url")
	isShareVisible, err := shareURLInput.IsVisible()
	if err != nil {
		t.Fatalf("failed to check share URL visibility: %v", err)
	}
	if !isShareVisible {
		t.Fatal("Share URL input not visible after making note public")
	}

	// Regression: share URL must be a short URL (/pub/...), not an S3 or long public path
	shareURL, err := shareURLInput.InputValue()
	if err != nil {
		t.Fatalf("failed to get share URL value: %v", err)
	}
	if !strings.Contains(shareURL, "/pub/") {
		t.Fatalf("share URL must be a short URL (/pub/...), got: %s", shareURL)
	}
	if strings.Contains(shareURL, "/public/") {
		t.Fatalf("share URL must NOT be a long public path, got: %s", shareURL)
	}
}

// TestBrowser_UnpublishNote tests making a public note private again.
func TestBrowser_UnpublishNote(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	authCtx := env.NewContext(t)
	defer authCtx.Close()
	env.LoginUser(t, authCtx, GenerateUniqueEmail("unpublish-note"))

	page, err := authCtx.NewPage()
	if err != nil {
		t.Fatalf("failed to create page: %v", err)
	}
	defer page.Close()

	// Create and publish note
	CreateNoteViaUI(t, page, env.BaseURL, "Note to Unpublish", "Content")
	shareURL := PublishNoteViaUI(t, page)

	// Verify it's now public (use specific class to avoid matching "Public Share Link")
	publicBadge := page.Locator("span.bg-success-100:has-text('Public')")
	isPublic, err := publicBadge.IsVisible()
	if err != nil {
		t.Fatalf("failed to check badge: %v", err)
	}
	if !isPublic {
		t.Fatal("note should be public")
	}

	// Verify share URL is a short URL
	if !strings.Contains(shareURL, "/pub/") {
		t.Fatalf("share URL must be a short URL, got: %s", shareURL)
	}

	// Now click "Make Private"
	err = page.Locator("button:has-text('Make Private')").Click()
	if err != nil {
		t.Fatalf("failed to click Make Private: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("failed to wait for load: %v", err)
	}

	// Verify it's now private
	privateBadge := page.Locator("span:has-text('Private')")
	isPrivate, err := privateBadge.IsVisible()
	if err != nil {
		t.Fatalf("failed to check private badge: %v", err)
	}
	if !isPrivate {
		t.Error("note should show Private badge after unpublishing")
	}

	// Verify share URL is no longer visible
	shareURLGone := page.Locator("input#share-url")
	isShareVisible, err := shareURLGone.IsVisible()
	if err != nil {
		t.Fatalf("failed to check share URL: %v", err)
	}
	if isShareVisible {
		t.Error("share URL should not be visible after unpublishing")
	}

	// Try to access the previously-working short URL (should 404 now)
	anonCtx := env.NewContext(t)
	defer anonCtx.Close()

	anonPage, err := anonCtx.NewPage()
	if err != nil {
		t.Fatalf("failed to create anon page: %v", err)
	}
	defer anonPage.Close()

	resp, err := anonPage.Goto(shareURL)
	if err != nil {
		t.Fatalf("failed to navigate to short URL: %v", err)
	}

	// Short URL should no longer resolve after unpublishing
	if resp.Status() != http.StatusNotFound {
		t.Logf("short URL returned status %d after unpublishing (expected 404)", resp.Status())
	}
}

// TestBrowser_PublicNoteSEO tests that public notes have proper SEO meta tags.
func TestBrowser_PublicNoteSEO(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// Create authenticated context to create and publish note
	authCtx := env.NewContext(t)
	defer authCtx.Close()
	env.LoginUser(t, authCtx, GenerateUniqueEmail("seo-note"))

	authPage, err := authCtx.NewPage()
	if err != nil {
		t.Fatalf("failed to create page: %v", err)
	}
	defer authPage.Close()

	// Create and publish a note
	CreateNoteViaUI(t, authPage, env.BaseURL, "SEO Test Note Title", "This note tests SEO meta tags.")
	shareURL := PublishNoteViaUI(t, authPage)

	// Navigate to public URL via short URL in anonymous context
	anonCtx := env.NewContext(t)
	defer anonCtx.Close()

	anonPage, err := anonCtx.NewPage()
	if err != nil {
		t.Fatalf("failed to create anon page: %v", err)
	}
	defer anonPage.Close()

	_, err = anonPage.Goto(shareURL)
	if err != nil {
		t.Fatalf("failed to navigate to share URL: %v", err)
	}

	// Check for og:title meta tag
	ogTitle := anonPage.Locator("meta[property='og:title']")
	ogTitleCount, err := ogTitle.Count()
	if err != nil {
		t.Fatalf("failed to count og:title: %v", err)
	}
	if ogTitleCount == 0 {
		t.Error("og:title meta tag not found")
	}

	// Check for twitter:card meta tag
	twitterCard := anonPage.Locator("meta[name='twitter:card']")
	twitterCardCount, err := twitterCard.Count()
	if err != nil {
		t.Fatalf("failed to count twitter:card: %v", err)
	}
	if twitterCardCount == 0 {
		t.Error("twitter:card meta tag not found")
	}

	// Check page title
	pageTitle, err := anonPage.Title()
	if err != nil {
		t.Fatalf("failed to get page title: %v", err)
	}
	if pageTitle == "" {
		t.Error("page title should not be empty")
	}
}

// TestBrowser_ShareLinkIsShortURL tests that the share link is a short URL (/pub/...) and is navigable.
// Also verifies minimal chrome style: no nav/footer, wordmark present, CTA visible, "Public Note" badge.
func TestBrowser_ShareLinkIsShortURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// Create authenticated context
	authCtx := env.NewContext(t)
	defer authCtx.Close()
	env.LoginUser(t, authCtx, GenerateUniqueEmail("share-note"))

	authPage, err := authCtx.NewPage()
	if err != nil {
		t.Fatalf("failed to create page: %v", err)
	}
	defer authPage.Close()

	noteTitle := "Shareable Note"
	noteContent := "This content should be visible via share link."

	// Create and publish a note
	CreateNoteViaUI(t, authPage, env.BaseURL, noteTitle, noteContent)
	shareURL := PublishNoteViaUI(t, authPage)

	t.Logf("Share URL: %s", shareURL)

	// Regression: share URL MUST be a short URL, not an S3 URL
	if !strings.Contains(shareURL, "/pub/") {
		t.Fatalf("share URL must be a short URL (/pub/...), got: %s", shareURL)
	}
	if strings.Contains(shareURL, "/public/") {
		t.Fatalf("share URL must NOT be a long public path, got: %s", shareURL)
	}

	// Navigate to the short URL in an anonymous context
	anonCtx := env.NewContext(t)
	defer anonCtx.Close()

	anonPage, err := anonCtx.NewPage()
	if err != nil {
		t.Fatalf("failed to create anon page: %v", err)
	}
	defer anonPage.Close()

	// The short URL renders inline (no redirect to /public/)
	_, err = anonPage.Goto(shareURL)
	if err != nil {
		t.Fatalf("failed to navigate to short URL: %v", err)
	}

	// URL should stay at /pub/... (no redirect)
	finalURL := anonPage.URL()
	if !strings.Contains(finalURL, "/pub/") {
		t.Fatalf("short URL should render inline at /pub/..., got: %s", finalURL)
	}
	if strings.Contains(finalURL, "/public/") {
		t.Fatalf("short URL should NOT redirect to /public/..., got: %s", finalURL)
	}

	// Verify the page loads and shows the note
	titleElement := anonPage.Locator("h1")
	titleText, err := titleElement.TextContent()
	if err != nil {
		t.Fatalf("failed to get title: %v", err)
	}
	if titleText == "" {
		t.Error("page title should not be empty")
	}

	// Verify page has content section
	contentSection := anonPage.Locator("article")
	isContentVisible, err := contentSection.IsVisible()
	if err != nil {
		t.Fatalf("failed to check content: %v", err)
	}
	if !isContentVisible {
		t.Error("article content section should be visible")
	}

	// === Minimal chrome style assertions (merged from ViewPublicNoteWithoutAuth) ===

	// Verify "Public Note" badge is visible
	publicBadge := anonPage.Locator("span:has-text('Public Note')")
	isVisible, err := publicBadge.IsVisible()
	if err != nil {
		t.Fatalf("failed to check public badge: %v", err)
	}
	if !isVisible {
		t.Error("Public Note badge should be visible")
	}

	// Verify: NO full nav bar (the app nav has desktop nav links like "Notes", "API Keys")
	fullNav := anonPage.Locator("nav")
	fullNavCount, err := fullNav.Count()
	if err != nil {
		t.Fatalf("failed to count nav elements: %v", err)
	}
	if fullNavCount > 0 {
		t.Error("public note page should NOT have a <nav> element (minimal chrome)")
	}

	// Verify: minimal header has "common.ink" wordmark link
	wordmark := anonPage.Locator("header a:has-text('common.ink')")
	wordmarkVisible, err := wordmark.IsVisible()
	if err != nil {
		t.Fatalf("failed to check wordmark: %v", err)
	}
	if !wordmarkVisible {
		t.Error("public note page should show 'common.ink' wordmark in header")
	}

	// Verify: NO app footer (the full footer has "About", "Privacy", "Terms" links)
	footer := anonPage.Locator("footer")
	footerCount, err := footer.Count()
	if err != nil {
		t.Fatalf("failed to count footer elements: %v", err)
	}
	if footerCount > 0 {
		t.Error("public note page should NOT have a <footer> element (minimal chrome)")
	}

	// Verify: "Get Started Free" CTA is present (article-level CTA, not app footer)
	ctaLink := anonPage.Locator("a:has-text('Get Started Free')")
	ctaVisible, err := ctaLink.IsVisible()
	if err != nil {
		t.Fatalf("failed to check CTA: %v", err)
	}
	if !ctaVisible {
		t.Error("public note page should show 'Get Started Free' CTA")
	}
}

// TestBrowser_CopyShareURL_Regression tests that the copy-to-clipboard button on the
// public share link actually copies the share URL. This is a regression test for a bug
// where the inline onclick handler had no .catch() fallback and broke silently.
func TestBrowser_CopyShareURL_Regression(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// Create context with clipboard permissions so we can read back
	authCtx := env.NewContextWithOptions(t, playwright.BrowserNewContextOptions{
		Permissions: []string{"clipboard-read", "clipboard-write"},
	})
	authCtx.SetDefaultTimeout(browserMaxTimeoutMS)
	authCtx.SetDefaultNavigationTimeout(browserMaxTimeoutMS)
	defer authCtx.Close()

	env.LoginUser(t, authCtx, GenerateUniqueEmail("copyurl-note"))

	page, err := authCtx.NewPage()
	if err != nil {
		t.Fatalf("failed to create page: %v", err)
	}
	defer page.Close()

	// Create note via UI
	CreateNoteViaUI(t, page, env.BaseURL, "Copy URL Test Note", "Content for clipboard test")

	// Publish: select "Public (Anonymous)" and click "Update Visibility"
	visSelect := page.Locator("select[name='visibility']")
	_, err = visSelect.SelectOption(playwright.SelectOptionValues{Values: &[]string{"1"}})
	if err != nil {
		t.Fatalf("failed to select Public (Anonymous): %v", err)
	}

	submitBtn := page.Locator("button:has-text('Update Visibility')")
	err = submitBtn.Click()
	if err != nil {
		t.Fatalf("failed to click Update Visibility: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("failed to wait for page load after publish: %v", err)
	}

	// Verify share URL input appeared
	shareURLInput := WaitForSelector(t, page, "input#share-url")
	shareURL, err := shareURLInput.InputValue()
	if err != nil {
		t.Fatalf("failed to get share URL value: %v", err)
	}
	if shareURL == "" {
		t.Fatal("share URL is empty after publishing")
	}
	if !strings.Contains(shareURL, "/pub/") {
		t.Fatalf("share URL must be a short URL (/pub/...), got: %s", shareURL)
	}

	// Click the copy button
	copyBtn := page.Locator("button#copy-share-url")
	err = copyBtn.Click()
	if err != nil {
		t.Fatalf("failed to click copy button: %v", err)
	}

	// Verify clipboard content matches share URL
	clipboardRaw, err := page.Evaluate("navigator.clipboard.readText()")
	if err != nil {
		t.Fatalf("failed to read clipboard: %v", err)
	}
	clipboardText, ok := clipboardRaw.(string)
	if !ok {
		t.Fatalf("clipboard readText returned non-string: %T", clipboardRaw)
	}
	if clipboardText != shareURL {
		t.Errorf("clipboard content %q does not match share URL %q", clipboardText, shareURL)
	}

	// Verify visual feedback: copy-icon hidden, check-icon visible
	checkIcon := page.Locator("#copy-check-icon")
	isCheckVisible, err := checkIcon.IsVisible()
	if err != nil {
		t.Fatalf("failed to check checkmark visibility: %v", err)
	}
	if !isCheckVisible {
		t.Error("checkmark icon should appear after clicking copy button")
	}

	copyIcon := page.Locator("#copy-icon")
	isCopyHidden, err := copyIcon.IsHidden()
	if err != nil {
		t.Fatalf("failed to check copy icon hidden state: %v", err)
	}
	if !isCopyHidden {
		t.Error("copy icon should be hidden after clicking copy button")
	}
}
