// Package browser contains Playwright E2E tests for app management flows.
// These tests require SPRITE_TOKEN to be set (except TestBrowser_UnifiedFeed_EmptyState).
package browser

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kuitang/agent-notes/tests/browser/internal/appseed"
	"github.com/playwright-community/playwright-go"
)

// spriteTimeoutMS is a longer timeout for Playwright waits that depend on
// sprite API calls (file listing, log fetching, bash commands) which go over the network.
// Sprite bash commands can take up to 120s.
const spriteTimeoutMS = 120000

func navigateSprite(t *testing.T, page playwright.Page, baseURL, path string) {
	t.Helper()
	_, err := page.Goto(baseURL+path, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to %s: %v", path, err)
	}
}

// =============================================================================
// Unified Feed Tests
// =============================================================================

// TestBrowser_UnifiedFeed_ShowsApp verifies that the unified feed shows both
// app cards and note cards after seeding an app and a note.
func TestBrowser_UnifiedFeed_ShowsApp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	if env.SpriteToken == "" {
		t.Skip("SPRITE_TOKEN required")
	}
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()

	emailAddr := GenerateUniqueEmail("feed-app")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	// Seed an app
	appName := "feed-" + GenerateUniqueEmail("x")[:8]
	appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	// Navigate to /notes (unified feed)
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	// Create a note through the UI to keep this suite user-behavior focused.
	CreateNoteViaUI(t, page, env.BaseURL, "Feed Test Note", "Content for feed test")
	navigateSprite(t, page, env.BaseURL, "/notes")

	// Assert: app-card is visible
	appCard := page.Locator("article.themed-card a[href*='/apps/']").First()
	err = appCard.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("App card not visible in unified feed: %v", err)
	}

	// Assert: note-card is visible
	noteCard := page.Locator("article.themed-card a[href*='/notes/']").First()
	err = noteCard.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Note card not visible in unified feed: %v", err)
	}
}

// TestBrowser_UnifiedFeed_EmptyState verifies the empty state when a user
// has no notes and no apps.
func TestBrowser_UnifiedFeed_EmptyState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()

	emailAddr := GenerateUniqueEmail("empty-feed")
	env.LoginUser(t, ctx, emailAddr)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	Navigate(t, page, env.BaseURL, "/notes")

	// Assert: empty state message is visible ("No notes yet")
	emptyHeading := page.Locator("h3:has-text('No notes yet')")
	err = emptyHeading.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Empty state heading not visible: %v", err)
	}

	// Assert: "Create your first note" link/button is visible
	createLink := page.Locator("a:has-text('Create your first note')")
	err = createLink.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Create first note link not visible in empty state: %v", err)
	}
}

// =============================================================================
// App Detail Tests
// =============================================================================

// TestBrowser_AppDetail_FileSidebar verifies the app detail page shows
// a header, status badge, file sidebar with "server.py", and clicking
// the file loads its content in the editor.
func TestBrowser_AppDetail_FileSidebar(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	if env.SpriteToken == "" {
		t.Skip("SPRITE_TOKEN required")
	}
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()

	emailAddr := GenerateUniqueEmail("detail-files")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	appName := "detail-" + GenerateUniqueEmail("x")[:8]
	appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	navigateSprite(t, page, env.BaseURL, "/apps/"+appName)

	// Assert: header with app name
	heading := page.Locator("h1")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get heading text: %v", err)
	}
	if !strings.Contains(headingText, appName) {
		t.Errorf("Expected heading to contain %q, got %q", appName, headingText)
	}

	// Assert: status badge
	statusBadge := page.Locator("#status-badge")
	err = statusBadge.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Status badge not visible: %v", err)
	}

	// Assert: file sidebar lists "server.py"
	// The file list is populated via fetch(), so wait for it
	serverPyBtn := page.Locator("button.file-btn[data-path='server.py']")
	err = serverPyBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		fileListHTML, _ := page.Locator("#file-list").InnerHTML()
		logText, _ := page.Locator("#log-output").TextContent()
		t.Fatalf("server.py not found in file sidebar: %v\nfile-list=%q\nlogs=%q", err, fileListHTML, logText)
	}

	// Click server.py to load content
	if err := serverPyBtn.Click(); err != nil {
		t.Fatalf("Failed to click server.py: %v", err)
	}

	// Wait for editor filename to update
	editorFilename := page.Locator("#editor-filename")
	_, err = page.WaitForFunction(`() => {
		const el = document.getElementById('editor-filename');
		return el && el.textContent.includes('server.py');
	}`, nil, playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		fnText, _ := editorFilename.TextContent()
		t.Fatalf("Editor filename did not update to server.py (got %q): %v", fnText, err)
	}

	// Assert: editor content loaded (user-visible behavior), not implementation-specific code text
	editorContent := page.Locator("#editor-content")
	_, err = page.WaitForFunction(`() => {
		const el = document.getElementById('editor-content');
		const value = (el && el.value) ? el.value : '';
		return value.trim().length > 0 && value.indexOf('Error:') !== 0;
	}`, nil, playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		editorValue, _ := editorContent.InputValue()
		t.Fatalf("Editor content did not load (got: %s): %v", editorValue, err)
	}

	editorValue, err := editorContent.InputValue()
	if err != nil {
		t.Fatalf("Failed to get editor content: %v", err)
	}
	if strings.TrimSpace(editorValue) == "" || strings.HasPrefix(editorValue, "Error:") {
		t.Errorf("Editor content should be non-empty file content, got: %s", editorValue[:min(200, len(editorValue))])
	}
}

// TestBrowser_AppDetail_Stream_UsesMockSSEData verifies that app detail UI can
// consume deterministic mocked SSE events for file/log updates.
func TestBrowser_AppDetail_Stream_UsesMockSSEData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	if env.SpriteToken == "" {
		t.Skip("SPRITE_TOKEN required")
	}
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()

	emailAddr := GenerateUniqueEmail("mock-sse")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	appName := "mock-sse-" + GenerateUniqueEmail("x")[:8]
	appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	streamPattern := "**/api/apps/" + appName + "/stream?*"
	mockSSE := strings.Join([]string{
		"event: file",
		`data: {"html":"<button data-path=\"mock.txt\" class=\"file-btn block w-full text-left px-2 py-1.5 text-xs rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 truncate\">mock.txt</button>"}`,
		"",
		"event: log",
		`data: {"output":"mock log line","stderr":"","exit_code":0}`,
		"",
	}, "\n")

	if err := page.Route(streamPattern, func(route playwright.Route) {
		_ = route.Fulfill(playwright.RouteFulfillOptions{
			Status:      playwright.Int(http.StatusOK),
			ContentType: playwright.String("text/event-stream"),
			Headers: map[string]string{
				"Cache-Control": "no-cache",
			},
			Body: mockSSE,
		})
	}); err != nil {
		t.Fatalf("Failed to install stream route mock: %v", err)
	}

	navigateSprite(t, page, env.BaseURL, "/apps/"+appName)

	mockFileBtn := page.Locator("button.file-btn[data-path='mock.txt']")
	if err := mockFileBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	}); err != nil {
		fileListHTML, _ := page.Locator("#file-list").InnerHTML()
		t.Fatalf("Mock SSE file payload did not render: %v\nfile-list=%q", err, fileListHTML)
	}
}

// TestBrowser_AppDetail_StreamError_StickyFlash verifies SSE startup errors do
// not break the page and remain visible until a connection succeeds.
func TestBrowser_AppDetail_StreamError_StickyFlash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	if env.SpriteToken == "" {
		t.Skip("SPRITE_TOKEN required")
	}
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()

	emailAddr := GenerateUniqueEmail("sticky-sse")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	appName := "sticky-sse-" + GenerateUniqueEmail("x")[:8]
	appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	consoleErrors := make([]string, 0, 8)
	page.OnConsole(func(msg playwright.ConsoleMessage) {
		if msg.Type() == "error" {
			consoleErrors = append(consoleErrors, msg.Text())
		}
	})

	streamPattern := "**/api/apps/" + appName + "/stream?*"
	if err := page.Route(streamPattern, func(route playwright.Route) {
		_ = route.Fulfill(playwright.RouteFulfillOptions{
			Status:      playwright.Int(http.StatusInternalServerError),
			ContentType: playwright.String("application/json"),
			Headers: map[string]string{
				"Cache-Control": "no-store",
			},
			Body: `{"error":"Streaming not supported"}`,
		})
	}); err != nil {
		t.Fatalf("Failed to install stream error route mock: %v", err)
	}

	navigateSprite(t, page, env.BaseURL, "/apps/"+appName)

	serverPyBtn := page.Locator("button.file-btn[data-path='server.py']")
	if err := serverPyBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	}); err != nil {
		fileListHTML, _ := page.Locator("#file-list").InnerHTML()
		t.Fatalf("Initial file list missing after SSE failure: %v\nfile-list=%q", err, fileListHTML)
	}

	flash := page.Locator("#stream-inline-flash")
	if err := flash.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	}); err != nil {
		t.Fatalf("SSE error flash did not appear: %v", err)
	}

	if _, err := page.WaitForFunction(`() => {
		const flash = document.getElementById('stream-inline-flash');
		if (!flash) return false;
		const text = flash.textContent || '';
		const visible = !flash.classList.contains('hidden');
		if (!visible) return false;
		if (!text.includes('Streaming not supported')) return false;
		if (!window.__streamErrorSeenAt) window.__streamErrorSeenAt = Date.now();
		return (Date.now() - window.__streamErrorSeenAt) > 3500
			&& !flash.classList.contains('hidden')
			&& (flash.textContent || '').includes('Streaming not supported');
	}`, nil, playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(spriteTimeoutMS),
	}); err != nil {
		flashText, _ := flash.TextContent()
		t.Fatalf("SSE error flash was not sticky across retry: %v\nflash=%q", err, flashText)
	}

	if !sliceContains(consoleErrors, "App stream startup failed:") || !sliceContains(consoleErrors, "Streaming not supported") {
		t.Fatalf("Expected console error with exact stream failure; got: %v", consoleErrors)
	}
}

// TestBrowser_AppDetail_VisitAndPost verifies that the app's public URL serves
// a form, and posting to it echoes the message.
func TestBrowser_AppDetail_VisitAndPost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	if env.SpriteToken == "" {
		t.Skip("SPRITE_TOKEN required")
	}
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()

	emailAddr := GenerateUniqueEmail("post-app")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	appName := "post-" + GenerateUniqueEmail("x")[:8]
	publicURL := appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	// Navigate to the public URL
	_, err = page.Goto(publicURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to public URL %s: %v", publicURL, err)
	}

	// Assert: form is visible
	msgInput := page.Locator("input#msg")
	err = msgInput.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Message input not visible on public app page: %v", err)
	}

	// Fill and submit
	testMsg := "hello from playwright"
	if err := msgInput.Fill(testMsg); err != nil {
		t.Fatalf("Failed to fill message: %v", err)
	}

	sendBtn := page.Locator("button#send")
	if err := sendBtn.Click(); err != nil {
		t.Fatalf("Failed to click send: %v", err)
	}

	// Wait for the echo response
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load after POST: %v", err)
	}

	// Assert: echo paragraph shows the message
	echoP := page.Locator("p#echo")
	err = echoP.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Echo paragraph not visible: %v", err)
	}

	echoText, err := echoP.TextContent()
	if err != nil {
		t.Fatalf("Failed to get echo text: %v", err)
	}
	if !strings.Contains(echoText, testMsg) {
		t.Errorf("Echo should contain %q, got: %q", testMsg, echoText)
	}
}

// TestBrowser_AppDetail_LogsShowPost verifies that after posting to an app,
// the logs panel on the detail page shows the POST request.
func TestBrowser_AppDetail_LogsShowPost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	if env.SpriteToken == "" {
		t.Skip("SPRITE_TOKEN required")
	}
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()

	emailAddr := GenerateUniqueEmail("logs-app")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	appName := "logs-" + GenerateUniqueEmail("x")[:8]
	publicURL := appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	// First, make a POST to the app so there are logs to check
	postPage, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	postPage.SetDefaultTimeout(spriteTimeoutMS)
	postPage.SetDefaultNavigationTimeout(spriteTimeoutMS)

	_, err = postPage.Goto(publicURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to public URL: %v", err)
	}

	msgInput := postPage.Locator("input#msg")
	err = msgInput.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Message input not visible: %v", err)
	}
	msgInput.Fill("logtest")
	postPage.Locator("button#send").Click()
	postPage.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	postPage.Close()

	// Now navigate to the app detail page
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	navigateSprite(t, page, env.BaseURL, "/apps/"+appName)

	// The log panel fetches logs on page load. Wait for it to populate.
	logOutput := page.Locator("#log-output")
	_, err = page.WaitForFunction(`() => {
		const el = document.getElementById('log-output');
		return el && el.textContent.includes('POST');
	}`, nil, playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		logText, _ := logOutput.TextContent()
		t.Fatalf("Log output does not contain 'POST' (got: %s): %v", logText, err)
	}

	logText, _ := logOutput.TextContent()
	if !strings.Contains(logText, "POST") || !strings.Contains(logText, "msg=") {
		t.Errorf("Logs should show POST with msg=, got: %s", logText)
	}
}

// TestBrowser_AppDetail_ActionButtons verifies that Start/Stop/Restart buttons
// are visible and invoke sprite-env service actions successfully.
func TestBrowser_AppDetail_ActionButtons(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	if env.SpriteToken == "" {
		t.Skip("SPRITE_TOKEN required")
	}
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()

	emailAddr := GenerateUniqueEmail("action-app")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	appName := "action-" + GenerateUniqueEmail("x")[:8]
	appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	navigateSprite(t, page, env.BaseURL, "/apps/"+appName)

	// Assert: Start button visible
	startBtn := page.Locator("#btn-start")
	err = startBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Start button not visible: %v", err)
	}

	// Assert: Restart button visible
	restartBtn := page.Locator("#btn-restart")
	err = restartBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Restart button not visible: %v", err)
	}

	// Assert: Stop button visible
	stopBtn := page.Locator("#btn-stop")
	err = stopBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Stop button not visible: %v", err)
	}

	actionOutput := page.Locator("#action-result pre")
	waitForAction := func(action string) string {
		_, err = page.WaitForFunction(`(act) => {
			const el = document.querySelector('#action-result pre');
			if (!el) return false;
			const text = (el.textContent || '').toLowerCase();
			if (!text) return false;
			return text.indexOf(('running ' + act + '...').toLowerCase()) === -1;
		}`, action, playwright.PageWaitForFunctionOptions{
			Timeout: playwright.Float(spriteTimeoutMS),
		})
		if err != nil {
			text, _ := actionOutput.TextContent()
			t.Fatalf("Action %q did not complete (output: %q): %v", action, text, err)
		}
		text, _ := actionOutput.TextContent()
		lower := strings.ToLower(text)
		if strings.Contains(lower, "error") || strings.Contains(lower, "service not found") || strings.Contains(lower, "requested url returned error") {
			t.Fatalf("Action %q failed: %q", action, text)
		}
		return text
	}

	if err := stopBtn.Click(); err != nil {
		t.Fatalf("Failed to click stop: %v", err)
	}
	waitForAction("stop")

	if err := startBtn.Click(); err != nil {
		t.Fatalf("Failed to click start: %v", err)
	}
	waitForAction("start")

	if err := restartBtn.Click(); err != nil {
		t.Fatalf("Failed to click restart: %v", err)
	}
	waitForAction("restart")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sliceContains(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
