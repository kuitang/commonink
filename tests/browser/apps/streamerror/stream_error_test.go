package browser

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kuitang/agent-notes/tests/browser/internal/appseed"
	"github.com/playwright-community/playwright-go"
)

const spriteTimeoutMS = 5000

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

func sliceContains(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

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

	appName := GenerateUniqueAppName("sticky-sse")
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
