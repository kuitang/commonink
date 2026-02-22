//go:build sprite
// +build sprite

package browser

import (
	"net/http"
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

func TestBrowser_AppDetail_StreamMock_LogEvent(t *testing.T) {
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

	emailAddr := GenerateUniqueEmail("mock-sse-log")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	appName := GenerateUniqueAppName("mock-sse-log")
	appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	streamPattern := "**/api/apps/" + appName + "/stream?*"
	mockSSE := BuildTestSSEEventBody("log", map[string]any{
		"output":    "mock log line",
		"stderr":    "",
		"exit_code": 0,
	})

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

	_, err = page.WaitForFunction(`() => {
		const el = document.getElementById('log-output');
		return el && (el.textContent || '').includes('mock log line');
	}`, nil, playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		logText, _ := page.Locator("#log-output").TextContent()
		t.Fatalf("Mock SSE log payload did not render: %v\nlogs=%q", err, logText)
	}
}
