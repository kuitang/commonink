//go:build sprite
// +build sprite

package browser

import (
	"net/http"
	"testing"

	"github.com/kuitang/agent-notes/tests/browser/internal/appseed"
	"github.com/playwright-community/playwright-go"

	"github.com/kuitang/agent-notes/tests/browser/internal/spriteutil"
)

func TestBrowser_AppDetail_StreamMock_FileEvent(t *testing.T) {
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

	emailAddr := GenerateUniqueEmail("mock-sse-file")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	appName := GenerateUniqueAppName("mock-sse-file")
	appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteutil.SpriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteutil.SpriteTimeoutMS)

	streamPattern := "**/api/apps/" + appName + "/stream?*"
	mockSSE := BuildTestSSEEventBody("file", map[string]any{
		"html": `<button data-path="mock.txt" class="file-btn block w-full text-left px-2 py-1.5 text-xs rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 truncate">mock.txt</button>`,
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

	spriteutil.NavigateSprite(t, page, env.BaseURL, "/apps/"+appName)

	mockFileBtn := page.Locator("button.file-btn[data-path='mock.txt']")
	if err := mockFileBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteutil.SpriteTimeoutMS),
	}); err != nil {
		fileListHTML, _ := page.Locator("#file-list").InnerHTML()
		t.Fatalf("Mock SSE file payload did not render: %v\nfile-list=%q", err, fileListHTML)
	}
}
