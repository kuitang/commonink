package browser

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kuitang/agent-notes/tests/browser/internal/appseed"
	"github.com/playwright-community/playwright-go"
)

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
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	streamPattern := "**/api/apps/" + appName + "/stream?*"
	mockSSE := strings.Join([]string{
		"event: file",
		`data: {"html":"<button data-path=\"mock.txt\" class=\"file-btn block w-full text-left px-2 py-1.5 text-xs rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 truncate\">mock.txt</button>"}`,
		"",
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
