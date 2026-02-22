package browser

import (
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

	appName := GenerateUniqueAppName("detail")
	appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	navigateSprite(t, page, env.BaseURL, "/apps/"+appName)

	heading := page.Locator("h1")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get heading text: %v", err)
	}
	if !strings.Contains(headingText, appName) {
		t.Errorf("Expected heading to contain %q, got %q", appName, headingText)
	}

	statusBadge := page.Locator("#status-badge")
	err = statusBadge.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Status badge not visible: %v", err)
	}

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

	if err := serverPyBtn.Click(); err != nil {
		t.Fatalf("Failed to click server.py: %v", err)
	}

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
