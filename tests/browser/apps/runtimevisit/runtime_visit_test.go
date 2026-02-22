//go:build sprite
// +build sprite

package browser

import (
	"strings"
	"testing"

	"github.com/kuitang/agent-notes/tests/browser/internal/appseed"
	"github.com/playwright-community/playwright-go"
)

const spriteTimeoutMS = 5000

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

	appName := GenerateUniqueAppName("post")
	publicURL := appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	_, err = page.Goto(publicURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to public URL %s: %v", publicURL, err)
	}

	msgInput := page.Locator("input#msg")
	err = msgInput.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Message input not visible on public app page: %v", err)
	}

	testMsg := "hello from playwright"
	if err := msgInput.Fill(testMsg); err != nil {
		t.Fatalf("Failed to fill message: %v", err)
	}

	sendBtn := page.Locator("button#send")
	if err := sendBtn.Click(); err != nil {
		t.Fatalf("Failed to click send: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load after POST: %v", err)
	}

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
