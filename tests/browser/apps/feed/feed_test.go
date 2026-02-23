//go:build sprite
// +build sprite

package browser

import (
	"testing"

	"github.com/kuitang/agent-notes/tests/browser/internal/appseed"
	"github.com/playwright-community/playwright-go"

	"github.com/kuitang/agent-notes/tests/browser/internal/spriteutil"
)

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

	appName := GenerateUniqueAppName("feed")
	appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteutil.SpriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteutil.SpriteTimeoutMS)

	CreateNoteViaUI(t, page, env.BaseURL, "Feed Test Note", "Content for feed test")
	spriteutil.NavigateSprite(t, page, env.BaseURL, "/notes")

	appCard := page.Locator("article.themed-card a[href*='/apps/']").First()
	err = appCard.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteutil.SpriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("App card not visible in unified feed: %v", err)
	}

	noteCard := page.Locator("article.themed-card a[href*='/notes/']").First()
	err = noteCard.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteutil.SpriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Note card not visible in unified feed: %v", err)
	}
}

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
	page.SetDefaultTimeout(spriteutil.SpriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteutil.SpriteTimeoutMS)

	Navigate(t, page, env.BaseURL, "/notes")

	emptyHeading := page.Locator("h3:has-text('No notes yet')")
	err = emptyHeading.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteutil.SpriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Empty state heading not visible: %v", err)
	}

	createLink := page.Locator("a:has-text('Create your first note')")
	err = createLink.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteutil.SpriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Create first note link not visible in empty state: %v", err)
	}
}
