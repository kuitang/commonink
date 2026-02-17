// Package browser contains screenshot tests for visual verification across themes.
package browser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// TestScreenshot_AllThemes captures screenshots of key pages in all three themes
// for visual review of theme distinctiveness.
func TestScreenshot_AllThemes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping screenshot test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	// Create screenshots directory
	screenshotDir := filepath.Join(os.TempDir(), "agent-notes-screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		t.Fatalf("Failed to create screenshot directory: %v", err)
	}
	t.Logf("=== Screenshots saved to: %s ===", screenshotDir)

	themes := []string{"default", "academic", "neonfizz"}
	pages := []struct {
		name string
		path string
	}{
		{"login", "/login"},
		{"register", "/register"},
		{"install", "/docs/install"},
		{"about", "/about"},
	}

	for _, theme := range themes {
		t.Run(theme, func(t *testing.T) {
			// Fresh context per theme for clean state
			ctx := env.NewContext(t)
			defer ctx.Close()

			page, err := ctx.NewPage()
			if err != nil {
				t.Fatalf("Failed to create page: %v", err)
			}
			defer page.Close()
			page.SetDefaultTimeout(browserMaxTimeoutMS)
			page.SetViewportSize(1280, 800)

			// Navigate to first page to set localStorage
			_, err = page.Goto(env.BaseURL + "/login")
			if err != nil {
				t.Fatalf("Failed to navigate: %v", err)
			}
			page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
				State: playwright.LoadStateDomcontentloaded,
			})

			// Set theme and remove darkmode override (let neonfizz auto-dark work)
			page.Evaluate(`(t) => { localStorage.setItem('ci_theme', t); localStorage.removeItem('ci_darkmode'); }`, theme)

			for _, p := range pages {
				_, err := page.Goto(env.BaseURL + p.path)
				if err != nil {
					t.Errorf("[%s] Failed to navigate to %s: %v", theme, p.path, err)
					continue
				}

				err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
					State: playwright.LoadStateNetworkidle,
				})
				if err != nil {
					t.Logf("[%s] Warning: network idle timeout for %s", theme, p.path)
				}

				// Ensure fade-in completes
				page.Evaluate(`() => { document.body.style.opacity = '1'; }`)

				screenshotPath := filepath.Join(screenshotDir, theme+"_"+p.name+".png")
				_, err = page.Screenshot(playwright.PageScreenshotOptions{
					Path:     playwright.String(screenshotPath),
					FullPage: playwright.Bool(true),
				})
				if err != nil {
					t.Errorf("[%s] Failed to capture %s: %v", theme, p.name, err)
				} else {
					t.Logf("[%s] %s -> %s", theme, p.name, screenshotPath)
				}
			}
		})
	}

	t.Logf("=== All screenshots in: %s ===", screenshotDir)
}
