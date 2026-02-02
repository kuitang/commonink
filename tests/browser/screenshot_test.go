// Package browser contains screenshot tests for visual verification.
package browser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// TestScreenshot_CapturePages captures screenshots of key pages for visual verification.
func TestScreenshot_CapturePages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping screenshot test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	// Create screenshots directory
	screenshotDir := filepath.Join(os.TempDir(), "agent-notes-screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		t.Fatalf("Failed to create screenshot directory: %v", err)
	}
	t.Logf("Screenshots will be saved to: %s", screenshotDir)

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Set viewport for consistent screenshots
	page.SetViewportSize(1280, 800)

	pages := []struct {
		name string
		path string
	}{
		{"login", "/login"},
		{"register", "/register"},
		{"password_reset", "/password-reset"},
	}

	for _, p := range pages {
		_, err := page.Goto(env.baseURL + p.path)
		if err != nil {
			t.Errorf("Failed to navigate to %s: %v", p.path, err)
			continue
		}

		// Wait for page to fully load
		err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
			State: playwright.LoadStateNetworkidle,
		})
		if err != nil {
			t.Logf("Warning: network idle timeout for %s", p.path)
		}

		// Capture screenshot
		screenshotPath := filepath.Join(screenshotDir, p.name+".png")
		_, err = page.Screenshot(playwright.PageScreenshotOptions{
			Path:     playwright.String(screenshotPath),
			FullPage: playwright.Bool(true),
		})
		if err != nil {
			t.Errorf("Failed to capture screenshot of %s: %v", p.path, err)
		} else {
			t.Logf("Captured screenshot: %s", screenshotPath)
		}
	}
}
