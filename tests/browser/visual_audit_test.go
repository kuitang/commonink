// Package browser contains visual audit screenshot tests for before/after comparison
// of button style consistency fixes across all templates.
package browser

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/playwright-community/playwright-go"
)

const screenshotBaseDir = "/home/kuitang/git/agent-notes/screenshots"

// screenshotSpec defines a page to screenshot, along with any setup required.
type screenshotSpec struct {
	name      string // filename-safe name for the screenshot
	path      string // URL path relative to base URL
	needsAuth bool   // whether the page requires login
	needsNote bool   // whether the page needs a note created first (implies needsAuth)
	setup     string // extra setup hint: "edit", "view", "consent", "api-keys-new", etc.
}

// allScreenshotSpecs returns all pages to capture. The note ID placeholder "{noteID}"
// is replaced at runtime.
func allScreenshotSpecs() []screenshotSpec {
	return []screenshotSpec{
		// Public/unauthenticated pages
		{name: "landing", path: "/"},
		{name: "login", path: "/login"},
		{name: "login-password", path: "/login?mode=password&email=demo@example.com"},
		{name: "register", path: "/register"},
		{name: "password-reset", path: "/auth/password-reset"},
		{name: "pricing", path: "/pricing"},

		// Authenticated pages (no note needed)
		{name: "notes-list-empty", path: "/notes", needsAuth: true},
		{name: "note-new", path: "/notes/new", needsAuth: true},
		{name: "api-keys-list", path: "/api-keys", needsAuth: true},
		{name: "api-keys-new", path: "/api-keys/new", needsAuth: true},
		{name: "settings-account", path: "/settings", needsAuth: true},
		{name: "settings-api-keys", path: "/settings/api-keys", needsAuth: true},
		{name: "billing-settings", path: "/billing/settings", needsAuth: true},

		// Authenticated pages requiring a note
		{name: "note-view", path: "/notes/{noteID}", needsAuth: true, needsNote: true},
		{name: "note-edit", path: "/notes/{noteID}/edit", needsAuth: true, needsNote: true},
		{name: "notes-list-with-note", path: "/notes", needsAuth: true, needsNote: true},
	}
}

// captureAllScreenshots runs through every page spec and takes a screenshot with the
// given filename prefix (e.g. "before_" or "after_").
func captureAllScreenshots(t *testing.T, prefix string) {
	t.Helper()

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)

	outDir := filepath.Join(screenshotBaseDir, prefix)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("Failed to create screenshot directory %s: %v", outDir, err)
	}
	t.Logf("=== Screenshots saved to: %s ===", outDir)

	specs := allScreenshotSpecs()

	// Create authenticated context
	authCtx := env.NewContext(t)
	defer authCtx.Close()

	email := GenerateUniqueEmail("visual-audit")
	userID := env.LoginUser(t, authCtx, email)

	// Create a note for specs that need it
	noteID := env.CreateNoteForUser(t, userID, "Visual Audit Test Note", "This is a **test note** with some content for visual audit.\n\n- Item 1\n- Item 2\n- Item 3\n\n> A blockquote for good measure.")

	// Unauthenticated context
	publicCtx := env.NewContext(t)
	defer publicCtx.Close()

	for _, spec := range specs {
		t.Run(spec.name, func(t *testing.T) {
			var page playwright.Page
			var err error

			if spec.needsAuth {
				page, err = authCtx.NewPage()
			} else {
				page, err = publicCtx.NewPage()
			}
			if err != nil {
				t.Fatalf("Failed to create page: %v", err)
			}
			defer page.Close()

			page.SetDefaultTimeout(browserMaxTimeoutMS)
			page.SetViewportSize(1280, 800)

			// Resolve path - replace {noteID} placeholder
			path := spec.path
			if spec.needsNote {
				path = replaceNoteID(path, noteID)
			}

			_, err = page.Goto(env.BaseURL+path, playwright.PageGotoOptions{
				WaitUntil: playwright.WaitUntilStateDomcontentloaded,
				Timeout:   playwright.Float(browserMaxTimeoutMS),
			})
			if err != nil {
				t.Errorf("Failed to navigate to %s: %v", path, err)
				return
			}

			// Wait for page to stabilize
			err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
				State: playwright.LoadStateDomcontentloaded,
			})
			if err != nil {
				t.Logf("Warning: load state timeout for %s", path)
			}

			// Ensure any CSS transitions/animations complete
			page.Evaluate(`() => { document.body.style.opacity = '1'; }`)

			screenshotPath := filepath.Join(outDir, spec.name+".png")
			_, err = page.Screenshot(playwright.PageScreenshotOptions{
				Path:     playwright.String(screenshotPath),
				FullPage: playwright.Bool(true),
			})
			if err != nil {
				t.Errorf("Failed to capture screenshot for %s: %v", spec.name, err)
			} else {
				t.Logf("Captured: %s", screenshotPath)
			}
		})
	}

	t.Logf("=== All %s screenshots in: %s ===", prefix, outDir)
}

func replaceNoteID(path, noteID string) string {
	result := ""
	for i := 0; i < len(path); i++ {
		if i+8 <= len(path) && path[i:i+8] == "{noteID}" {
			result += noteID
			i += 7 // skip remaining chars of placeholder (loop increments by 1)
		} else {
			result += string(path[i])
		}
	}
	return result
}

// TestVisualAudit_Before captures "before" screenshots of all pages.
// Run this BEFORE applying button style fixes to establish baseline.
func TestVisualAudit_Before(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping visual audit screenshots in short mode")
	}
	captureAllScreenshots(t, "before")
}

// TestVisualAudit_After captures "after" screenshots of all pages.
// Run this AFTER applying button style fixes to show the improvements.
func TestVisualAudit_After(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping visual audit screenshots in short mode")
	}
	captureAllScreenshots(t, "after")
}

// TestVisualAudit_GenerateGallery creates an HTML index showing before/after comparison.
func TestVisualAudit_GenerateGallery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping gallery generation in short mode")
	}

	specs := allScreenshotSpecs()

	beforeDir := filepath.Join(screenshotBaseDir, "before")
	afterDir := filepath.Join(screenshotBaseDir, "after")

	// Check which screenshots actually exist
	type comparison struct {
		name      string
		hasBefore bool
		hasAfter  bool
	}
	var comparisons []comparison
	for _, spec := range specs {
		c := comparison{name: spec.name}
		if _, err := os.Stat(filepath.Join(beforeDir, spec.name+".png")); err == nil {
			c.hasBefore = true
		}
		if _, err := os.Stat(filepath.Join(afterDir, spec.name+".png")); err == nil {
			c.hasAfter = true
		}
		if c.hasBefore || c.hasAfter {
			comparisons = append(comparisons, c)
		}
	}

	if len(comparisons) == 0 {
		t.Skip("No screenshots found to compare")
	}

	// Generate HTML gallery
	html := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Visual Audit: Before / After Button Style Fixes</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8f9fa; color: #1a1a2e; padding: 2rem; }
  h1 { text-align: center; margin-bottom: 0.5rem; font-size: 1.75rem; }
  .subtitle { text-align: center; color: #666; margin-bottom: 2rem; font-size: 0.95rem; }
  .grid { display: grid; gap: 2rem; }
  .comparison { background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; }
  .comparison h2 { padding: 1rem 1.5rem; font-size: 1.1rem; border-bottom: 1px solid #eee; background: #fafafa; }
  .images { display: grid; grid-template-columns: 1fr 1fr; }
  .images > div { padding: 1rem; }
  .images > div:first-child { border-right: 1px solid #eee; }
  .label { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
  .label.before { color: #dc3545; }
  .label.after { color: #28a745; }
  .images img { width: 100%; border: 1px solid #ddd; border-radius: 4px; }
  .missing { color: #999; font-style: italic; padding: 2rem; text-align: center; background: #f5f5f5; border-radius: 4px; }
  .stats { text-align: center; margin-bottom: 1.5rem; color: #555; font-size: 0.9rem; }
</style>
</head>
<body>
<h1>Visual Audit: Button Style Fixes</h1>
<p class="subtitle">Before / After comparison of themed button class standardization</p>
`
	html += fmt.Sprintf(`<p class="stats">%d pages compared</p>`, len(comparisons))
	html += `<div class="grid">`

	for _, c := range comparisons {
		html += fmt.Sprintf(`<div class="comparison">
<h2>%s</h2>
<div class="images">
<div>
<div class="label before">Before</div>
`, c.name)
		if c.hasBefore {
			html += fmt.Sprintf(`<img src="before/%s.png" alt="Before: %s" loading="lazy">`, c.name, c.name)
		} else {
			html += `<div class="missing">No before screenshot</div>`
		}
		html += `</div><div><div class="label after">After</div>`
		if c.hasAfter {
			html += fmt.Sprintf(`<img src="after/%s.png" alt="After: %s" loading="lazy">`, c.name, c.name)
		} else {
			html += `<div class="missing">No after screenshot</div>`
		}
		html += `</div></div></div>`
	}

	html += `</div></body></html>`

	indexPath := filepath.Join(screenshotBaseDir, "index.html")
	if err := os.WriteFile(indexPath, []byte(html), 0644); err != nil {
		t.Fatalf("Failed to write gallery index: %v", err)
	}
	t.Logf("Gallery written to: %s", indexPath)
}
