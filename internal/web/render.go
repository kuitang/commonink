// Package web provides HTML template rendering for the web UI.
package web

import (
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/microcosm-cc/bluemonday"
)

// Renderer manages HTML template rendering with caching and custom functions.
type Renderer struct {
	templates map[string]*template.Template
	funcMap   template.FuncMap
	mu        sync.RWMutex
}

// NewRenderer creates a new Renderer by parsing all templates in the given directory.
// It parses base.html first, then combines it with each page template in subdirectories.
// Returns an error if the templates directory doesn't exist or templates fail to parse.
func NewRenderer(templatesDir string) (*Renderer, error) {
	r := &Renderer{
		templates: make(map[string]*template.Template),
		funcMap:   createFuncMap(),
	}

	if err := r.parseTemplates(templatesDir); err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return r, nil
}

// Render executes the named template with the given data and writes the result to w.
// The templateName should be the relative path from the templates directory
// (e.g., "auth/login.html", "notes/list.html").
func (r *Renderer) Render(w http.ResponseWriter, templateName string, data interface{}) error {
	r.mu.RLock()
	tmpl, ok := r.templates[templateName]
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("template %q not found", templateName)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		return fmt.Errorf("failed to execute template %q: %w", templateName, err)
	}

	return nil
}

// RenderError renders an error page with the given HTTP status code and message.
func (r *Renderer) RenderError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)

	// Try to use the error template if available
	r.mu.RLock()
	tmpl, ok := r.templates["auth/error.html"]
	r.mu.RUnlock()

	if ok {
		data := map[string]interface{}{
			"Error":     message,
			"ErrorCode": http.StatusText(code),
		}
		if err := tmpl.ExecuteTemplate(w, "base", data); err == nil {
			return
		}
	}

	http.Error(w, fmt.Sprintf("Error %d: %s", code, message), code)
}

// RenderPublic executes the named template with the given data using the minimal
// public base template (base_public.html) instead of the full app chrome.
func (r *Renderer) RenderPublic(w http.ResponseWriter, templateName string, data interface{}) error {
	publicKey := "public:" + templateName
	r.mu.RLock()
	tmpl, ok := r.templates[publicKey]
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("public template %q not found", templateName)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base_public", data); err != nil {
		return fmt.Errorf("failed to execute public template %q: %w", templateName, err)
	}

	return nil
}

// parseTemplates parses the base template and all page templates.
func (r *Renderer) parseTemplates(templatesDir string) error {
	// Use os.Root to safely scope file access to the templates directory
	// This prevents path traversal attacks (G304)
	root, err := os.OpenRoot(templatesDir)
	if err != nil {
		return fmt.Errorf("failed to open templates directory: %w", err)
	}
	defer root.Close()

	// Parse base.html first using the rooted file access
	baseFile, err := root.Open("base.html")
	if err != nil {
		return fmt.Errorf("failed to open base template: %w", err)
	}
	baseContent, err := io.ReadAll(baseFile)
	baseFile.Close()
	if err != nil {
		return fmt.Errorf("failed to read base template: %w", err)
	}

	// Parse base_public.html for minimal-chrome public pages
	basePublicFile, err := root.Open("base_public.html")
	if err != nil {
		return fmt.Errorf("failed to open base_public template: %w", err)
	}
	basePublicContent, err := io.ReadAll(basePublicFile)
	basePublicFile.Close()
	if err != nil {
		return fmt.Errorf("failed to read base_public template: %w", err)
	}

	// Walk through subdirectories to find page templates
	absTemplatesDir, err := filepath.Abs(templatesDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path of templates dir: %w", err)
	}
	basePath := filepath.Join(absTemplatesDir, "base.html")
	basePublicPath := filepath.Join(absTemplatesDir, "base_public.html")

	err = filepath.WalkDir(absTemplatesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and the base templates
		if d.IsDir() || path == basePath || path == basePublicPath {
			return nil
		}

		// Only process .html files
		if !strings.HasSuffix(path, ".html") {
			return nil
		}

		// Get the relative path for the template name
		relPath, err := filepath.Rel(absTemplatesDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path for %s: %w", path, err)
		}

		// Read the page template using the rooted file access (safe from path traversal)
		pageFile, err := root.Open(relPath)
		if err != nil {
			return fmt.Errorf("failed to open template %s: %w", relPath, err)
		}
		pageContent, err := io.ReadAll(pageFile)
		pageFile.Close()
		if err != nil {
			return fmt.Errorf("failed to read template %s: %w", relPath, err)
		}

		// Create a new template with the function map (standard base)
		tmpl := template.New("base").Funcs(r.funcMap)

		// Parse the base template first
		tmpl, err = tmpl.Parse(string(baseContent))
		if err != nil {
			return fmt.Errorf("failed to parse base template for %s: %w", relPath, err)
		}

		// Parse the page template (which overrides the content block)
		tmpl, err = tmpl.Parse(string(pageContent))
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %w", relPath, err)
		}

		// Also create a public variant with base_public.html
		publicTmpl := template.New("base_public").Funcs(r.funcMap)
		publicTmpl, err = publicTmpl.Parse(string(basePublicContent))
		if err != nil {
			return fmt.Errorf("failed to parse base_public template for %s: %w", relPath, err)
		}
		publicTmpl, err = publicTmpl.Parse(string(pageContent))
		if err != nil {
			return fmt.Errorf("failed to parse public template %s: %w", relPath, err)
		}

		// Store both template variants
		r.mu.Lock()
		r.templates[relPath] = tmpl
		r.templates["public:"+relPath] = publicTmpl
		r.mu.Unlock()

		return nil
	})

	if err != nil {
		return err
	}

	if len(r.templates) == 0 {
		return fmt.Errorf("no templates found in %s", templatesDir)
	}

	return nil
}

// createFuncMap creates the template function map with all custom functions.
func createFuncMap() template.FuncMap {
	return template.FuncMap{
		"formatTime":  formatTime,
		"truncate":    truncate,
		"markdown":    renderMarkdown,
		"add":         add,
		"sub":         sub,
		"formatFloat": formatFloat,
	}
}

// formatTime formats a time.Time as a human-readable date string.
// Example: "Jan 2, 2006"
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("Jan 2, 2006")
}

// truncate truncates a string to n characters, adding "..." if truncated.
// If the string is shorter than or equal to n, it is returned unchanged.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}

	// Convert to runes to handle multi-byte characters correctly
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}

	// Account for the "..." suffix
	if n <= 3 {
		return string(runes[:n])
	}

	return string(runes[:n-3]) + "..."
}

// renderMarkdown converts markdown text to HTML.
// The returned HTML is safe to use in templates (marked as template.HTML).
func renderMarkdown(s string) template.HTML {
	// Configure the markdown parser with common extensions
	extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock
	p := parser.NewWithExtensions(extensions)

	// Parse the markdown
	doc := p.Parse([]byte(s))

	// Configure the HTML renderer
	htmlFlags := html.CommonFlags | html.HrefTargetBlank
	opts := html.RendererOptions{
		Flags: htmlFlags,
	}
	renderer := html.NewRenderer(opts)

	// Render to HTML
	htmlContent := markdown.Render(doc, renderer)

	// Sanitize HTML to prevent XSS attacks
	policy := bluemonday.UGCPolicy()
	sanitized := policy.SanitizeBytes(htmlContent)

	return template.HTML(sanitized)
}

// add returns the sum of two integers. Used for pagination.
func add(a, b int) int {
	return a + b
}

// sub returns the difference of two integers. Used for pagination.
func sub(a, b int) int {
	return a - b
}

// formatFloat formats a float64 with the given number of decimal places.
func formatFloat(f float64, decimals int) string {
	return fmt.Sprintf("%.*f", decimals, f)
}
