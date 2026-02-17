// Package web provides static page handlers for legal documents and info pages.
package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/microcosm-cc/bluemonday"
)

// StaticPageData contains data for static pages.
type StaticPageData struct {
	PageData
	Content template.HTML
}

// StaticHandler serves static pages (privacy, terms, about, api-docs).
// It can serve from pre-generated HTML files or render markdown dynamically.
type StaticHandler struct {
	renderer     *Renderer
	staticGenDir string
	staticSrcDir string
	cache        map[string][]byte
	cacheMu      sync.RWMutex
	useGenerated bool
}

// NewStaticHandler creates a new static page handler.
// If staticGenDir contains pre-generated HTML files, those are served directly.
// Otherwise, markdown from staticSrcDir is rendered dynamically.
func NewStaticHandler(renderer *Renderer, staticGenDir, staticSrcDir string) *StaticHandler {
	h := &StaticHandler{
		renderer:     renderer,
		staticGenDir: staticGenDir,
		staticSrcDir: staticSrcDir,
		cache:        make(map[string][]byte),
	}

	// Check if generated files exist
	if _, err := os.Stat(filepath.Join(staticGenDir, "privacy.html")); err == nil {
		h.useGenerated = true
	}

	return h
}

// RegisterRoutes registers static page routes on the given mux.
func (h *StaticHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /privacy", h.HandlePrivacy)
	mux.HandleFunc("GET /terms", h.HandleTerms)
	mux.HandleFunc("GET /about", h.HandleAbout)
	mux.HandleFunc("GET /docs/api", h.HandleAPIDocs)
	mux.HandleFunc("GET /docs", h.HandleAPIDocs) // Alias
}

// HandlePrivacy serves the privacy policy page.
func (h *StaticHandler) HandlePrivacy(w http.ResponseWriter, r *http.Request) {
	h.servePage(w, r, "privacy", "Privacy Policy")
}

// HandleTerms serves the terms of service page.
func (h *StaticHandler) HandleTerms(w http.ResponseWriter, r *http.Request) {
	h.servePage(w, r, "terms", "Terms of Service")
}

// HandleAbout serves the about page.
func (h *StaticHandler) HandleAbout(w http.ResponseWriter, r *http.Request) {
	h.servePage(w, r, "about", "About")
}

// HandleAPIDocs serves the API documentation page.
func (h *StaticHandler) HandleAPIDocs(w http.ResponseWriter, r *http.Request) {
	h.servePage(w, r, "api-docs", "API Documentation")
}

// servePage serves a static page by slug.
// Always renders through the page.html template so that copy buttons and
// other template-level features (styles, scripts) are included.
func (h *StaticHandler) servePage(w http.ResponseWriter, r *http.Request, slug, title string) {
	var htmlContent []byte

	// Try pre-generated HTML first (markdown already converted)
	if h.useGenerated {
		genPath := filepath.Join(h.staticGenDir, slug+".html")
		content, err := h.readCached(genPath)
		if err == nil {
			htmlContent = content
		}
	}

	// Fall back to dynamic rendering from markdown
	if htmlContent == nil {
		srcFile := slug + ".md"
		if slug == "terms" {
			srcFile = "tos.md"
		}

		srcPath := filepath.Join(h.staticSrcDir, srcFile)
		mdContent, err := h.readCached(srcPath)
		if err != nil {
			h.renderer.RenderError(w, http.StatusNotFound, "Page not found")
			return
		}

		htmlContent = renderMarkdownContent(mdContent)
	}

	data := StaticPageData{
		PageData: PageData{
			Title: title,
		},
		Content: template.HTML(htmlContent),
	}

	if err := h.renderer.Render(w, "static/page.html", data); err != nil {
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to render page")
	}
}

// readCached reads a file with caching.
func (h *StaticHandler) readCached(path string) ([]byte, error) {
	h.cacheMu.RLock()
	content, ok := h.cache[path]
	h.cacheMu.RUnlock()

	if ok {
		return content, nil
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	h.cacheMu.Lock()
	h.cache[path] = content
	h.cacheMu.Unlock()

	return content, nil
}

// renderMarkdownContent converts markdown to sanitized HTML.
func renderMarkdownContent(md []byte) []byte {
	// Configure the markdown parser with common extensions
	extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock
	p := parser.NewWithExtensions(extensions)

	// Parse the markdown
	doc := p.Parse(md)

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
	policy.AllowElements("pre", "code")
	policy.AllowAttrs("class").OnElements("code", "pre")
	sanitized := policy.SanitizeBytes(htmlContent)

	return sanitized
}

// EmbeddedStaticHandler serves static pages from embedded files.
// This is useful for single-binary deployments.
type EmbeddedStaticHandler struct {
	renderer *Renderer
	genFS    fs.FS
	srcFS    fs.FS
}

// NewEmbeddedStaticHandler creates a handler using embedded file systems.
func NewEmbeddedStaticHandler(renderer *Renderer, genFS, srcFS embed.FS) *EmbeddedStaticHandler {
	return &EmbeddedStaticHandler{
		renderer: renderer,
		genFS:    genFS,
		srcFS:    srcFS,
	}
}

// ClearCache clears the static page cache (useful for development).
func (h *StaticHandler) ClearCache() {
	h.cacheMu.Lock()
	h.cache = make(map[string][]byte)
	h.cacheMu.Unlock()
}
