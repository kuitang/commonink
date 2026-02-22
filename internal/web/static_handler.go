// Package web provides static page handlers for legal documents and info pages.
package web

import (
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/microcosm-cc/bluemonday"
)

// StaticPageData contains data for static pages.
type StaticPageData struct {
	PageData
	Content template.HTML
}

// markdownPage describes a page rendered from a markdown source file.
type markdownPage struct {
	path    string // URL path, e.g., "/privacy"
	srcFile string // filename in staticSrcDir, e.g., "privacy.md"
	title   string // page title
}

// markdownPages lists all markdown-sourced informational pages.
var markdownPages = []markdownPage{
	{"/privacy", "privacy.md", "Privacy Policy"},
	{"/terms", "tos.md", "Terms of Service"},
	{"/about", "about.md", "About"},
	{"/faq", "faq.md", "FAQ"},
	{"/docs/api", "api-docs.md", "API Documentation"},
	{"/docs", "api-docs.md", "API Documentation"},
}

// StaticHandler serves informational pages (privacy, terms, about, api-docs, install).
// Markdown-sourced pages are rendered dynamically from .md files.
// Template-sourced pages (install) render directly through the Renderer.
// All routes use OptionalAuth so the nav reflects login state.
type StaticHandler struct {
	renderer     *Renderer
	staticSrcDir string
	auth         *auth.Middleware
	cache        map[string][]byte
	cacheMu      sync.RWMutex
}

// NewStaticHandler creates a new static page handler.
func NewStaticHandler(renderer *Renderer, staticSrcDir string, authMiddleware *auth.Middleware) *StaticHandler {
	return &StaticHandler{
		renderer:     renderer,
		staticSrcDir: staticSrcDir,
		auth:         authMiddleware,
		cache:        make(map[string][]byte),
	}
}

// RegisterRoutes registers all informational page routes on the given mux.
func (h *StaticHandler) RegisterRoutes(mux *http.ServeMux) {
	// Markdown-sourced pages (HTML + raw .md variants)
	for _, p := range markdownPages {
		p := p // capture for closure
		mux.Handle("GET "+p.path, h.auth.OptionalAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if wantsMarkdown(r) {
				h.serveRawMarkdown(w, p)
				return
			}
			h.servePage(w, r, p.srcFile, p.title)
		})))
	}

	// .md suffix routes — always serve raw markdown
	seen := make(map[string]bool)
	for _, p := range markdownPages {
		mdPath := p.path + ".md"
		if seen[mdPath] {
			continue
		}
		seen[mdPath] = true
		p := p
		mux.Handle("GET "+mdPath, h.auth.OptionalAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.serveRawMarkdown(w, p)
		})))
	}

	// Template-sourced pages
	mux.Handle("GET /docs/install", h.auth.OptionalAuth(http.HandlerFunc(h.HandleInstallPage)))
}

// HandleInstallPage serves GET /docs/install — the installation/setup page.
func (h *StaticHandler) HandleInstallPage(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title: "Connect common.ink",
	}
	if auth.IsAuthenticated(r.Context()) {
		data.User = getUserWithEmail(r)
	}
	if err := h.renderer.Render(w, "install.html", data); err != nil {
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to render page")
	}
}

// servePage renders a markdown-sourced page through the static/page.html template.
func (h *StaticHandler) servePage(w http.ResponseWriter, r *http.Request, srcFile, title string) {
	srcPath := filepath.Join(h.staticSrcDir, srcFile)
	mdContent, err := h.readCached(srcPath)
	if err != nil {
		h.renderer.RenderError(w, http.StatusNotFound, "Page not found")
		return
	}

	htmlContent := renderMarkdownContent(mdContent)

	data := StaticPageData{
		PageData: PageData{
			Title: title,
		},
		Content: template.HTML(htmlContent),
	}

	if auth.IsAuthenticated(r.Context()) {
		data.User = getUserWithEmail(r)
	}

	if err := h.renderer.Render(w, "static/page.html", data); err != nil {
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to render page")
	}
}

// serveRawMarkdown writes the raw .md source with appropriate headers.
func (h *StaticHandler) serveRawMarkdown(w http.ResponseWriter, p markdownPage) {
	srcPath := filepath.Join(h.staticSrcDir, p.srcFile)
	md, err := h.readCached(srcPath)
	if err != nil {
		http.Error(w, "Page not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=UTF-8")
	w.Header().Set("Vary", "Accept")
	w.Write(md)
}

// wantsMarkdown returns true when the client prefers raw markdown.
func wantsMarkdown(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/markdown")
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
	extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock
	p := parser.NewWithExtensions(extensions)
	doc := p.Parse(md)

	htmlFlags := html.CommonFlags | html.HrefTargetBlank
	opts := html.RendererOptions{Flags: htmlFlags}
	renderer := html.NewRenderer(opts)
	htmlContent := markdown.Render(doc, renderer)

	policy := bluemonday.UGCPolicy()
	policy.AllowElements("pre", "code")
	policy.AllowAttrs("class").OnElements("code", "pre")
	sanitized := policy.SanitizeBytes(htmlContent)

	return sanitized
}

// ClearCache clears the static page cache (useful for development).
func (h *StaticHandler) ClearCache() {
	h.cacheMu.Lock()
	h.cache = make(map[string][]byte)
	h.cacheMu.Unlock()
}
