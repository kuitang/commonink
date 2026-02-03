// Command generate-static generates HTML pages from markdown source files.
// It reads markdown files from static/src/, renders them through a template,
// and outputs HTML to static/gen/.
//
// Usage:
//
//	go run ./cmd/generate-static
//
// Or via go generate (add to a source file):
//
//	//go:generate go run ./cmd/generate-static
package main

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/microcosm-cc/bluemonday"
)

// PageData contains the data passed to the HTML template.
type PageData struct {
	Title   string
	Content template.HTML
	Slug    string
}

// staticPageTemplate is the HTML template for static pages.
// This uses the same styling as the main application templates.
const staticPageTemplate = `<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="common.ink - {{.Title}}">
    <title>{{.Title}} - common.ink</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        primary: {
                            50: '#eff6ff',
                            100: '#dbeafe',
                            200: '#bfdbfe',
                            300: '#93c5fd',
                            400: '#60a5fa',
                            500: '#3b82f6',
                            600: '#2563eb',
                            700: '#1d4ed8',
                            800: '#1e40af',
                            900: '#1e3a8a',
                        }
                    }
                }
            }
        }
    </script>
    <script>
        if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
            document.documentElement.classList.add('dark');
        }
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
            if (e.matches) {
                document.documentElement.classList.add('dark');
            } else {
                document.documentElement.classList.remove('dark');
            }
        });
    </script>
    <style>
        .prose { max-width: 65ch; }
        .prose h1 { font-size: 2.25rem; font-weight: 800; margin-bottom: 1rem; color: inherit; }
        .prose h2 { font-size: 1.5rem; font-weight: 700; margin-top: 2rem; margin-bottom: 0.75rem; color: inherit; }
        .prose h3 { font-size: 1.25rem; font-weight: 600; margin-top: 1.5rem; margin-bottom: 0.5rem; color: inherit; }
        .prose p { margin-bottom: 1rem; line-height: 1.75; }
        .prose ul, .prose ol { margin-bottom: 1rem; padding-left: 1.5rem; }
        .prose li { margin-bottom: 0.5rem; }
        .prose ul { list-style-type: disc; }
        .prose ol { list-style-type: decimal; }
        .prose a { color: #3b82f6; text-decoration: underline; }
        .prose a:hover { color: #2563eb; }
        .prose code { background-color: #f3f4f6; padding: 0.125rem 0.25rem; border-radius: 0.25rem; font-size: 0.875rem; }
        .dark .prose code { background-color: #374151; }
        .prose pre { background-color: #1f2937; color: #f9fafb; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; margin-bottom: 1rem; }
        .prose pre code { background-color: transparent; padding: 0; }
        .prose blockquote { border-left: 4px solid #3b82f6; padding-left: 1rem; margin: 1rem 0; font-style: italic; }
        .prose table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }
        .prose th, .prose td { border: 1px solid #e5e7eb; padding: 0.5rem 1rem; text-align: left; }
        .dark .prose th, .dark .prose td { border-color: #374151; }
        .prose th { background-color: #f3f4f6; font-weight: 600; }
        .dark .prose th { background-color: #374151; }
        .prose strong { font-weight: 600; }
        .prose hr { border-color: #e5e7eb; margin: 2rem 0; }
        .dark .prose hr { border-color: #374151; }
    </style>
</head>
<body class="h-full bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
    <!-- Navigation -->
    <nav class="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between h-16">
                <div class="flex items-center">
                    <a href="/" class="flex items-center">
                        <svg class="h-8 w-8 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        <span class="ml-2 text-xl font-bold text-gray-900 dark:text-white">common.ink</span>
                    </a>
                </div>
                <div class="flex items-center">
                    <a href="/login" class="inline-flex items-center justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-600 dark:focus:ring-offset-gray-800 transition-colors">
                        Sign in
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main content -->
    <main class="flex-1">
        <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <article class="prose dark:prose-invert mx-auto">
                {{.Content}}
            </article>
        </div>
    </main>

    <!-- Footer -->
    <footer class="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-auto">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div class="md:flex md:items-center md:justify-between">
                <div class="flex justify-center space-x-6 md:order-2">
                    <a href="/about" class="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 text-sm">
                        About
                    </a>
                    <a href="/privacy" class="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 text-sm">
                        Privacy
                    </a>
                    <a href="/terms" class="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 text-sm">
                        Terms
                    </a>
                    <a href="/docs/api" class="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 text-sm">
                        API Docs
                    </a>
                </div>
                <div class="mt-8 md:mt-0 md:order-1">
                    <p class="text-center text-sm text-gray-600 dark:text-gray-400">
                        common.ink - Secure notes for AI agents and humans
                    </p>
                </div>
            </div>
        </div>
    </footer>
</body>
</html>
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Find project root (where go.mod is)
	projectRoot, err := findProjectRoot()
	if err != nil {
		log.Fatalf("Failed to find project root: %v", err)
	}

	srcDir := filepath.Join(projectRoot, "static", "src")
	genDir := filepath.Join(projectRoot, "static", "gen")

	// Ensure output directory exists
	if err := os.MkdirAll(genDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Parse the HTML template
	tmpl, err := template.New("static").Parse(staticPageTemplate)
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	// Define page mappings: source file -> output slug and title
	pages := map[string]struct {
		Slug  string
		Title string
	}{
		"privacy.md":  {Slug: "privacy", Title: "Privacy Policy"},
		"tos.md":      {Slug: "terms", Title: "Terms of Service"},
		"about.md":    {Slug: "about", Title: "About"},
		"api-docs.md": {Slug: "api-docs", Title: "API Documentation"},
	}

	// Process each markdown file
	for srcFile, meta := range pages {
		srcPath := filepath.Join(srcDir, srcFile)
		outPath := filepath.Join(genDir, meta.Slug+".html")

		// Read markdown source
		mdContent, err := os.ReadFile(srcPath)
		if err != nil {
			log.Printf("Warning: Failed to read %s: %v", srcFile, err)
			continue
		}

		// Convert markdown to HTML
		htmlContent := renderMarkdown(mdContent)

		// Create page data
		data := PageData{
			Title:   meta.Title,
			Content: template.HTML(htmlContent),
			Slug:    meta.Slug,
		}

		// Render template
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			log.Printf("Warning: Failed to render %s: %v", srcFile, err)
			continue
		}

		// Write output file
		if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
			log.Printf("Warning: Failed to write %s: %v", outPath, err)
			continue
		}

		log.Printf("Generated: %s -> %s", srcFile, outPath)
	}

	log.Println("Static page generation complete")
}

// findProjectRoot finds the project root by looking for go.mod.
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}

// renderMarkdown converts markdown to sanitized HTML.
func renderMarkdown(md []byte) []byte {
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
	// Allow additional elements for code blocks
	policy.AllowElements("pre", "code")
	policy.AllowAttrs("class").OnElements("code", "pre")
	sanitized := policy.SanitizeBytes(htmlContent)

	return sanitized
}

// extractTitle extracts the first H1 heading from markdown content.
func extractTitle(md []byte) string {
	lines := strings.Split(string(md), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimPrefix(line, "# ")
		}
	}
	return ""
}
