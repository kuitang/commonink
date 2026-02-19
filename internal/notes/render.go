package notes

import (
	"bytes"
	"html"
	"html/template"
	"io"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	mdhtml "github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/microcosm-cc/bluemonday"
)

// ensure io is used (required for renderHook signature)
var _ io.Writer

// htmlTemplate is the template for the complete HTML document.
// Uses Tailwind CSS CDN with an academic theme: Georgia serif, terracotta accents,
// warm gray surfaces, CSS-only dark mode via prefers-color-scheme.
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <meta name="description" content="{{.Description}}">

    <!-- Canonical URL -->
    <link rel="canonical" href="{{.CanonicalURL}}">

    <!-- Open Graph -->
    <meta property="og:title" content="{{.Title}}">
    <meta property="og:description" content="{{.Description}}">
    <meta property="og:url" content="{{.CanonicalURL}}">
    <meta property="og:type" content="article">

    <!-- Twitter Cards -->
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="{{.Title}}">
    <meta name="twitter:description" content="{{.Description}}">

    <!-- Tailwind CSS CDN with academic theme -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
    tailwind.config = {
      darkMode: 'media',
      theme: {
        extend: {
          colors: {
            terracotta: {
              50:  '#fdf3ef',
              100: '#fbe4da',
              200: '#f6c5b4',
              300: '#f0a084',
              400: '#e87853',
              500: '#c4633a',
              600: '#b0502e',
              700: '#923f26',
              800: '#763424',
              900: '#612c21',
              950: '#34140f',
            },
            warmgray: {
              50:  '#F5F5F0',
              100: '#EBEBDF',
              200: '#D6D6C8',
              300: '#B8B8A6',
              400: '#9A9A84',
              500: '#7D7D68',
              600: '#636353',
              700: '#4D4D41',
              800: '#3A3A32',
              900: '#2A2A24',
              950: '#1a1a18',
            },
          },
          fontFamily: {
            serif: ['Georgia', 'Cambria', '"Times New Roman"', 'Times', 'serif'],
          },
        },
      },
    }
    </script>

    <style type="text/tailwindcss">
        /* Prose overrides for markdown content */
        article pre {
            @apply overflow-x-auto;
        }
    </style>
</head>
<body class="bg-warmgray-50 dark:bg-warmgray-950 text-warmgray-900 dark:text-warmgray-100 font-serif antialiased">
    <div class="max-w-3xl mx-auto px-4 sm:px-6 py-10 sm:py-16">

        <!-- Article header -->
        <header class="mb-8 border-b border-warmgray-200 dark:border-warmgray-800 pb-6">
            <h1 class="text-3xl sm:text-4xl font-bold leading-tight text-warmgray-900 dark:text-warmgray-50 mb-3">{{.Title}}</h1>
            <p class="text-sm text-warmgray-500 dark:text-warmgray-400">
                By <span class="font-medium text-terracotta-600 dark:text-terracotta-400">{{if .Author}}{{.Author}}{{else}}Anonymous{{end}}</span>
            </p>
        </header>

        <!-- Article body -->
        <article class="
            prose prose-lg max-w-none
            prose-headings:font-serif prose-headings:text-warmgray-900 dark:prose-headings:text-warmgray-50
            prose-h2:text-2xl prose-h2:mt-10 prose-h2:mb-4 prose-h2:border-b prose-h2:border-warmgray-200 dark:prose-h2:border-warmgray-800 prose-h2:pb-2
            prose-h3:text-xl prose-h3:mt-8 prose-h3:mb-3
            prose-p:text-warmgray-800 dark:prose-p:text-warmgray-200 prose-p:leading-relaxed
            prose-a:text-terracotta-600 dark:prose-a:text-terracotta-400 prose-a:underline prose-a:decoration-terracotta-300 dark:prose-a:decoration-terracotta-700 hover:prose-a:decoration-terracotta-500
            prose-strong:text-warmgray-900 dark:prose-strong:text-warmgray-50
            prose-code:text-terracotta-700 dark:prose-code:text-terracotta-300 prose-code:bg-warmgray-100 dark:prose-code:bg-warmgray-900 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-sm prose-code:font-normal prose-code:before:content-none prose-code:after:content-none
            prose-pre:bg-warmgray-100 dark:prose-pre:bg-warmgray-900 prose-pre:border prose-pre:border-warmgray-200 dark:prose-pre:border-warmgray-800 prose-pre:rounded-lg prose-pre:shadow-sm
            prose-blockquote:border-terracotta-400 dark:prose-blockquote:border-terracotta-600 prose-blockquote:text-warmgray-600 dark:prose-blockquote:text-warmgray-400 prose-blockquote:not-italic
            prose-img:rounded-lg prose-img:shadow-md
            prose-hr:border-warmgray-200 dark:prose-hr:border-warmgray-800
            prose-th:text-warmgray-900 dark:prose-th:text-warmgray-50
            prose-td:text-warmgray-700 dark:prose-td:text-warmgray-300
            prose-li:text-warmgray-800 dark:prose-li:text-warmgray-200
        ">
            {{.Content}}
        </article>

        <!-- Share section -->
        {{if .CanonicalURL}}
        <footer class="mt-12 pt-6 border-t border-warmgray-200 dark:border-warmgray-800">
            <p class="text-xs text-warmgray-400 dark:text-warmgray-500 uppercase tracking-wider mb-2">Share this note</p>
            <p class="text-sm text-warmgray-600 dark:text-warmgray-400 font-mono break-all select-all bg-warmgray-100 dark:bg-warmgray-900 rounded px-3 py-2 border border-warmgray-200 dark:border-warmgray-800">{{.CanonicalURL}}</p>
        </footer>
        {{end}}

    </div>
</body>
</html>`

// templateData holds the data for the HTML template
type templateData struct {
	Title        string
	Description  string
	CanonicalURL string
	Author       string
	Content      template.HTML
}

// RenderMarkdownToHTML converts markdown to a complete HTML document with SEO meta tags.
// Parameters:
//   - markdownContent: the raw markdown content to render
//   - title: the page title (used in <title> and Open Graph/Twitter meta tags)
//   - description: a brief description (used in meta description and social tags)
//   - canonicalURL: the canonical URL for the page (used in <link rel="canonical"> and og:url)
//   - author: the author name displayed in the byline (shown as "Anonymous" if empty)
//
// Returns a complete HTML document as a byte slice.
func RenderMarkdownToHTML(markdownContent, title, description, canonicalURL, author string) []byte {
	// Configure the markdown parser with common extensions
	extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock
	p := parser.NewWithExtensions(extensions)

	// Parse the markdown
	doc := p.Parse([]byte(markdownContent))

	// Configure the HTML renderer
	htmlFlags := mdhtml.CommonFlags | mdhtml.HrefTargetBlank
	opts := mdhtml.RendererOptions{
		Flags:          htmlFlags,
		RenderNodeHook: renderHook,
	}
	renderer := mdhtml.NewRenderer(opts)

	// Render markdown to HTML
	contentHTML := markdown.Render(doc, renderer)

	// Sanitize HTML to prevent XSS attacks
	policy := bluemonday.UGCPolicy()
	sanitizedContent := policy.SanitizeBytes(contentHTML)

	// Escape the meta tag values to prevent XSS
	escapedTitle := html.EscapeString(title)
	escapedDescription := html.EscapeString(description)
	escapedCanonicalURL := html.EscapeString(canonicalURL)
	escapedAuthor := html.EscapeString(author)

	// Parse and execute the template
	tmpl := template.Must(template.New("html").Parse(htmlTemplate))

	var buf bytes.Buffer
	data := templateData{
		Title:        escapedTitle,
		Description:  escapedDescription,
		CanonicalURL: escapedCanonicalURL,
		Author:       escapedAuthor,
		Content:      template.HTML(sanitizedContent),
	}

	err := tmpl.Execute(&buf, data)
	if err != nil {
		// Fall back to a simple error page if template execution fails
		return []byte("<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Error rendering page</h1></body></html>")
	}

	return buf.Bytes()
}

// renderHook is a custom render hook for additional processing
func renderHook(w io.Writer, node ast.Node, entering bool) (ast.WalkStatus, bool) {
	// Return false to use default rendering for all nodes
	return ast.GoToNext, false
}
