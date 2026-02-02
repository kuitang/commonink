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
)

// ensure io is used (required for renderHook signature)
var _ io.Writer

// htmlTemplate is the template for the complete HTML document
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

    <style>
        :root {
            --text-color: #1a1a1a;
            --bg-color: #ffffff;
            --link-color: #0066cc;
            --code-bg: #f5f5f5;
            --border-color: #e0e0e0;
            --blockquote-border: #ddd;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --text-color: #e0e0e0;
                --bg-color: #1a1a1a;
                --link-color: #66b3ff;
                --code-bg: #2d2d2d;
                --border-color: #404040;
                --blockquote-border: #555;
            }
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--bg-color);
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem 1rem;
        }

        h1, h2, h3, h4, h5, h6 {
            margin-top: 1.5em;
            margin-bottom: 0.5em;
            line-height: 1.3;
        }

        h1 { font-size: 2rem; }
        h2 { font-size: 1.5rem; }
        h3 { font-size: 1.25rem; }

        a {
            color: var(--link-color);
            text-decoration: none;
        }

        a:hover {
            text-decoration: underline;
        }

        p {
            margin: 1em 0;
        }

        code {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;
            background-color: var(--code-bg);
            padding: 0.2em 0.4em;
            border-radius: 3px;
            font-size: 0.9em;
        }

        pre {
            background-color: var(--code-bg);
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
        }

        pre code {
            background-color: transparent;
            padding: 0;
        }

        blockquote {
            margin: 1em 0;
            padding: 0.5em 1em;
            border-left: 4px solid var(--blockquote-border);
            color: inherit;
            opacity: 0.85;
        }

        ul, ol {
            margin: 1em 0;
            padding-left: 2em;
        }

        li {
            margin: 0.25em 0;
        }

        img {
            max-width: 100%;
            height: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1em 0;
        }

        th, td {
            border: 1px solid var(--border-color);
            padding: 0.5em 1em;
            text-align: left;
        }

        th {
            background-color: var(--code-bg);
        }

        hr {
            border: none;
            border-top: 1px solid var(--border-color);
            margin: 2em 0;
        }
    </style>
</head>
<body>
    <article>
        {{.Content}}
    </article>
</body>
</html>`

// templateData holds the data for the HTML template
type templateData struct {
	Title        string
	Description  string
	CanonicalURL string
	Content      template.HTML
}

// RenderMarkdownToHTML converts markdown to a complete HTML document with SEO meta tags.
// Parameters:
//   - markdownContent: the raw markdown content to render
//   - title: the page title (used in <title> and Open Graph/Twitter meta tags)
//   - description: a brief description (used in meta description and social tags)
//   - canonicalURL: the canonical URL for the page (used in <link rel="canonical"> and og:url)
//
// Returns a complete HTML document as a byte slice.
func RenderMarkdownToHTML(markdownContent, title, description, canonicalURL string) []byte {
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

	// Escape the meta tag values to prevent XSS
	escapedTitle := html.EscapeString(title)
	escapedDescription := html.EscapeString(description)
	escapedCanonicalURL := html.EscapeString(canonicalURL)

	// Parse and execute the template
	tmpl := template.Must(template.New("html").Parse(htmlTemplate))

	var buf bytes.Buffer
	data := templateData{
		Title:        escapedTitle,
		Description:  escapedDescription,
		CanonicalURL: escapedCanonicalURL,
		Content:      template.HTML(contentHTML),
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
