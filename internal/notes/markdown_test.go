package notes

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// =============================================================================
// Generators for markdown property tests
// =============================================================================

// headingLevelGenerator generates heading levels (1-6)
func headingLevelGenerator() *rapid.Generator[int] {
	return rapid.IntRange(1, 6)
}

// headingTextGenerator generates valid heading text (must have at least one non-space character)
func headingTextGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9][A-Za-z0-9 ]{0,49}`)
}

// codeContentGenerator generates code block content (safe characters)
func codeContentGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9 =+(){};\n]{1,100}`)
}

// urlGenerator generates valid URLs
func urlGenerator() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.Just("https://example.com"),
		rapid.Just("https://test.com/page"),
		rapid.Just("http://example.test:8080"),
	)
}

// linkTextGenerator generates link text
func linkTextGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9 ]{1,30}`)
}

// paragraphTextGenerator generates paragraph text (must start with non-space to avoid code blocks)
// Excludes periods to avoid smartypants ellipsis conversion
func paragraphTextGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z][A-Za-z0-9 ,!?]{9,99}`)
}

// =============================================================================
// Property: Markdown headings render as <h1>-<h6>
// =============================================================================

func testMarkdown_HeadingsRender_Properties(t *rapid.T) {
	level := headingLevelGenerator().Draw(t, "level")
	text := headingTextGenerator().Draw(t, "text")

	// Create markdown heading with n # characters
	markdown := strings.Repeat("#", level) + " " + text
	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(markdown, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output contains the appropriate heading tag
	hLevel := string(rune('0' + level))
	expectedCloseTag := "</h" + hLevel + ">"

	// Check for opening tag (may have attributes like id)
	if !strings.Contains(htmlStr, "<h"+hLevel) {
		t.Fatalf("Expected h%d tag in output for markdown: %s\nGot: %s", level, markdown, htmlStr)
	}

	// Check for closing tag
	if !strings.Contains(htmlStr, expectedCloseTag) {
		t.Fatalf("Expected %s tag in output for markdown: %s\nGot: %s", expectedCloseTag, markdown, htmlStr)
	}

	// Property: The heading text appears in the output (trimmed, since markdown trims whitespace)
	trimmedText := strings.TrimSpace(text)
	if trimmedText != "" && !strings.Contains(htmlStr, trimmedText) {
		t.Fatalf("Expected heading text %q in output\nGot: %s", trimmedText, htmlStr)
	}
}

func TestMarkdown_HeadingsRender_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_HeadingsRender_Properties)
}

func FuzzMarkdown_HeadingsRender_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_HeadingsRender_Properties))
}

// =============================================================================
// Property: Code blocks render as <pre><code>
// =============================================================================

func testMarkdown_CodeBlocksRender_Properties(t *rapid.T) {
	code := codeContentGenerator().Draw(t, "code")

	// Create markdown code block
	markdown := "```\n" + code + "\n```"
	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(markdown, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output contains <pre> and <code> tags
	if !strings.Contains(htmlStr, "<pre>") && !strings.Contains(htmlStr, "<pre ") {
		t.Fatalf("Expected <pre> tag in output for code block\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	if !strings.Contains(htmlStr, "<code>") && !strings.Contains(htmlStr, "<code ") {
		t.Fatalf("Expected <code> tag in output for code block\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	if !strings.Contains(htmlStr, "</pre>") {
		t.Fatalf("Expected </pre> tag in output for code block\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	if !strings.Contains(htmlStr, "</code>") {
		t.Fatalf("Expected </code> tag in output for code block\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}
}

func TestMarkdown_CodeBlocksRender_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_CodeBlocksRender_Properties)
}

func FuzzMarkdown_CodeBlocksRender_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_CodeBlocksRender_Properties))
}

// =============================================================================
// Property: Inline code renders as <code>
// =============================================================================

func testMarkdown_InlineCodeRender_Properties(t *rapid.T) {
	code := rapid.StringMatching(`[A-Za-z0-9_]{1,20}`).Draw(t, "code")

	// Create markdown with inline code
	markdown := "Here is some `" + code + "` inline code."
	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(markdown, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output contains <code> tag (not necessarily in <pre>)
	if !strings.Contains(htmlStr, "<code>") && !strings.Contains(htmlStr, "<code ") {
		t.Fatalf("Expected <code> tag in output for inline code\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	// Property: The code text appears in the output
	if !strings.Contains(htmlStr, code) {
		t.Fatalf("Expected code text %q in output\nGot: %s", code, htmlStr)
	}
}

func TestMarkdown_InlineCodeRender_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_InlineCodeRender_Properties)
}

func FuzzMarkdown_InlineCodeRender_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_InlineCodeRender_Properties))
}

// =============================================================================
// Property: Links render as <a href>
// =============================================================================

func testMarkdown_LinksRender_Properties(t *rapid.T) {
	linkText := linkTextGenerator().Draw(t, "linkText")
	url := urlGenerator().Draw(t, "url")

	// Create markdown link
	markdown := "[" + linkText + "](" + url + ")"
	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(markdown, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output contains <a> tag with href attribute
	if !strings.Contains(htmlStr, "<a ") {
		t.Fatalf("Expected <a> tag in output for link\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	if !strings.Contains(htmlStr, "href=") {
		t.Fatalf("Expected href attribute in output for link\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	// Property: The link text appears in the output
	if !strings.Contains(htmlStr, linkText) {
		t.Fatalf("Expected link text %q in output\nGot: %s", linkText, htmlStr)
	}

	// Property: The URL appears in the href (may be escaped)
	if !strings.Contains(htmlStr, url) {
		t.Fatalf("Expected URL %q in output\nGot: %s", url, htmlStr)
	}
}

func TestMarkdown_LinksRender_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_LinksRender_Properties)
}

func FuzzMarkdown_LinksRender_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_LinksRender_Properties))
}

// =============================================================================
// Property: Bold text renders correctly with <strong>
// =============================================================================

func testMarkdown_BoldRender_Properties(t *rapid.T) {
	// Bold text must not start or end with whitespace in markdown
	text := rapid.StringMatching(`[A-Za-z0-9]{1,20}`).Draw(t, "text")

	// Create markdown bold text (using **)
	markdown := "This has **" + text + "** bold text."
	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(markdown, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output contains <strong> tags
	if !strings.Contains(htmlStr, "<strong>") {
		t.Fatalf("Expected <strong> tag in output for bold text\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	if !strings.Contains(htmlStr, "</strong>") {
		t.Fatalf("Expected </strong> tag in output for bold text\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	// Property: The bold text appears in the output
	if !strings.Contains(htmlStr, text) {
		t.Fatalf("Expected bold text %q in output\nGot: %s", text, htmlStr)
	}
}

func TestMarkdown_BoldRender_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_BoldRender_Properties)
}

func FuzzMarkdown_BoldRender_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_BoldRender_Properties))
}

// =============================================================================
// Property: Italic text renders correctly with <em>
// =============================================================================

func testMarkdown_ItalicRender_Properties(t *rapid.T) {
	// Italic text must not start or end with whitespace in markdown
	text := rapid.StringMatching(`[A-Za-z0-9]{1,20}`).Draw(t, "text")

	// Create markdown italic text (using single *)
	markdown := "This has *" + text + "* italic text."
	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(markdown, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output contains <em> tags
	if !strings.Contains(htmlStr, "<em>") {
		t.Fatalf("Expected <em> tag in output for italic text\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	if !strings.Contains(htmlStr, "</em>") {
		t.Fatalf("Expected </em> tag in output for italic text\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	// Property: The italic text appears in the output
	if !strings.Contains(htmlStr, text) {
		t.Fatalf("Expected italic text %q in output\nGot: %s", text, htmlStr)
	}
}

func TestMarkdown_ItalicRender_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_ItalicRender_Properties)
}

func FuzzMarkdown_ItalicRender_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_ItalicRender_Properties))
}

// =============================================================================
// Property: Paragraphs are wrapped in <p>
// =============================================================================

func testMarkdown_ParagraphsRender_Properties(t *rapid.T) {
	para1 := paragraphTextGenerator().Draw(t, "para1")
	para2 := paragraphTextGenerator().Draw(t, "para2")

	// Create markdown with two paragraphs (separated by blank line)
	markdown := para1 + "\n\n" + para2
	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(markdown, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output contains <p> tags
	if !strings.Contains(htmlStr, "<p>") {
		t.Fatalf("Expected <p> tag in output for paragraphs\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	if !strings.Contains(htmlStr, "</p>") {
		t.Fatalf("Expected </p> tag in output for paragraphs\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	// Property: Both paragraph texts appear in the output (trimmed, since markdown trims whitespace)
	trimmedPara1 := strings.TrimSpace(para1)
	trimmedPara2 := strings.TrimSpace(para2)

	if !strings.Contains(htmlStr, trimmedPara1) {
		t.Fatalf("Expected first paragraph %q in output\nGot: %s", trimmedPara1, htmlStr)
	}

	if !strings.Contains(htmlStr, trimmedPara2) {
		t.Fatalf("Expected second paragraph %q in output\nGot: %s", trimmedPara2, htmlStr)
	}

	// Property: Multiple <p> tags exist (for two paragraphs)
	pCount := strings.Count(htmlStr, "<p>")
	if pCount < 2 {
		t.Fatalf("Expected at least 2 <p> tags for two paragraphs, got %d\nMarkdown: %s\nGot: %s", pCount, markdown, htmlStr)
	}
}

func TestMarkdown_ParagraphsRender_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_ParagraphsRender_Properties)
}

func FuzzMarkdown_ParagraphsRender_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_ParagraphsRender_Properties))
}

// =============================================================================
// Property: Unordered lists render as <ul><li>
// =============================================================================

func testMarkdown_UnorderedListRender_Properties(t *rapid.T) {
	// List items should start with non-space character
	item1 := rapid.StringMatching(`[A-Za-z0-9][A-Za-z0-9 ]{0,29}`).Draw(t, "item1")
	item2 := rapid.StringMatching(`[A-Za-z0-9][A-Za-z0-9 ]{0,29}`).Draw(t, "item2")

	// Create markdown unordered list
	markdown := "- " + item1 + "\n- " + item2
	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(markdown, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output contains <ul> and <li> tags
	if !strings.Contains(htmlStr, "<ul>") {
		t.Fatalf("Expected <ul> tag in output for unordered list\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	if !strings.Contains(htmlStr, "<li>") {
		t.Fatalf("Expected <li> tag in output for unordered list\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	// Property: Both list items appear in the output (trimmed, since markdown trims whitespace)
	trimmedItem1 := strings.TrimSpace(item1)
	trimmedItem2 := strings.TrimSpace(item2)

	if !strings.Contains(htmlStr, trimmedItem1) {
		t.Fatalf("Expected first item %q in output\nGot: %s", trimmedItem1, htmlStr)
	}

	if !strings.Contains(htmlStr, trimmedItem2) {
		t.Fatalf("Expected second item %q in output\nGot: %s", trimmedItem2, htmlStr)
	}
}

func TestMarkdown_UnorderedListRender_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_UnorderedListRender_Properties)
}

func FuzzMarkdown_UnorderedListRender_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_UnorderedListRender_Properties))
}

// =============================================================================
// Property: Ordered lists render as <ol><li>
// =============================================================================

func testMarkdown_OrderedListRender_Properties(t *rapid.T) {
	// List items should start with non-space character
	item1 := rapid.StringMatching(`[A-Za-z0-9][A-Za-z0-9 ]{0,29}`).Draw(t, "item1")
	item2 := rapid.StringMatching(`[A-Za-z0-9][A-Za-z0-9 ]{0,29}`).Draw(t, "item2")

	// Create markdown ordered list
	markdown := "1. " + item1 + "\n2. " + item2
	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(markdown, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output contains <ol> and <li> tags
	if !strings.Contains(htmlStr, "<ol>") {
		t.Fatalf("Expected <ol> tag in output for ordered list\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	if !strings.Contains(htmlStr, "<li>") {
		t.Fatalf("Expected <li> tag in output for ordered list\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	// Property: Both list items appear in the output (trimmed, since markdown trims whitespace)
	trimmedItem1 := strings.TrimSpace(item1)
	trimmedItem2 := strings.TrimSpace(item2)

	if !strings.Contains(htmlStr, trimmedItem1) {
		t.Fatalf("Expected first item %q in output\nGot: %s", trimmedItem1, htmlStr)
	}

	if !strings.Contains(htmlStr, trimmedItem2) {
		t.Fatalf("Expected second item %q in output\nGot: %s", trimmedItem2, htmlStr)
	}
}

func TestMarkdown_OrderedListRender_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_OrderedListRender_Properties)
}

func FuzzMarkdown_OrderedListRender_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_OrderedListRender_Properties))
}

// =============================================================================
// Property: Blockquotes render as <blockquote>
// =============================================================================

func testMarkdown_BlockquoteRender_Properties(t *rapid.T) {
	// Quote text should not start with spaces (which would create code block inside blockquote)
	// Excludes periods to avoid smartypants ellipsis conversion
	quote := rapid.StringMatching(`[A-Za-z][A-Za-z0-9 ,!?]{9,99}`).Draw(t, "quote")

	// Create markdown blockquote
	markdown := "> " + quote
	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(markdown, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output contains <blockquote> tag
	if !strings.Contains(htmlStr, "<blockquote>") {
		t.Fatalf("Expected <blockquote> tag in output for blockquote\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	if !strings.Contains(htmlStr, "</blockquote>") {
		t.Fatalf("Expected </blockquote> tag in output for blockquote\nMarkdown: %s\nGot: %s", markdown, htmlStr)
	}

	// Property: The quote text appears in the output (trimmed, since markdown trims whitespace)
	trimmedQuote := strings.TrimSpace(quote)
	if !strings.Contains(htmlStr, trimmedQuote) {
		t.Fatalf("Expected quote text %q in output\nGot: %s", trimmedQuote, htmlStr)
	}
}

func TestMarkdown_BlockquoteRender_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_BlockquoteRender_Properties)
}

func FuzzMarkdown_BlockquoteRender_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_BlockquoteRender_Properties))
}

// =============================================================================
// Property: Output is valid HTML document
// =============================================================================

func testMarkdown_ValidHTMLDocument_Properties(t *rapid.T) {
	content := paragraphTextGenerator().Draw(t, "content")
	title := rapid.StringMatching(`[A-Za-z0-9 ]{1,50}`).Draw(t, "title")
	description := rapid.StringMatching(`[A-Za-z0-9 ]{1,100}`).Draw(t, "description")
	canonicalURL := urlGenerator().Draw(t, "canonicalURL")

	html := RenderMarkdownToHTML(content, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Property: Output starts with DOCTYPE
	if !strings.HasPrefix(htmlStr, "<!DOCTYPE html>") {
		t.Fatalf("Expected output to start with <!DOCTYPE html>\nGot: %s", htmlStr[:min(100, len(htmlStr))])
	}

	// Property: Output contains <html> tag
	if !strings.Contains(htmlStr, "<html") {
		t.Fatalf("Expected <html> tag in output\nGot: %s", htmlStr)
	}

	// Property: Output contains <head> tag
	if !strings.Contains(htmlStr, "<head>") {
		t.Fatalf("Expected <head> tag in output\nGot: %s", htmlStr)
	}

	// Property: Output contains <body> tag (may have attributes like class)
	if !strings.Contains(htmlStr, "<body") {
		t.Fatalf("Expected <body> tag in output\nGot: %s", htmlStr)
	}

	// Property: Output contains <title> tag with the title
	if !strings.Contains(htmlStr, "<title>") {
		t.Fatalf("Expected <title> tag in output\nGot: %s", htmlStr)
	}

	// Property: Output contains meta description
	if !strings.Contains(htmlStr, "meta name=\"description\"") {
		t.Fatalf("Expected meta description in output\nGot: %s", htmlStr)
	}

	// Property: Output contains canonical link
	if !strings.Contains(htmlStr, "rel=\"canonical\"") {
		t.Fatalf("Expected canonical link in output\nGot: %s", htmlStr)
	}
}

func TestMarkdown_ValidHTMLDocument_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_ValidHTMLDocument_Properties)
}

func FuzzMarkdown_ValidHTMLDocument_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_ValidHTMLDocument_Properties))
}

// =============================================================================
// Property: XSS prevention - script tags are sanitized
// =============================================================================

func testMarkdown_XSSPrevention_Properties(t *rapid.T) {
	// Attempt to inject a script tag
	maliciousContent := rapid.OneOf(
		rapid.Just("<script>alert('XSS')</script>"),
		rapid.Just("<script src=\"evil.js\"></script>"),
		rapid.Just("<img onerror=\"alert('XSS')\" src=\"x\">"),
		rapid.Just("<a href=\"javascript:alert('XSS')\">click</a>"),
	).Draw(t, "maliciousContent")

	title := "Test Title"
	description := "Test Description"
	canonicalURL := "https://example.com/test"

	html := RenderMarkdownToHTML(maliciousContent, title, description, canonicalURL, "")
	htmlStr := string(html)

	// Extract just the article body content to avoid matching the Tailwind CDN <script> in <head>
	articleStart := strings.Index(htmlStr, "<article")
	articleEnd := strings.Index(htmlStr, "</article>")
	if articleStart == -1 || articleEnd == -1 {
		t.Fatalf("Expected <article> tags in output\nGot: %s", htmlStr)
	}
	articleContent := htmlStr[articleStart : articleEnd+len("</article>")]

	// Property: Script tags are not present in article content
	if strings.Contains(articleContent, "<script") {
		t.Fatalf("Script tag should be sanitized\nInput: %s\nGot: %s", maliciousContent, articleContent)
	}

	// Property: JavaScript URLs are not present in article content
	if strings.Contains(articleContent, "javascript:") {
		t.Fatalf("JavaScript URL should be sanitized\nInput: %s\nGot: %s", maliciousContent, articleContent)
	}

	// Property: Event handlers are not present in article content (onerror, onclick, etc.)
	if strings.Contains(articleContent, "onerror=") || strings.Contains(articleContent, "onclick=") {
		t.Fatalf("Event handlers should be sanitized\nInput: %s\nGot: %s", maliciousContent, articleContent)
	}
}

func TestMarkdown_XSSPrevention_Properties(t *testing.T) {
	rapid.Check(t, testMarkdown_XSSPrevention_Properties)
}

func FuzzMarkdown_XSSPrevention_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMarkdown_XSSPrevention_Properties))
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
