package notes

import (
	"fmt"
	"strings"
)

// ContentPreview returns the first maxLines lines of content, appending "..." on a new line if truncated.
// If content has maxLines or fewer lines, returns content unchanged.
func ContentPreview(content string, maxLines int) string {
	if content == "" || maxLines <= 0 {
		return content
	}

	// Find the position of the Nth newline
	pos := 0
	found := 0
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			found++
			if found == maxLines {
				pos = i
				break
			}
		}
	}

	if found < maxLines {
		// Content has fewer than maxLines lines, return as-is
		return content
	}

	// Truncate at the Nth newline and append "..."
	return content[:pos] + "\n..."
}

// CountLines returns the number of lines in content.
// An empty string has 0 lines.
func CountLines(content string) int {
	if content == "" {
		return 0
	}
	return strings.Count(content, "\n") + 1
}

// SnippetAroundByteOffset extracts a line-numbered snippet around a byte offset in content.
// Returns the formatted snippet (with line numbers), start line, and end line (1-indexed).
// contextLines is the number of lines to show before and after the target line.
func SnippetAroundByteOffset(content string, byteOffset int, contextLines int) (snippet string, startLine int, endLine int) {
	if content == "" {
		return "", 0, 0
	}

	// Find which line the byte offset falls on (1-indexed)
	targetLine := 1
	for i := 0; i < len(content) && i < byteOffset; i++ {
		if content[i] == '\n' {
			targetLine++
		}
	}

	totalLines := strings.Count(content, "\n") + 1

	// Compute context window
	startLine = targetLine - contextLines
	if startLine < 1 {
		startLine = 1
	}
	endLine = targetLine + contextLines
	if endLine > totalLines {
		endLine = totalLines
	}

	formatted, _ := FormatWithLineNumbers(content, startLine, endLine)
	return formatted, startLine, endLine
}

// FormatWithLineNumbers formats content with cat -n style line numbers.
// Line numbers are 6-char right-justified followed by a TAB.
// If start > 0 and end > 0, only lines in that 1-indexed inclusive range are returned.
// end = -1 means end of file.
// Returns the formatted string and total line count of the original content.
func FormatWithLineNumbers(content string, start, end int) (string, int) {
	if content == "" {
		return "", 0
	}

	lines := strings.Split(content, "\n")
	totalLines := len(lines)

	// Determine range
	rangeStart := 1
	rangeEnd := totalLines

	if start > 0 {
		rangeStart = start
	}
	if end > 0 {
		rangeEnd = end
	} else if end == -1 {
		rangeEnd = totalLines
	}

	// Clamp to valid bounds
	if rangeStart < 1 {
		rangeStart = 1
	}
	if rangeEnd > totalLines {
		rangeEnd = totalLines
	}
	if rangeStart > rangeEnd {
		return "", totalLines
	}

	var b strings.Builder
	for i := rangeStart; i <= rangeEnd; i++ {
		if i > rangeStart {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%6d\t%s", i, lines[i-1])
	}

	return b.String(), totalLines
}
