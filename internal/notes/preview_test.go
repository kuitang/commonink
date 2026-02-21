package notes

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// =============================================================================
// Generators for preview property tests
// =============================================================================

// multilineContentGenerator generates content with a controllable number of lines.
// Each line has at least 1 character to avoid producing empty strings.
func multilineContentGenerator() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		numLines := rapid.IntRange(1, 20).Draw(t, "numLines")
		lines := make([]string, numLines)
		for i := 0; i < numLines; i++ {
			lines[i] = rapid.StringMatching(`[A-Za-z0-9 .,!?]{1,80}`).Draw(t, "line")
		}
		return strings.Join(lines, "\n")
	})
}

// =============================================================================
// Property: ContentPreview - no truncation when content has <= maxLines lines
// =============================================================================

func testContentPreview_NoTruncation_Properties(t *rapid.T) {
	content := multilineContentGenerator().Draw(t, "content")
	lineCount := CountLines(content)
	// maxLines >= lineCount means no truncation
	maxLines := rapid.IntRange(lineCount, lineCount+10).Draw(t, "maxLines")

	result := ContentPreview(content, maxLines)

	// Property: output equals input when no truncation needed
	if result != content {
		t.Fatalf("Expected no truncation: content has %d lines, maxLines=%d, but got different output.\nInput:  %q\nOutput: %q",
			lineCount, maxLines, content, result)
	}
}

func TestContentPreview_NoTruncation_Properties(t *testing.T) {
	rapid.Check(t, testContentPreview_NoTruncation_Properties)
}

func FuzzContentPreview_NoTruncation_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testContentPreview_NoTruncation_Properties))
}

// =============================================================================
// Property: ContentPreview - truncation produces maxLines+1 lines (including "...")
// =============================================================================

func testContentPreview_Truncation_Properties(t *rapid.T) {
	// Generate content with at least 2 lines so we can truncate
	numLines := rapid.IntRange(2, 20).Draw(t, "numLines")
	lines := make([]string, numLines)
	for i := 0; i < numLines; i++ {
		lines[i] = rapid.StringMatching(`[A-Za-z0-9 ]{1,40}`).Draw(t, "line")
	}
	content := strings.Join(lines, "\n")

	// maxLines < numLines forces truncation
	maxLines := rapid.IntRange(1, numLines-1).Draw(t, "maxLines")

	result := ContentPreview(content, maxLines)

	// Property: output has exactly maxLines+1 lines (maxLines of content + "..." line)
	resultLines := strings.Split(result, "\n")
	expectedResultLines := maxLines + 1
	if len(resultLines) != expectedResultLines {
		t.Fatalf("Expected %d lines in truncated output, got %d.\nmaxLines=%d, numLines=%d\nResult: %q",
			expectedResultLines, len(resultLines), maxLines, numLines, result)
	}

	// Property: last line is "..."
	if resultLines[len(resultLines)-1] != "..." {
		t.Fatalf("Expected last line to be \"...\", got %q", resultLines[len(resultLines)-1])
	}
}

func TestContentPreview_Truncation_Properties(t *testing.T) {
	rapid.Check(t, testContentPreview_Truncation_Properties)
}

func FuzzContentPreview_Truncation_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testContentPreview_Truncation_Properties))
}

// =============================================================================
// Property: ContentPreview - empty content returns empty
// =============================================================================

func testContentPreview_Empty_Properties(t *rapid.T) {
	maxLines := rapid.IntRange(1, 100).Draw(t, "maxLines")

	result := ContentPreview("", maxLines)

	// Property: empty content returns empty
	if result != "" {
		t.Fatalf("Expected empty string for empty content, got %q", result)
	}
}

func TestContentPreview_Empty_Properties(t *testing.T) {
	rapid.Check(t, testContentPreview_Empty_Properties)
}

func FuzzContentPreview_Empty_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testContentPreview_Empty_Properties))
}

// =============================================================================
// Property: CountLines - empty string returns 0
// =============================================================================

func testCountLines_Empty_Properties(t *rapid.T) {
	result := CountLines("")

	// Property: empty string has 0 lines
	if result != 0 {
		t.Fatalf("Expected 0 lines for empty string, got %d", result)
	}
}

func TestCountLines_Empty_Properties(t *testing.T) {
	rapid.Check(t, testCountLines_Empty_Properties)
}

func FuzzCountLines_Empty_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCountLines_Empty_Properties))
}

// =============================================================================
// Property: CountLines - string with N newlines returns N+1
// =============================================================================

func testCountLines_NewlineCount_Properties(t *rapid.T) {
	content := multilineContentGenerator().Draw(t, "content")
	expectedNewlines := strings.Count(content, "\n")

	result := CountLines(content)

	// Property: line count equals newline count + 1
	expected := expectedNewlines + 1
	if result != expected {
		t.Fatalf("Expected %d lines (newlines=%d), got %d for content %q",
			expected, expectedNewlines, result, content)
	}
}

func TestCountLines_NewlineCount_Properties(t *testing.T) {
	rapid.Check(t, testCountLines_NewlineCount_Properties)
}

func FuzzCountLines_NewlineCount_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCountLines_NewlineCount_Properties))
}

// =============================================================================
// Property: CountLines - single line (no newlines) returns 1
// =============================================================================

func testCountLines_SingleLine_Properties(t *rapid.T) {
	// Generate content with no newlines
	content := rapid.StringMatching(`[A-Za-z0-9 ]{1,100}`).Draw(t, "content")

	result := CountLines(content)

	// Property: single line returns 1
	if result != 1 {
		t.Fatalf("Expected 1 line for single-line content %q, got %d", content, result)
	}
}

func TestCountLines_SingleLine_Properties(t *testing.T) {
	rapid.Check(t, testCountLines_SingleLine_Properties)
}

func FuzzCountLines_SingleLine_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCountLines_SingleLine_Properties))
}

// =============================================================================
// Property: FormatWithLineNumbers - every line starts with number and tab
// =============================================================================

func testFormatWithLineNumbers_LineFormat_Properties(t *rapid.T) {
	content := multilineContentGenerator().Draw(t, "content")

	result, totalLines := FormatWithLineNumbers(content, 0, -1)

	// Property: total lines matches CountLines
	if totalLines != CountLines(content) {
		t.Fatalf("Total lines mismatch: FormatWithLineNumbers=%d, CountLines=%d",
			totalLines, CountLines(content))
	}

	// Property: every output line starts with a number and tab
	if result == "" {
		return
	}
	outputLines := strings.Split(result, "\n")
	for i, line := range outputLines {
		tabIdx := strings.IndexByte(line, '\t')
		if tabIdx == -1 {
			t.Fatalf("Line %d has no tab: %q", i, line)
		}
		prefix := strings.TrimSpace(line[:tabIdx])
		if prefix == "" {
			t.Fatalf("Line %d has empty number prefix: %q", i, line)
		}
		// Verify prefix is a valid number
		for _, ch := range prefix {
			if ch < '0' || ch > '9' {
				t.Fatalf("Line %d has non-numeric prefix %q: %q", i, prefix, line)
			}
		}
	}
}

func TestFormatWithLineNumbers_LineFormat_Properties(t *testing.T) {
	rapid.Check(t, testFormatWithLineNumbers_LineFormat_Properties)
}

func FuzzFormatWithLineNumbers_LineFormat_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testFormatWithLineNumbers_LineFormat_Properties))
}

// =============================================================================
// Property: FormatWithLineNumbers - full range [1, -1] returns all lines
// =============================================================================

func testFormatWithLineNumbers_FullRange_Properties(t *rapid.T) {
	content := multilineContentGenerator().Draw(t, "content")

	result, totalLines := FormatWithLineNumbers(content, 1, -1)

	// Property: output has same number of lines as input
	if result == "" && totalLines == 0 {
		return
	}
	outputLines := strings.Split(result, "\n")
	if len(outputLines) != totalLines {
		t.Fatalf("Expected %d output lines for full range, got %d", totalLines, len(outputLines))
	}
}

func TestFormatWithLineNumbers_FullRange_Properties(t *testing.T) {
	rapid.Check(t, testFormatWithLineNumbers_FullRange_Properties)
}

func FuzzFormatWithLineNumbers_FullRange_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testFormatWithLineNumbers_FullRange_Properties))
}

// =============================================================================
// Property: FormatWithLineNumbers - range [start, end] returns end-start+1 lines
// =============================================================================

func testFormatWithLineNumbers_SubRange_Properties(t *rapid.T) {
	// Generate content with at least 3 lines for meaningful sub-ranges
	numLines := rapid.IntRange(3, 20).Draw(t, "numLines")
	lines := make([]string, numLines)
	for i := 0; i < numLines; i++ {
		lines[i] = rapid.StringMatching(`[A-Za-z0-9 ]{1,40}`).Draw(t, "line")
	}
	content := strings.Join(lines, "\n")

	start := rapid.IntRange(1, numLines).Draw(t, "start")
	end := rapid.IntRange(start, numLines).Draw(t, "end")

	result, totalLines := FormatWithLineNumbers(content, start, end)

	// Property: total lines always reflects the full content
	if totalLines != numLines {
		t.Fatalf("Total lines mismatch: expected %d, got %d", numLines, totalLines)
	}

	// Property: output has exactly end-start+1 lines
	expectedOutputLines := end - start + 1
	outputLines := strings.Split(result, "\n")
	if len(outputLines) != expectedOutputLines {
		t.Fatalf("Expected %d output lines for range [%d, %d], got %d",
			expectedOutputLines, start, end, len(outputLines))
	}
}

func TestFormatWithLineNumbers_SubRange_Properties(t *testing.T) {
	rapid.Check(t, testFormatWithLineNumbers_SubRange_Properties)
}

func FuzzFormatWithLineNumbers_SubRange_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testFormatWithLineNumbers_SubRange_Properties))
}

// =============================================================================
// Property: FormatWithLineNumbers - empty content returns empty and 0
// =============================================================================

func testFormatWithLineNumbers_Empty_Properties(t *rapid.T) {
	start := rapid.IntRange(0, 10).Draw(t, "start")
	end := rapid.IntRange(-1, 10).Draw(t, "end")

	result, totalLines := FormatWithLineNumbers("", start, end)

	// Property: empty content returns empty string and 0 total
	if result != "" {
		t.Fatalf("Expected empty result for empty content, got %q", result)
	}
	if totalLines != 0 {
		t.Fatalf("Expected 0 total lines for empty content, got %d", totalLines)
	}
}

func TestFormatWithLineNumbers_Empty_Properties(t *testing.T) {
	rapid.Check(t, testFormatWithLineNumbers_Empty_Properties)
}

func FuzzFormatWithLineNumbers_Empty_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testFormatWithLineNumbers_Empty_Properties))
}
