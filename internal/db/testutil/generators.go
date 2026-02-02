// Package testutil provides shared test utilities and generators for property-based testing.
// All string generators are intentionally aggressive to catch edge cases.
package testutil

import (
	"pgregory.net/rapid"
)

// ArbitraryString generates truly arbitrary strings including:
// - Empty strings
// - Null bytes
// - Unicode (CJK, Arabic, emoji)
// - Control characters
// - SQL injection attempts
// - FTS5 special syntax
// - Very long strings
func ArbitraryString() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.String(),                              // Truly arbitrary (rapid's default)
		rapid.Just(""),                              // Empty string
		rapid.Just("\x00"),                          // Single null byte
		rapid.Just("test\x00test"),                  // Embedded null
		rapid.Just("\x00\x00\x00"),                  // Multiple nulls
		rapid.StringMatching(`[a-zA-Z0-9 ]{0,100}`), // Normal alphanumeric
		rapid.StringMatching(`[\x00-\x1F]{1,10}`),   // Control characters
		arbitrarySQLInjection(),                     // SQL injection attempts
		arbitraryFTS5Syntax(),                       // FTS5 special syntax
		arbitraryUnicode(),                          // Unicode edge cases
		arbitraryWhitespace(),                       // Whitespace variations
		arbitraryLongString(),                       // Long strings
	)
}

// ArbitraryNonEmptyString is like ArbitraryString but never empty.
// Use for fields that require non-empty values (like note titles).
func ArbitraryNonEmptyString() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.StringN(1, 100, 200), // Guaranteed 1-100 chars
		rapid.Just("\x00"),         // Null byte is non-empty
		rapid.Just("test\x00test"),
		rapid.StringMatching(`[a-zA-Z0-9 ]{1,100}`),
		arbitrarySQLInjection(),
		arbitraryFTS5Syntax(),
		arbitraryUnicode(),
		arbitraryLongString(),
	)
}

// ArbitrarySearchQuery generates strings suitable for FTS5 search testing.
// Includes all the edge cases that could break search.
func ArbitrarySearchQuery() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.String(),
		rapid.Just(""),
		rapid.Just("\x00"),
		rapid.Just("test\x00test"),
		arbitrarySQLInjection(),
		arbitraryFTS5Syntax(),
		arbitraryUnicode(),
		arbitraryWhitespace(),
	)
}

// ArbitraryNoteTitle generates titles for property testing.
// Non-empty but otherwise arbitrary.
func ArbitraryNoteTitle() *rapid.Generator[string] {
	return ArbitraryNonEmptyString()
}

// ArbitraryNoteContent generates content for property testing.
// Can be empty or contain any characters.
func ArbitraryNoteContent() *rapid.Generator[string] {
	return ArbitraryString()
}

// arbitrarySQLInjection generates common SQL injection patterns
func arbitrarySQLInjection() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{
		`' OR 1=1 --`,
		`'; DROP TABLE notes; --`,
		`" OR "1"="1`,
		`1; SELECT * FROM users`,
		`admin'--`,
		`' UNION SELECT * FROM users --`,
		`'; TRUNCATE TABLE notes; --`,
		`' OR ''='`,
		`1' AND '1'='1`,
		`%27%20OR%20%271%27%3D%271`,
		`<script>alert('xss')</script>`,
		`' OR 1=1#`,
		`admin' #`,
		`' AND 1=0 UNION SELECT 1,2,3 --`,
	})
}

// arbitraryFTS5Syntax generates FTS5 special syntax that could cause parsing errors
func arbitraryFTS5Syntax() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{
		`"`,
		`""`,
		`"""`,
		`test"`,
		`"test`,
		`"test"`,
		`""test""`,
		`AND`,
		`OR`,
		`NOT`,
		`NEAR`,
		`NEAR/5`,
		`*`,
		`test*`,
		`^test`,
		`col:value`,
		`(test)`,
		`(test`,
		`test)`,
		`-test`,
		`+test`,
		`test AND OR`,
		`test NEAR/10 other`,
		`*test*`,
		`"phrase query"`,
		`"unterminated phrase`,
		`col1:test col2:other`,
	})
}

// arbitraryUnicode generates various Unicode edge cases
func arbitraryUnicode() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{
		"日本語",                            // Japanese
		"中文测试",                           // Chinese
		"العربية",                        // Arabic (RTL)
		"עברית",                          // Hebrew (RTL)
		"🔥🎉💻🚀",                           // Emoji
		"emoji🔥in🎉middle",                // Mixed emoji
		"Ñoño",                           // Spanish
		"Zürich",                         // German umlaut
		"Москва",                         // Cyrillic
		"Ελληνικά",                       // Greek
		"한국어",                            // Korean
		"\u200B",                         // Zero-width space
		"\u200C",                         // Zero-width non-joiner
		"\u200D",                         // Zero-width joiner
		"\uFEFF",                         // BOM
		"a\u0300",                        // Combining diacritical
		"\u202E" + "reversed" + "\u202C", // RTL override
		"🧑‍💻",                            // ZWJ sequence (person + computer)
		"👨‍👩‍👧‍👦",                        // Family emoji (ZWJ sequence)
		"\U0001F1FA\U0001F1F8",           // Flag emoji (regional indicators)
		"é" + "\u0301",                   // Double combining
		"test\u00A0space",                // Non-breaking space
		"line\u2028separator",            // Line separator
		"para\u2029separator",            // Paragraph separator
		"\U0001F600",                     // Grinning face emoji
		"math∑∏∫",                        // Mathematical symbols
	})
}

// arbitraryWhitespace generates various whitespace patterns
func arbitraryWhitespace() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{
		" ",
		"  ",
		"   ",
		"\t",
		"\n",
		"\r",
		"\r\n",
		" \t \n ",
		"\t\t\t",
		"\n\n\n",
		"  test  ",
		"\ttest\t",
		"line1\nline2",
		"line1\r\nline2",
		"\u00A0", // Non-breaking space
		"\u2003", // Em space
		"\u2002", // En space
		"\u3000", // Ideographic space
		"\v",     // Vertical tab
		"\f",     // Form feed
	})
}

// arbitraryLongString generates very long strings to test limits
func arbitraryLongString() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		length := rapid.SampledFrom([]int{
			1000,    // 1KB
			10000,   // 10KB
			100000,  // 100KB
			500000,  // 500KB
			1000000, // 1MB (at limit)
		}).Draw(t, "length")

		// Generate a repeating pattern
		base := "abcdefghij"
		result := make([]byte, length)
		for i := 0; i < length; i++ {
			result[i] = base[i%len(base)]
		}
		return string(result)
	})
}

// ValidUserID generates valid user IDs (for tests that need valid DB paths).
// User IDs must be safe for filesystem paths.
func ValidUserID() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		prefix := rapid.StringMatching("[a-z]{1,10}").Draw(t, "prefix")
		suffix := rapid.StringMatching("[0-9]{1,5}").Draw(t, "suffix")
		return prefix + "-" + suffix
	})
}

// ArbitraryUserID generates arbitrary user IDs including invalid ones.
// Use for testing error handling.
func ArbitraryUserID() *rapid.Generator[string] {
	return rapid.OneOf(
		ValidUserID(),
		rapid.Just(""),           // Empty
		rapid.Just("\x00"),       // Null byte
		rapid.Just("../escape"),  // Path traversal
		rapid.Just("/root"),      // Absolute path
		rapid.Just("a/b"),        // Slash in name
		rapid.Just("user\x00id"), // Embedded null
		ArbitraryString(),        // Fully arbitrary
	)
}
