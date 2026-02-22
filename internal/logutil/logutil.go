package logutil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// IsSensitiveLogField returns true when a key likely contains sensitive data.
func IsSensitiveLogField(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "_", "")

	switch {
	case normalized == "authorization":
		return true
	case strings.Contains(normalized, "token"):
		return true
	case strings.Contains(normalized, "secret"):
		return true
	case strings.Contains(normalized, "password"):
		return true
	case strings.Contains(normalized, "apikey"):
		return true
	case strings.Contains(normalized, "cookie"):
		return true
	case strings.Contains(normalized, "auth"):
		return true
	default:
		return false
	}
}

// RedactHeaderValue redacts a header value when the key looks sensitive.
func RedactHeaderValue(key, value string) string {
	if IsSensitiveLogField(key) {
		return "[REDACTED]"
	}
	return value
}

// FormatHeadersForLog returns stable, redacted header text for logs.
func FormatHeadersForLog(headers http.Header) string {
	if len(headers) == 0 {
		return "{}"
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		values := headers.Values(k)
		if len(values) == 0 {
			parts = append(parts, fmt.Sprintf("%s=<empty>", strings.ToLower(k)))
			continue
		}

		redacted := make([]string, len(values))
		for i, v := range values {
			redacted[i] = RedactHeaderValue(k, v)
		}
		parts = append(parts, fmt.Sprintf("%s=%q", strings.ToLower(k), strings.Join(redacted, ", ")))
	}
	return strings.Join(parts, "; ")
}

// RedactBodyForLog redacts sensitive fields from JSON payloads; non-JSON bodies are returned as-is.
func RedactBodyForLog(contentType string, body []byte) string {
	text := string(body)
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return text
	}

	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return text
	}

	var redact func(v any)
	redact = func(v any) {
		switch typed := v.(type) {
		case map[string]any:
			for k, child := range typed {
				if IsSensitiveLogField(k) {
					typed[k] = "[REDACTED]"
					continue
				}
				redact(child)
			}
		case []any:
			for _, child := range typed {
				redact(child)
			}
		}
	}

	redact(payload)
	safeJSON, err := json.Marshal(payload)
	if err != nil {
		return text
	}
	return string(safeJSON)
}

// FormatBodyForLog truncates and redacts body text for safe logging.
func FormatBodyForLog(contentType string, body []byte, maxBytes int, truncated bool) string {
	if len(body) == 0 {
		return ""
	}
	textBytes := body
	if maxBytes > 0 && len(textBytes) > maxBytes {
		textBytes = textBytes[:maxBytes]
		truncated = true
	}
	text := RedactBodyForLog(contentType, textBytes)
	if truncated {
		return text + " [truncated]"
	}
	return text
}

// TruncateForLog returns a single-line truncated preview for unstructured values.
func TruncateForLog(value string, maxChars int) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	normalized := strings.ReplaceAll(trimmed, "\n", "\\n")
	if maxChars <= 0 || len(normalized) <= maxChars {
		return normalized
	}
	return normalized[:maxChars] + "... [truncated]"
}
