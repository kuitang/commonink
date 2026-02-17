package urlutil

import (
	"net/http"
	"strings"
)

// OriginFromRequest returns the request origin (scheme + host) with the provided
// fallback when request host or scheme cannot be resolved.
func OriginFromRequest(r *http.Request, fallback string) string {
	base := normalizeBaseURL(fallback)
	if r == nil {
		return base
	}

	scheme := requestScheme(r)
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return base
	}

	return normalizeBaseURL(scheme + "://" + host)
}

// BuildAbsolute builds an absolute URL from a base origin and a path.
func BuildAbsolute(base, path string) string {
	base = normalizeBaseURL(base)
	if path == "" {
		return base
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return base + path
	}
	return base + "/" + path
}

func requestScheme(r *http.Request) string {
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto != "" {
		if comma := strings.Index(proto, ","); comma >= 0 {
			proto = strings.TrimSpace(proto[:comma])
		}
		if proto == "http" || proto == "https" {
			return proto
		}
	}

	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func normalizeBaseURL(base string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/")
}
