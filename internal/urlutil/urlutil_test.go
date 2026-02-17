package urlutil

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func drawHost(rt *rapid.T, label string) string {
	sub := rapid.StringMatching(`[a-z0-9](?:[a-z0-9-]{0,8}[a-z0-9])?`).Draw(rt, label+"_sub")
	root := rapid.StringMatching(`[a-z0-9](?:[a-z0-9-]{0,8}[a-z0-9])?`).Draw(rt, label+"_root")
	tld := rapid.StringMatching(`[a-z]{2,10}`).Draw(rt, label+"_tld")
	host := fmt.Sprintf("%s.%s.%s", sub, root, tld)
	if rapid.Bool().Draw(rt, label+"_hasPort") {
		host = fmt.Sprintf("%s:%d", host, rapid.IntRange(1, 65535).Draw(rt, label+"_port"))
	}
	return host
}

func drawOrigin(rt *rapid.T, label string) string {
	scheme := rapid.SampledFrom([]string{"http", "https"}).Draw(rt, label+"_scheme")
	return scheme + "://" + drawHost(rt, label+"_host")
}

func drawAbsoluteURL(rt *rapid.T, label string) string {
	u, err := url.Parse(drawOrigin(rt, label+"_origin"))
	if err != nil {
		rt.Fatalf("failed to parse generated origin: %v", err)
	}

	segments := rapid.IntRange(0, 4).Draw(rt, label+"_segments")
	path := ""
	for i := 0; i < segments; i++ {
		seg := rapid.StringMatching(`[A-Za-z0-9._~!$&()*+,;=:@-]{1,12}`).Draw(rt, fmt.Sprintf("%s_seg_%d", label, i))
		path += "/" + seg
	}
	if path == "" {
		path = "/"
	}
	u.Path = path

	params := url.Values{}
	pairs := rapid.IntRange(0, 3).Draw(rt, label+"_pairs")
	for i := 0; i < pairs; i++ {
		key := rapid.StringMatching(`[a-z]{1,8}`).Draw(rt, fmt.Sprintf("%s_key_%d", label, i))
		val := rapid.StringMatching(`[A-Za-z0-9._~-]{0,12}`).Draw(rt, fmt.Sprintf("%s_val_%d", label, i))
		params.Add(key, val)
	}
	u.RawQuery = params.Encode()

	if rapid.Bool().Draw(rt, label+"_hasFrag") {
		u.Fragment = rapid.StringMatching(`[A-Za-z0-9._~-]{1,12}`).Draw(rt, label+"_frag")
	}

	return u.String()
}

func TestOriginFromRequest_UsesRequestOrigin(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		scheme := rapid.SampledFrom([]string{"http", "https"}).Draw(rt, "scheme")
		host := fmt.Sprintf(
			"%s.%s:%d",
			rapid.StringMatching(`[a-z]{3,12}`).Draw(rt, "host"),
			rapid.StringMatching(`[a-z]{2,8}`).Draw(rt, "tld"),
			rapid.IntRange(1024, 9999).Draw(rt, "port"),
		)
		path := "/" + rapid.StringMatching(`[a-z]{1,8}`).Draw(rt, "path")
		req := httptest.NewRequest(http.MethodGet, scheme+"://"+host+path, nil)
		req.Header.Set("X-Forwarded-Proto", scheme)

		got := OriginFromRequest(req, "https://fallback.example.test")
		if got != fmt.Sprintf("%s://%s", scheme, host) {
			rt.Fatalf("unexpected origin: got=%s want=%s://%s", got, scheme, host)
		}
	})
}

func TestOriginFromRequest_ForwardsInvalidProtoThenFallsBack(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		req := httptest.NewRequest(http.MethodGet, "http://preview.example.test/callback", nil)
		req.Header.Set("X-Forwarded-Proto", rapid.SampledFrom([]string{"ftp", "wss", "chrome://", "ws"}).Draw(rt, "proto"))
		req.Host = "preview.example.test"
		got := OriginFromRequest(req, "https://fallback.example.test:8080")
		if got != "http://preview.example.test" {
			rt.Fatalf("unexpected fallback for invalid forwarded proto: got=%s", got)
		}
	})
}

func TestOriginFromRequest_UsesFallbackWhenHostMissing(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		fallback := rapid.SampledFrom([]string{
			"https://fallback.one",
			"https://fallback.two:8080",
		}).Draw(rt, "fallback")
		req := httptest.NewRequest(http.MethodGet, "https://preview.example.test/callback", nil)
		req.Host = ""
		got := OriginFromRequest(req, fallback)
		if got != strings.TrimRight(fallback, "/") {
			rt.Fatalf("expected fallback origin, got=%s want=%s", got, strings.TrimRight(fallback, "/"))
		}
	})
}

func TestOriginFromRequest_ArbitraryValidURLs(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		requestURL := drawAbsoluteURL(rt, "request")
		parsed, err := url.Parse(requestURL)
		if err != nil {
			rt.Fatalf("generated request URL should parse: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, requestURL, nil)
		req.Host = parsed.Host
		req.Header.Set("X-Forwarded-Proto", parsed.Scheme)

		got := OriginFromRequest(req, drawOrigin(rt, "fallback"))
		want := parsed.Scheme + "://" + parsed.Host
		if got != want {
			rt.Fatalf("unexpected origin: got=%s want=%s", got, want)
		}

		originParsed, err := url.Parse(got)
		if err != nil {
			rt.Fatalf("origin should parse: %v", err)
		}
		if originParsed.Scheme == "" || originParsed.Host == "" {
			rt.Fatalf("origin should have scheme and host: %s", got)
		}
	})
}

func TestBuildAbsolute_GeneratesExpectedURLs(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		base := fmt.Sprintf(
			"https://%s.%s",
			rapid.StringMatching(`[a-z]{3,12}`).Draw(rt, "baseHost"),
			rapid.StringMatching(`[a-z]{2,8}`).Draw(rt, "baseTld"),
		)
		if rapid.Bool().Draw(rt, "baseHasSlash") {
			base += "/"
		}

		pathKind := rapid.IntRange(0, 3).Draw(rt, "pathKind")
		var path string
		switch pathKind {
		case 0:
			path = ""
		case 1:
			path = "/" + rapid.StringMatching(`[a-z]{1,12}`).Draw(rt, "relativePath")
		case 2:
			path = "notes/" + rapid.StringMatching(`[a-z]{1,12}`).Draw(rt, "nestedPath")
		case 3:
			path = fmt.Sprintf(
				"https://%s.%s/callback",
				rapid.StringMatching(`[a-z]{3,10}`).Draw(rt, "absoluteHost"),
				rapid.StringMatching(`[a-z]{2,6}`).Draw(rt, "absoluteTld"),
			)
		}

		got := BuildAbsolute(base, path)
		var want string
		switch {
		case path == "":
			want = strings.TrimRight(base, "/")
		case strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://"):
			want = path
		case strings.HasPrefix(path, "/"):
			want = strings.TrimRight(base, "/") + path
		default:
			want = strings.TrimRight(base, "/") + "/" + path
		}

		if got != want {
			rt.Fatalf("BuildAbsolute mismatch: got=%s want=%s", got, want)
		}
		parsed, err := url.Parse(got)
		if err != nil {
			rt.Fatalf("BuildAbsolute returned invalid URL %s: %v", got, err)
		}
		if parsed.Scheme == "" && pathKind != 3 {
			rt.Fatalf("expected absolute URL with scheme, got=%s", got)
		}
	})
}

func TestBuildAbsolute_ArbitraryValidOriginsAndPaths(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		base := drawOrigin(rt, "base")
		if rapid.Bool().Draw(rt, "baseSlash") {
			base += "/"
		}

		var path string
		switch rapid.IntRange(0, 3).Draw(rt, "pathType") {
		case 0:
			path = "/" + rapid.StringMatching(`[A-Za-z0-9._~!$&()*+,;=:@-]{1,16}`).Draw(rt, "absPath")
		case 1:
			path = rapid.StringMatching(`[A-Za-z0-9._~!$&()*+,;=:@-]{1,16}`).Draw(rt, "relPath")
		case 2:
			path = drawAbsoluteURL(rt, "absolutePath")
		default:
			path = ""
		}

		got := BuildAbsolute(base, path)
		parsed, err := url.Parse(got)
		if err != nil {
			rt.Fatalf("BuildAbsolute result should parse: %v", err)
		}

		switch {
		case strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://"):
			if got != path {
				rt.Fatalf("absolute path should pass through unchanged: got=%s want=%s", got, path)
			}
		case path == "":
			if got != strings.TrimRight(base, "/") {
				rt.Fatalf("empty path should normalize base: got=%s want=%s", got, strings.TrimRight(base, "/"))
			}
		default:
			if parsed.Scheme == "" || parsed.Host == "" {
				rt.Fatalf("expected absolute URL for non-absolute path: %s", got)
			}
		}
	})
}
