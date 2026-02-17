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

		got := OriginFromRequest(req, "https://fallback.localhost")
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
		got := OriginFromRequest(req, "https://fallback.localhost:8080")
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
