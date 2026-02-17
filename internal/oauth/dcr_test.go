package oauth

import (
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func drawHost(t *rapid.T, key string) string {
	label := rapid.StringMatching("[a-z][a-z0-9-]{2,15}").Draw(t, key+"_label")
	return fmt.Sprintf("%s.example.test", label)
}

func drawPath(t *rapid.T, key string) string {
	return rapid.SampledFrom([]string{
		"",
		"/callback",
		"/oauth/callback",
		"/cb/v1",
	}).Draw(t, key+"_path")
}

func drawHTTPSRedirectURI(t *rapid.T, key string) string {
	host := drawHost(t, key)
	path := drawPath(t, key)
	return "https://" + host + path
}

func TestValidateRedirectURI_HTTPSAccepted_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		redirectURI := drawHTTPSRedirectURI(rt, "redirect_uri")
		if err := validateRedirectURI(redirectURI); err != nil {
			rt.Fatalf("expected valid https redirect URI, got error: %v (uri=%q)", err, redirectURI)
		}
	})
}

func TestValidateRedirectURI_HTTPRejected_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		host := drawHost(rt, "host")
		path := drawPath(rt, "path")
		redirectURI := "http://" + host + path

		err := validateRedirectURI(redirectURI)
		if err == nil {
			rt.Fatalf("expected http redirect URI to be rejected: %q", redirectURI)
		}
		if !strings.Contains(err.Error(), "scheme must be https") {
			rt.Fatalf("expected https scheme error, got: %v", err)
		}
	})
}

func TestValidateRedirectURI_FragmentRejected_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		host := drawHost(rt, "host")
		path := drawPath(rt, "path")
		fragment := rapid.StringMatching("[a-z0-9]{1,12}").Draw(rt, "fragment")
		redirectURI := "https://" + host + path + "#" + fragment

		err := validateRedirectURI(redirectURI)
		if err == nil {
			rt.Fatalf("expected fragment to be rejected: %q", redirectURI)
		}
		if !strings.Contains(err.Error(), "must not include fragment") {
			rt.Fatalf("expected fragment error, got: %v", err)
		}
	})
}

func TestValidateRedirectURIs_MixedListRejected_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		valid := drawHTTPSRedirectURI(rt, "valid")
		host := drawHost(rt, "invalid_host")
		invalid := "http://" + host + "/callback"

		err := validateRedirectURIs([]string{valid, invalid})
		if err == nil {
			rt.Fatalf("expected mixed redirect URI list to be rejected: valid=%q invalid=%q", valid, invalid)
		}
	})
}
