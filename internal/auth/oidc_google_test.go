package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestGoogleOIDCClient_GetAuthURLIncludesStateAndRedirect(t *testing.T) {
	t.Parallel()
	client := &GoogleOIDCClient{
		oauthConfig: oauth2.Config{
			ClientID: "client-id-123",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://accounts.example.com/auth",
			},
			Scopes: []string{"openid", "email", "profile"},
		},
	}

	authURL := client.GetAuthURL("state-xyz", "https://app.example.com/auth/callback")
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL failed: %v", err)
	}
	q := parsed.Query()
	if q.Get("state") != "state-xyz" {
		t.Fatalf("state mismatch: got=%q", q.Get("state"))
	}
	if q.Get("redirect_uri") != "https://app.example.com/auth/callback" {
		t.Fatalf("redirect_uri mismatch: got=%q", q.Get("redirect_uri"))
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("scope should include openid, got=%q", q.Get("scope"))
	}
}

func TestGoogleOIDCClient_ExchangeCode_FailsOnTokenExchangeError(t *testing.T) {
	t.Parallel()
	client := &GoogleOIDCClient{
		oauthConfig: oauth2.Config{
			ClientID:     "client-id-123",
			ClientSecret: "secret-123",
			Endpoint: oauth2.Endpoint{
				TokenURL: "http://127.0.0.1:1/unreachable",
			},
		},
	}

	_, err := client.ExchangeCode(context.Background(), "bad-code", "https://app.example.com/callback")
	if err == nil {
		t.Fatal("expected exchange failure")
	}
	if !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("expected ErrCodeExchangeFailed, got %v", err)
	}
}

func TestGoogleOIDCClient_ExchangeCode_MissingIDToken(t *testing.T) {
	t.Parallel()
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok_123","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokenServer.Close()

	client := &GoogleOIDCClient{
		oauthConfig: oauth2.Config{
			ClientID:     "client-id-123",
			ClientSecret: "secret-123",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenServer.URL,
			},
		},
	}

	_, err := client.ExchangeCode(context.Background(), "code-123", "https://app.example.com/callback")
	if err == nil {
		t.Fatal("expected missing id_token error")
	}
	if !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("expected ErrCodeExchangeFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "missing id_token") {
		t.Fatalf("expected missing id_token details, got %v", err)
	}
}
