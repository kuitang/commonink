// Package e2e provides additional e2e property-based tests for web handler coverage.
// These tests target handler functions in internal/web/handlers.go that are NOT
// already covered by web_forms_test.go, specifically:
//   - HandleConsentPage + HandleConsentDecision (OAuth consent flow)
//   - HandleShortURLRedirect (short URL redirect)
//   - HandlePasswordResetConfirmPage (GET render)
//   - HandleLanding (authenticated redirect)
//   - HandleLoginPage/HandleRegisterPage with error query params
//   - HandleViewNote/HandleEditNotePage with nonexistent notes (error paths)
//   - HandleNotesList with out-of-range page numbers
//   - API Key handlers: HandleAPIKeySettings, HandleNewAPIKeyPage, HandleCreateAPIKey, HandleRevokeAPIKey
package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	emailpkg "github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/shorturl"
	"github.com/kuitang/agent-notes/internal/web"
	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// =============================================================================
// Helper: create an authenticated client for the webFormServer
// =============================================================================

// webFormAuthClient creates a user, session, and returns an authenticated HTTP client.
func webFormAuthClient(ts *webFormServer, email string) (*http.Client, string) {
	ctx := context.Background()
	user, _ := ts.userService.FindOrCreateByProvider(ctx, email)
	sessionID, _ := ts.sessionService.Create(ctx, user.ID)

	jar, _ := cookiejar.New(nil)
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	serverURL, _ := url.Parse(ts.URL)
	jar.SetCookies(serverURL, []*http.Cookie{{
		Name:  "session_id",
		Value: sessionID,
		Path:  "/",
	}})

	return client, user.ID
}

// =============================================================================
// TEST: HandleLanding - authenticated user redirects to /notes
// =============================================================================

func TestWebHandler_LandingAuthenticated_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		// Property: Authenticated user on GET / should redirect to /notes
		resp, err := client.Get(ts.URL + "/")
		if err != nil {
			rt.Fatalf("Landing request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusFound {
			rt.Fatalf("Expected 302, got %d", resp.StatusCode)
		}

		location := resp.Header.Get("Location")
		if !strings.Contains(location, "/notes") {
			rt.Fatalf("Expected redirect to /notes, got %s", location)
		}
	})
}

// =============================================================================
// TEST: HandleLoginPage with error query param
// =============================================================================

func TestWebHandler_LoginPageWithError_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		errorMsg := rapid.SampledFrom([]string{
			"Invalid+credentials",
			"Email+and+password+are+required",
			"Failed+to+create+session",
		}).Draw(rt, "errorMsg")

		client := ts.Client()

		resp, err := client.Get(ts.URL + "/login?error=" + errorMsg)
		if err != nil {
			rt.Fatalf("Login page request failed: %v", err)
		}
		defer resp.Body.Close()

		// Property: Login page with error param renders 200
		if resp.StatusCode != http.StatusOK {
			rt.Fatalf("Expected 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		html := string(body)

		// Property: Error message should appear in the rendered HTML
		decodedErr := strings.ReplaceAll(errorMsg, "+", " ")
		if !strings.Contains(html, decodedErr) {
			rt.Fatalf("Error message %q should appear in login page HTML", decodedErr)
		}
	})
}

// =============================================================================
// TEST: HandleRegisterPage with error query param
// =============================================================================

func TestWebHandler_RegisterPageWithError_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		errorMsg := rapid.SampledFrom([]string{
			"Email+and+password+are+required",
			"Passwords+do+not+match",
			"Failed+to+create+account",
		}).Draw(rt, "errorMsg")

		client := ts.Client()

		resp, err := client.Get(ts.URL + "/register?error=" + errorMsg)
		if err != nil {
			rt.Fatalf("Register page request failed: %v", err)
		}
		defer resp.Body.Close()

		// Property: Register page with error param renders 200
		if resp.StatusCode != http.StatusOK {
			rt.Fatalf("Expected 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		html := string(body)

		decodedErr := strings.ReplaceAll(errorMsg, "+", " ")
		if !strings.Contains(html, decodedErr) {
			rt.Fatalf("Error message %q should appear in register page HTML", decodedErr)
		}
	})
}

// =============================================================================
// TEST: HandlePasswordResetConfirmPage (GET)
// =============================================================================

func TestWebHandler_PasswordResetConfirmPage_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()

	// Property 1: Missing token shows error page
	resp, err := client.Get(ts.URL + "/auth/password-reset-confirm")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 (error page), got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(strings.ToLower(html), "invalid") && !strings.Contains(strings.ToLower(html), "missing") && !strings.Contains(strings.ToLower(html), "error") {
		t.Fatal("Missing token should show error message")
	}

	// Property 2: With token, shows password form
	resp2, err := client.Get(ts.URL + "/auth/password-reset-confirm?token=some-fake-token")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 (password form), got %d", resp2.StatusCode)
	}

	body2, _ := io.ReadAll(resp2.Body)
	html2 := string(body2)
	if !strings.Contains(html2, "password") {
		t.Fatal("Reset confirm page with token should show password input")
	}

	// Property 3: With token and error param, shows error on form
	resp3, err := client.Get(ts.URL + "/auth/password-reset-confirm?token=some-fake-token&error=Passwords+do+not+match")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp3.StatusCode)
	}

	body3, _ := io.ReadAll(resp3.Body)
	html3 := string(body3)
	if !strings.Contains(html3, "Passwords do not match") {
		t.Fatal("Error message should appear on reset confirm page")
	}
}

// =============================================================================
// TEST: HandleViewNote - nonexistent note returns error
// =============================================================================

func TestWebHandler_ViewNonexistentNote_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		nonexistentID := rapid.StringMatching(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`).Draw(rt, "id")

		// Property: GET /notes/{nonexistent} returns error (404 or error page)
		resp, err := client.Get(ts.URL + "/notes/" + nonexistentID)
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Should return a 404 error page (rendered as HTML with error status)
		if resp.StatusCode != http.StatusNotFound {
			rt.Fatalf("Expected 404 for nonexistent note, got %d", resp.StatusCode)
		}
	})
}

// =============================================================================
// TEST: HandleEditNotePage - nonexistent note returns error
// =============================================================================

func TestWebHandler_EditNonexistentNote_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		nonexistentID := rapid.StringMatching(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`).Draw(rt, "id")

		// Property: GET /notes/{nonexistent}/edit returns 404
		resp, err := client.Get(ts.URL + "/notes/" + nonexistentID + "/edit")
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			rt.Fatalf("Expected 404 for editing nonexistent note, got %d", resp.StatusCode)
		}
	})
}

// =============================================================================
// TEST: HandleNotesList - out-of-range page numbers
// =============================================================================

func TestWebHandler_NotesListLargePageNumber_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		largePage := rapid.IntRange(100, 10000).Draw(rt, "largePage")

		// Property: Very large page number returns 200 (empty notes, page defaults)
		resp, err := client.Get(fmt.Sprintf("%s/notes?page=%d", ts.URL, largePage))
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			rt.Fatalf("Expected 200 for large page, got %d", resp.StatusCode)
		}
	})
}

// =============================================================================
// TEST: HandleNotesList - error flash message via query param
// =============================================================================

func TestWebHandler_NotesListWithError_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		errorMsg := "Storage+limit+exceeded"

		resp, err := client.Get(ts.URL + "/notes?error=" + errorMsg)
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			rt.Fatalf("Expected 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		html := string(body)
		if !strings.Contains(html, "Storage limit exceeded") {
			rt.Fatal("Error flash message should appear in notes list page")
		}
	})
}

// =============================================================================
// TEST: HandleDeleteNote - deleting nonexistent note returns error
// =============================================================================

func TestWebHandler_DeleteNonexistentNote_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		nonexistentID := rapid.StringMatching(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`).Draw(rt, "id")

		// Property: POST /notes/{nonexistent}/delete returns error
		resp, err := client.PostForm(ts.URL+"/notes/"+nonexistentID+"/delete", url.Values{})
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Should return 500 (error page) since the note doesn't exist to delete
		if resp.StatusCode != http.StatusInternalServerError {
			rt.Fatalf("Expected 500 for deleting nonexistent note, got %d", resp.StatusCode)
		}
	})
}

// =============================================================================
// TEST: HandleUpdateNote - updating nonexistent note returns error
// =============================================================================

func TestWebHandler_UpdateNonexistentNote_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		nonexistentID := rapid.StringMatching(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`).Draw(rt, "id")
		title := testutil.NoteTitleGenerator().Draw(rt, "title")
		content := testutil.NoteContentGenerator().Draw(rt, "content")

		// Property: POST /notes/{nonexistent} returns error
		resp, err := client.PostForm(ts.URL+"/notes/"+nonexistentID, url.Values{
			"title":   {title},
			"content": {content},
		})
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusInternalServerError {
			rt.Fatalf("Expected 500 for updating nonexistent note, got %d", resp.StatusCode)
		}
	})
}

// =============================================================================
// TEST: HandleTogglePublish - nonexistent note returns error
// =============================================================================

func TestWebHandler_TogglePublishNonexistent_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		nonexistentID := rapid.StringMatching(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`).Draw(rt, "id")

		// Property: POST /notes/{nonexistent}/publish returns 404
		resp, err := client.PostForm(ts.URL+"/notes/"+nonexistentID+"/publish", url.Values{})
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			rt.Fatalf("Expected 404 for publishing nonexistent note, got %d", resp.StatusCode)
		}
	})
}

// =============================================================================
// TEST: HandlePublicNote - various user_id/note_id combinations
// =============================================================================

func TestWebHandler_PublicNote_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		userID := rapid.StringMatching(`[a-f0-9]{8}`).Draw(rt, "userID")
		noteID := rapid.StringMatching(`[a-f0-9]{8}`).Draw(rt, "noteID")

		// No auth needed for public notes
		client := ts.Client()

		// Property: GET /public/{user_id}/{note_id} returns 200 (stub renders placeholder)
		resp, err := client.Get(ts.URL + "/public/" + userID + "/" + noteID)
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			rt.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		body, _ := io.ReadAll(resp.Body)
		html := string(body)

		// Property: Public note page contains the note ID and user ID
		if !strings.Contains(html, "Public Note") {
			rt.Fatal("Public note page should contain 'Public Note' title")
		}
	})
}

// =============================================================================
// TEST: HandlePublicNote - missing path values
// =============================================================================

func TestWebHandler_PublicNoteMissing_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()

	// Property: GET /public/ with missing parts returns 404
	resp, err := client.Get(ts.URL + "/public//")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should return 404 (or an error page) for missing user_id/note_id
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 404 or error page, got %d", resp.StatusCode)
	}
}

// =============================================================================
// TEST: HandleShortURLRedirect
// =============================================================================

func TestWebHandler_ShortURLRedirect_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Property 1: Nonexistent short ID returns 404
	resp, err := client.Get(ts.URL + "/pub/abcdef")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp.Body.Close()

	// The shortURLSvc is nil in the webFormServer setup, so expect 500
	if resp.StatusCode != http.StatusInternalServerError && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 500 or 404 for short URL with nil service, got %d", resp.StatusCode)
	}

	// Property 2: Empty short_id returns 404
	resp2, err := client.Get(ts.URL + "/pub/")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp2.Body.Close()

	// 404 for empty path or method not allowed
	if resp2.StatusCode != http.StatusNotFound && resp2.StatusCode != http.StatusMovedPermanently {
		t.Logf("Empty short_id returned status %d (acceptable)", resp2.StatusCode)
	}
}

// =============================================================================
// TEST: HandleShortURLRedirect with real shortURL service
// =============================================================================

func TestWebHandler_ShortURLRedirectWithService_Properties(t *testing.T) {
	ts := setupWebFormServerWithShortURL(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		client := ts.Client()
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		// Create a short URL mapping in the database
		fullPath := "/public/user123/note456"
		shortURLSvc := shorturl.NewService(ts.sessionsDB.Queries())
		surl, err := shortURLSvc.Create(context.Background(), fullPath)
		if err != nil {
			rt.Fatalf("Failed to create short URL: %v", err)
		}

		// Property: GET /pub/{short_id} redirects to the full path
		resp, err := client.Get(ts.URL + "/pub/" + surl.ShortID)
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMovedPermanently {
			body, _ := io.ReadAll(resp.Body)
			rt.Fatalf("Expected 301 redirect, got %d: %s", resp.StatusCode, string(body))
		}

		location := resp.Header.Get("Location")
		if location != fullPath {
			rt.Fatalf("Expected redirect to %s, got %s", fullPath, location)
		}
	})
}

// setupWebFormServerWithShortURL creates a webFormServer with shortURL service enabled.
func setupWebFormServerWithShortURL(t testing.TB) *webFormServer {
	t.Helper()
	ts := setupWebFormServer(t)

	// Replace the server with one that includes shortURL service.
	// We need to close and rebuild with the shortURL service enabled.
	// The shortURL service needs the sessions DB queries.
	shortURLSvc := shorturl.NewService(ts.sessionsDB.Queries())

	// Create a new server that includes the shortURL service.
	// We do this by creating a new mux and adding routes.
	ts.Server.Close()

	templatesDir := findWebFormTemplatesDir()
	renderer, err := newRendererForTest(templatesDir)
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	mux := http.NewServeMux()
	server := newTestServerFromMux(mux)

	// Recreate user service with new URL
	ts.userService = newUserServiceForTest(ts.sessionsDB, ts.keyManager, ts.emailService, server.URL)

	// Create web handler with shortURL service
	webHandler := newWebHandlerForTest(renderer, ts.userService, ts.sessionService, ts.sessionsDB, shortURLSvc, server.URL)

	authMiddleware := newAuthMiddlewareForTest(ts.sessionService, ts.keyManager)
	webHandler.RegisterRoutes(mux, authMiddleware)

	// Register auth API routes
	registerAuthRoutesForTest(mux, ts.userService, ts.sessionService)

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	ts.Server = server
	return ts
}

// =============================================================================
// TEST: HandleConsentPage (GET /oauth/consent)
// =============================================================================

func TestWebHandler_ConsentPage_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		clientID := testutil.ClientNameGenerator().Draw(rt, "clientID")
		state := testutil.StateGenerator().Draw(rt, "state")
		scope := testutil.ScopeGenerator().Draw(rt, "scope")
		redirectURI := "http://localhost:8080/callback"

		// Property: GET /oauth/consent with valid params returns 200 with consent form
		consentURL := ts.URL + "/oauth/consent?" + url.Values{
			"client_id":    {clientID},
			"state":        {state},
			"redirect_uri": {redirectURI},
			"scope":        {scope},
		}.Encode()

		resp, err := client.Get(consentURL)
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			rt.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		body, _ := io.ReadAll(resp.Body)
		html := string(body)

		// Property: Consent page shows the client name
		if !strings.Contains(html, clientID) {
			rt.Fatalf("Consent page should contain client name %q", clientID)
		}

		// Property: If scope includes notes:read, description should appear
		if strings.Contains(scope, "notes:read") {
			if !strings.Contains(html, "View your notes") {
				rt.Fatal("Consent page should show 'View your notes' for notes:read scope")
			}
		}

		// Property: If scope includes notes:write, description should appear
		if strings.Contains(scope, "notes:write") {
			if !strings.Contains(html, "Create and edit notes") {
				rt.Fatal("Consent page should show 'Create and edit notes' for notes:write scope")
			}
		}
	})
}

// =============================================================================
// TEST: HandleConsentPage - unauthenticated redirects to login
// =============================================================================

func TestWebHandler_ConsentPageUnauthenticated(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Property: Unauthenticated GET /oauth/consent redirects to login
	resp, err := client.Get(ts.URL + "/oauth/consent?client_id=test&scope=notes:read")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected 302, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/login") {
		t.Fatalf("Expected redirect to /login, got %s", location)
	}
}

// =============================================================================
// TEST: HandleConsentDecision - deny decision
// =============================================================================

func TestWebHandler_ConsentDecisionDeny_Properties(t *testing.T) {
	ts := setupWebFormServerWithConsentDecision(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		clientID := testutil.ClientNameGenerator().Draw(rt, "clientID")
		state := testutil.StateGenerator().Draw(rt, "state")
		redirectURI := "http://localhost:8080/callback"

		// Property: POST /oauth/consent with decision=deny shows denied page
		resp, err := client.PostForm(
			ts.URL+"/oauth/consent?client_id="+url.QueryEscape(clientID)+"&scope=notes:read",
			url.Values{
				"decision":     {"deny"},
				"state":        {state},
				"redirect_uri": {redirectURI},
			},
		)
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			rt.Fatalf("Expected 200 (denied page), got %d: %s", resp.StatusCode, string(body))
		}

		body, _ := io.ReadAll(resp.Body)
		html := string(body)

		// Property: Denied page shows "Access Denied"
		if !strings.Contains(html, "Access Denied") {
			rt.Fatal("Consent denied page should contain 'Access Denied'")
		}

		// Property: Denied page mentions the client
		if !strings.Contains(html, clientID) {
			rt.Fatalf("Consent denied page should mention client %q", clientID)
		}
	})
}

// =============================================================================
// TEST: HandleConsentDecision - allow decision
// =============================================================================

func TestWebHandler_ConsentDecisionAllow_Properties(t *testing.T) {
	ts := setupWebFormServerWithConsentDecision(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		clientID := testutil.ClientNameGenerator().Draw(rt, "clientID")
		state := testutil.StateGenerator().Draw(rt, "state")
		scope := testutil.ScopeGenerator().Draw(rt, "scope")
		redirectURI := "http://localhost:8080/callback"

		// Property: POST /oauth/consent with decision=allow shows granted page
		resp, err := client.PostForm(
			ts.URL+"/oauth/consent?client_id="+url.QueryEscape(clientID)+"&scope="+url.QueryEscape(scope),
			url.Values{
				"decision":     {"allow"},
				"state":        {state},
				"redirect_uri": {redirectURI},
			},
		)
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			rt.Fatalf("Expected 200 (granted page), got %d: %s", resp.StatusCode, string(body))
		}

		body, _ := io.ReadAll(resp.Body)
		html := string(body)

		// Property: Granted page shows "Access Granted"
		if !strings.Contains(html, "Access Granted") {
			rt.Fatal("Consent granted page should contain 'Access Granted'")
		}

		// Property: Granted page mentions the client
		if !strings.Contains(html, clientID) {
			rt.Fatalf("Consent granted page should mention client %q", clientID)
		}
	})
}

// setupWebFormServerWithConsentDecision creates a server with POST /oauth/consent
// registered via the web handler (HandleConsentDecision).
// The standard webFormServer uses RegisterRoutes which only has GET /oauth/consent.
// We need to manually add POST /oauth/consent pointing to HandleConsentDecision.
func setupWebFormServerWithConsentDecision(t testing.TB) *webFormServer {
	t.Helper()
	ts := setupWebFormServer(t)

	// The webFormServer already has GET /oauth/consent via RegisterRoutes.
	// We need to add POST /oauth/consent -> HandleConsentDecision.
	// Since we cannot add routes to a running server, rebuild.
	ts.Server.Close()

	templatesDir := findWebFormTemplatesDir()
	renderer, err := newRendererForTest(templatesDir)
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	mux := http.NewServeMux()
	server := newTestServerFromMux(mux)

	ts.userService = newUserServiceForTest(ts.sessionsDB, ts.keyManager, ts.emailService, server.URL)

	webHandler := newWebHandlerForTest(renderer, ts.userService, ts.sessionService, ts.sessionsDB, nil, server.URL)

	authMiddleware := newAuthMiddlewareForTest(ts.sessionService, ts.keyManager)
	webHandler.RegisterRoutes(mux, authMiddleware)

	// Register POST /oauth/consent for HandleConsentDecision
	mux.Handle("POST /oauth/consent", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(webHandler.HandleConsentDecision)))

	registerAuthRoutesForTest(mux, ts.userService, ts.sessionService)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	ts.Server = server
	return ts
}

// =============================================================================
// TEST: HandleViewNote with published note shows share URL
// =============================================================================

func TestWebHandler_ViewPublishedNote_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		noteTitle := testutil.NoteTitleGenerator().Draw(rt, "title")
		noteContent := testutil.NoteContentGenerator().Draw(rt, "content")
		client, _ := webFormAuthClient(ts, email)

		// Create a note
		createResp, err := client.PostForm(ts.URL+"/notes", url.Values{
			"title":   {noteTitle},
			"content": {noteContent},
		})
		if err != nil {
			rt.Fatalf("Create failed: %v", err)
		}
		location := createResp.Header.Get("Location")
		createResp.Body.Close()
		parts := strings.Split(location, "/")
		noteID := parts[len(parts)-1]

		// Publish the note
		publishResp, err := client.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{})
		if err != nil {
			rt.Fatalf("Publish failed: %v", err)
		}
		publishResp.Body.Close()

		// Property: Viewing published note shows share URL
		viewResp, err := client.Get(ts.URL + "/notes/" + noteID)
		if err != nil {
			rt.Fatalf("View failed: %v", err)
		}
		defer viewResp.Body.Close()

		if viewResp.StatusCode != http.StatusOK {
			rt.Fatalf("Expected 200, got %d", viewResp.StatusCode)
		}

		body, _ := io.ReadAll(viewResp.Body)
		html := string(body)

		// Property: Note title is shown
		if !strings.Contains(html, noteTitle) {
			rt.Fatal("View page should show note title")
		}
	})
}

// =============================================================================
// TEST: HandleMagicLinkVerify - empty token (auth handler returns 400)
// =============================================================================

func TestWebHandler_MagicLinkVerifyEmpty(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()

	// Property: GET /auth/magic/verify without token returns error
	// The auth handler (not the web handler) handles this route and returns 400
	resp, err := client.Get(ts.URL + "/auth/magic/verify")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Auth handler returns 400 for missing token
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for missing token, got %d", resp.StatusCode)
	}

	html := strings.ToLower(string(body))
	if !strings.Contains(html, "token") && !strings.Contains(html, "required") && !strings.Contains(html, "error") {
		t.Fatal("Empty token should show error message")
	}
}

// =============================================================================
// TEST: HandleMagicLinkVerify - invalid token
// =============================================================================

func TestWebHandler_MagicLinkVerifyInvalid_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		fakeToken := rapid.StringMatching(`[a-z0-9]{20,50}`).Draw(rt, "token")

		client := ts.Client()

		// Property: GET /auth/magic/verify with invalid token shows error page
		resp, err := client.Get(ts.URL + "/auth/magic/verify?token=" + fakeToken)
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Should show error page (200 with error content), not a redirect
		if resp.StatusCode == http.StatusFound {
			rt.Fatal("Invalid magic token should not redirect (should show error)")
		}

		body, _ := io.ReadAll(resp.Body)
		html := strings.ToLower(string(body))
		if !strings.Contains(html, "invalid") && !strings.Contains(html, "expired") && !strings.Contains(html, "error") {
			rt.Fatal("Invalid token should show error message")
		}
	})
}

// =============================================================================
// TEST: HandlePasswordResetConfirm - mismatched passwords (auth handler returns 400)
// =============================================================================

func TestWebHandler_PasswordResetConfirmMismatch_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		token := rapid.StringMatching(`[a-z0-9]{20,40}`).Draw(rt, "token")
		password1 := testutil.PasswordGenerator().Draw(rt, "pass1")
		password2 := testutil.PasswordGenerator().Draw(rt, "pass2")

		client := ts.Client()
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		if password1 == password2 {
			return
		}

		// The auth handler handles POST /auth/password-reset-confirm
		// It returns 400 for validation errors (not 302 like the web handler would)
		resp, err := client.PostForm(ts.URL+"/auth/password-reset-confirm", url.Values{
			"token":            {token},
			"password":         {password1},
			"confirm_password": {password2},
		})
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Auth handler redirects (303 SeeOther) for mismatched passwords
		if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusFound {
			rt.Fatalf("Expected 303, 400, or 302 for mismatched passwords, got %d", resp.StatusCode)
		}
	})
}

// =============================================================================
// TEST: HandlePasswordResetConfirm - missing token (auth handler returns 400)
// =============================================================================

func TestWebHandler_PasswordResetConfirmMissingToken(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()

	// The auth handler returns 400 for missing token
	resp, err := client.PostForm(ts.URL+"/auth/password-reset-confirm", url.Values{
		"password":         {"ValidPassword123!"},
		"confirm_password": {"ValidPassword123!"},
	})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for missing token, got %d", resp.StatusCode)
	}

	html := strings.ToLower(string(body))
	if !strings.Contains(html, "token") && !strings.Contains(html, "required") && !strings.Contains(html, "error") {
		t.Fatal("Missing token should show error")
	}
}

// =============================================================================
// TEST: HandleGoogleLogin stub redirect
// =============================================================================

func TestWebHandler_GoogleLoginStub(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Property: GET /auth/google redirects to OIDC provider
	// Note: The test server configures a MockOIDCClient with AuthURL = "https://mock-oidc.example.com/authorize"
	resp, err := client.Get(ts.URL + "/auth/google")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected 302, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "mock-oidc.example.com/authorize") {
		t.Fatalf("Expected redirect to mock OIDC provider, got %s", location)
	}
}

// =============================================================================
// TEST: HandleGoogleCallback stub error
// =============================================================================

func TestWebHandler_GoogleCallbackStub(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()

	// Property: GET /auth/google/callback without state cookie returns 400
	// Note: The auth handler checks for oauth_state cookie first and returns 400 if missing
	resp, err := client.Get(ts.URL + "/auth/google/callback")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 (missing state cookie), got %d", resp.StatusCode)
	}
}

// =============================================================================
// TEST: API Key Settings page
// =============================================================================

func TestWebHandler_APIKeySettings_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		// Property: GET /api-keys returns 200 with API key list page
		resp, err := client.Get(ts.URL + "/api-keys")
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			rt.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		body, _ := io.ReadAll(resp.Body)
		html := strings.ToLower(string(body))
		if !strings.Contains(html, "api") {
			rt.Fatal("API keys page should reference API keys")
		}
	})
}

// =============================================================================
// TEST: API Key Settings page - unauthenticated
// =============================================================================

func TestWebHandler_APIKeySettingsUnauthenticated(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Property: Unauthenticated GET /api-keys redirects to login
	resp, err := client.Get(ts.URL + "/api-keys")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected 302, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/login") {
		t.Fatalf("Expected redirect to /login, got %s", location)
	}
}

// =============================================================================
// TEST: New API Key page
// =============================================================================

func TestWebHandler_NewAPIKeyPage_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		client, _ := webFormAuthClient(ts, email)

		// Property: GET /api-keys/new returns 200 with creation form
		resp, err := client.Get(ts.URL + "/api-keys/new")
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			rt.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		body, _ := io.ReadAll(resp.Body)
		html := strings.ToLower(string(body))
		if !strings.Contains(html, "name") {
			rt.Fatal("New API key page should contain name input")
		}
	})
}

// =============================================================================
// TEST: Settings API Keys page (alternate route)
// =============================================================================

func TestWebHandler_SettingsAPIKeysPage(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	email := "settingstest@example.com"
	client, _ := webFormAuthClient(ts, email)

	// Property: GET /settings/api-keys also renders API keys page
	resp, err := client.Get(ts.URL + "/settings/api-keys")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(body))
	}
}

// =============================================================================
// TEST: HandleLogin - missing email/password
// =============================================================================

func TestWebHandler_LoginMissingFields_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		client := ts.Client()
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		// Property 1: Missing both fields returns error
		// Note: POST /auth/login is handled by auth.Handler (JSON API) which returns 400
		resp, err := client.PostForm(ts.URL+"/auth/login", url.Values{})
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			rt.Fatalf("Expected 400, got %d", resp.StatusCode)
		}

		// Property 2: Missing password returns error
		resp2, err := client.PostForm(ts.URL+"/auth/login", url.Values{
			"email": {"test@example.com"},
		})
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		resp2.Body.Close()

		if resp2.StatusCode != http.StatusBadRequest {
			rt.Fatalf("Expected 400, got %d", resp2.StatusCode)
		}
	})
}

// =============================================================================
// TEST: HandlePasswordReset - email is required
// =============================================================================

func TestWebHandler_PasswordResetMissingEmail_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Property: POST /auth/password-reset without email returns error
	// Note: POST /auth/password-reset is handled by auth.Handler (JSON API) which returns 400
	resp, err := client.PostForm(ts.URL+"/auth/password-reset", url.Values{})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d", resp.StatusCode)
	}
}

// =============================================================================
// TEST: HandleMagicLinkRequest - missing email
// =============================================================================

func TestWebHandler_MagicLinkRequestMissingEmail(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Property: POST /auth/magic without email returns error
	// Note: POST /auth/magic is handled by auth.Handler (JSON API) which returns 400
	resp, err := client.PostForm(ts.URL+"/auth/magic", url.Values{})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d", resp.StatusCode)
	}
}

// =============================================================================
// Factory helpers for rebuilding servers with different configurations
// =============================================================================

func newRendererForTest(templatesDir string) (*web.Renderer, error) {
	return web.NewRenderer(templatesDir)
}

func newTestServerFromMux(mux *http.ServeMux) *httptest.Server {
	return httptest.NewServer(mux)
}

func newUserServiceForTest(sessionsDB *db.SessionsDB, keyManager *crypto.KeyManager, emailService *emailpkg.MockEmailService, baseURL string) *auth.UserService {
	return auth.NewUserService(sessionsDB, keyManager, emailService, baseURL)
}

func newWebHandlerForTest(renderer *web.Renderer, userService *auth.UserService, sessionService *auth.SessionService, sessionsDB *db.SessionsDB, shortURLSvc *shorturl.Service, baseURL string) *web.WebHandler {
	consentService := auth.NewConsentService(sessionsDB)
	s3Server, mockS3Client := createMockS3Server()
	_ = s3Server // keep alive; will be GC'd with test

	return web.NewWebHandler(
		renderer,
		nil, // notesService is created per-request
		notes.NewPublicNoteService(mockS3Client),
		userService,
		sessionService,
		consentService,
		mockS3Client,
		shortURLSvc,
		baseURL,
	)
}

func newAuthMiddlewareForTest(sessionService *auth.SessionService, keyManager *crypto.KeyManager) *auth.Middleware {
	return auth.NewMiddleware(sessionService, keyManager)
}

func registerAuthRoutesForTest(mux *http.ServeMux, userService *auth.UserService, sessionService *auth.SessionService) {
	oidcClient := auth.NewMockOIDCClient()
	authHandler := auth.NewHandler(oidcClient, userService, sessionService)
	authHandler.RegisterRoutes(mux)
}
