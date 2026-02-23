package web

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	emailpkg "github.com/kuitang/agent-notes/internal/email"
)

func testTemplatesDir(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"../../web/templates",
		"../web/templates",
		"./web/templates",
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Fatalf("unable to locate templates directory from test working directory")
	return ""
}

func makeAuthHarness(t *testing.T) (*auth.Middleware, *auth.UserService, *auth.SessionService, func()) {
	t.Helper()

	db.ResetForTesting()
	db.DataDirectory = t.TempDir()

	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("open sessions db failed: %v", err)
	}
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("master key generation failed: %v", err)
	}
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)
	emailService := emailpkg.NewMockEmailService()
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, "http://example.test", auth.FakeInsecureHasher{})
	sessionService := auth.NewSessionService(sessionsDB)
	middleware := auth.NewMiddleware(sessionService, keyManager)

	cleanup := func() {
		db.CloseAll()
	}
	return middleware, userService, sessionService, cleanup
}

func TestHandleAppDetail_UnauthenticatedRedirectsToLogin(t *testing.T) {
	t.Parallel()
	handler := &WebHandler{}

	req := httptest.NewRequest(http.MethodGet, "/apps/demo", nil)
	req.SetPathValue("name", "demo")
	resp := httptest.NewRecorder()

	handler.HandleAppDetail(resp, req)
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", resp.Code)
	}
	if got := resp.Header().Get("Location"); got != "/login" {
		t.Fatalf("unexpected redirect location: got=%q want=%q", got, "/login")
	}
}

func TestHandleAppDetail_EmptyNameRedirectsToNotes(t *testing.T) {
	authMW, userService, sessionService, cleanup := makeAuthHarness(t)
	defer cleanup()

	user, err := userService.FindOrCreateByProvider(context.Background(), "app-detail@example.com")
	if err != nil {
		t.Fatalf("FindOrCreateByProvider failed: %v", err)
	}
	sessionID, err := sessionService.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("session create failed: %v", err)
	}

	handler := &WebHandler{}
	wrapped := authMW.RequireAuthWithRedirect(http.HandlerFunc(handler.HandleAppDetail))

	req := httptest.NewRequest(http.MethodGet, "/apps/", nil)
	req.SetPathValue("name", "   ")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID, Path: "/"})
	resp := httptest.NewRecorder()

	wrapped.ServeHTTP(resp, req)
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", resp.Code)
	}
	if got := resp.Header().Get("Location"); got != "/notes" {
		t.Fatalf("unexpected redirect location: got=%q want=%q", got, "/notes")
	}
}

func TestHandleAppDetail_AppNotFoundRenders404(t *testing.T) {
	authMW, userService, sessionService, cleanup := makeAuthHarness(t)
	defer cleanup()

	user, err := userService.FindOrCreateByProvider(context.Background(), "missing-app@example.com")
	if err != nil {
		t.Fatalf("FindOrCreateByProvider failed: %v", err)
	}
	sessionID, err := sessionService.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("session create failed: %v", err)
	}

	renderer, err := NewRenderer(testTemplatesDir(t))
	if err != nil {
		t.Fatalf("renderer init failed: %v", err)
	}
	handler := &WebHandler{
		renderer: renderer,
	}
	wrapped := authMW.RequireAuthWithRedirect(http.HandlerFunc(handler.HandleAppDetail))

	req := httptest.NewRequest(http.MethodGet, "/apps/does-not-exist", nil)
	req.SetPathValue("name", "does-not-exist")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID, Path: "/"})
	resp := httptest.NewRecorder()

	wrapped.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%q", resp.Code, resp.Body.String())
	}
}
