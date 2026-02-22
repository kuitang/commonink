package apps

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
	sprites "github.com/superfly/sprites-go"
	_ "pgregory.net/rapid"
)

// CRITICAL REGRESSION TEST:
// Property: when Sprite API returns a canonical sprite name different from the requested
// app name, we must persist and use the canonical sprite name for all subsequent Sprite API calls.
func TestCriticalRegression_CreatePersistsCanonicalSpriteAndTargetsCanonicalSprite(t *testing.T) {
	ctx := context.Background()
	desiredName := "doodle-calendar-poll"
	canonicalName := "doodle-calendar-poll-bfnrc"
	canonicalURL := "https://doodle-calendar-poll-bfnrc.sprites.app/"

	svc, mock, cleanup := newAppsServiceWithMockSpriteAPI(t, desiredName, canonicalName, canonicalURL)
	defer cleanup()

	createResult, err := svc.Create(ctx, []string{desiredName})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if !createResult.Created {
		t.Fatalf("Create returned Created=false: %+v", createResult)
	}

	meta, err := svc.getMetadata(ctx, desiredName)
	if err != nil {
		t.Fatalf("getMetadata failed: %v", err)
	}
	if meta.SpriteName != canonicalName {
		t.Fatalf("sprite_name not canonical: got=%q want=%q", meta.SpriteName, canonicalName)
	}

	writeResult, err := svc.WriteFiles(ctx, desiredName, []AppWriteFileInput{
		{Path: "server.py", Content: "print('ok')\n"},
	})
	if err != nil {
		t.Fatalf("WriteFiles failed: %v", err)
	}
	if writeResult.TotalFilesWritten != 1 {
		t.Fatalf("WriteFiles total files mismatch: got=%d want=1", writeResult.TotalFilesWritten)
	}

	readResult, err := svc.ReadFiles(ctx, desiredName, []string{"server.py"})
	if err != nil {
		t.Fatalf("ReadFiles failed: %v", err)
	}
	if len(readResult.Files) != 1 {
		t.Fatalf("ReadFiles file count mismatch: got=%d want=1", len(readResult.Files))
	}
	if readResult.Files[0].Path != "server.py" || readResult.Files[0].Content != "print('ok')\n" {
		t.Fatalf("ReadFiles content mismatch: got=%+v", readResult.Files[0])
	}

	deleteResult, err := svc.Delete(ctx, desiredName)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if !deleteResult.Deleted {
		t.Fatalf("Delete result mismatch: %+v", deleteResult)
	}

	// Property assertion: no Sprite API path call is allowed to target desiredName once canonical exists.
	for _, call := range mock.Calls() {
		parts := strings.SplitN(call, " ", 3)
		if len(parts) < 2 {
			continue
		}
		path := parts[1]
		if path == "/v1/sprites" {
			continue
		}
		if strings.HasPrefix(path, "/v1/sprites/") {
			target := strings.TrimPrefix(path, "/v1/sprites/")
			if idx := strings.IndexByte(target, '/'); idx >= 0 {
				target = target[:idx]
			}
			if target != canonicalName {
				t.Fatalf("unexpected sprite target in call %q: got=%q want=%q", call, target, canonicalName)
			}
		}
	}
}

// CRITICAL REGRESSION TEST:
// Property: if metadata sprite_name drifts from canonical Sprite identity, every Sprite-backed
// operation must fail fast with a descriptive error instead of silently targeting the wrong Sprite.
func TestCriticalRegression_AllSpriteOperationsFailOnSpriteBindingMismatch(t *testing.T) {
	ctx := context.Background()
	desiredName := "doodle-calendar-poll"
	canonicalName := "doodle-calendar-poll-bfnrc"
	canonicalURL := "https://doodle-calendar-poll-bfnrc.sprites.app/"

	svc, _, cleanup := newAppsServiceWithMockSpriteAPI(t, desiredName, canonicalName, canonicalURL)
	defer cleanup()

	now := time.Now().UTC().Unix()
	_, err := svc.userDB.DB().ExecContext(ctx, `
		INSERT INTO apps(name, sprite_name, public_url, status, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?)
	`, desiredName, desiredName, canonicalURL, "created", now, now)
	if err != nil {
		t.Fatalf("failed to seed metadata: %v", err)
	}

	assertBindingError := func(method string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s expected error but got nil", method)
		}
		want := fmt.Sprintf("failed to verify sprite %q", desiredName)
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%s error mismatch: got=%q want_substring=%q", method, err.Error(), want)
		}
	}

	_, err = svc.WriteFiles(ctx, desiredName, []AppWriteFileInput{{Path: "server.py", Content: "print('x')\n"}})
	assertBindingError("WriteFiles", err)

	_, err = svc.ReadFiles(ctx, desiredName, []string{"server.py"})
	assertBindingError("ReadFiles", err)

	_, err = svc.RunBash(ctx, desiredName, "echo ok", 1)
	assertBindingError("RunBash", err)

	_, err = svc.ListFiles(ctx, desiredName)
	assertBindingError("ListFiles", err)

	_, err = svc.TailLogs(ctx, desiredName, 10)
	assertBindingError("TailLogs", err)

	_, err = svc.Delete(ctx, desiredName)
	assertBindingError("Delete", err)
}

type mockSpriteAPI struct {
	desiredName   string
	canonicalName string
	canonicalURL  string

	mu    sync.Mutex
	files map[string][]byte
	calls []string
}

func (m *mockSpriteAPI) Calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *mockSpriteAPI) recordCall(r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
}

func (m *mockSpriteAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.recordCall(r)

	if r.URL.Path == "/v1/sprites" && r.Method == http.MethodPost {
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid create request", http.StatusBadRequest)
			return
		}
		if req.Name != m.desiredName {
			http.Error(w, "unexpected desired sprite name", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, fmt.Sprintf(`{"name":%q}`, m.canonicalName))
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/v1/sprites/") {
		http.NotFound(w, r)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/v1/sprites/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	spriteName := parts[0]
	route := ""
	if len(parts) == 2 {
		route = parts[1]
	}

	switch {
	case route == "" && r.Method == http.MethodPut:
		if spriteName != m.canonicalName {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
		return
	case route == "" && r.Method == http.MethodGet:
		if spriteName != m.canonicalName {
			http.NotFound(w, r)
			return
		}
		resp := map[string]any{
			"id":           "spr_test",
			"name":         m.canonicalName,
			"organization": "test-org",
			"status":       "running",
			"url":          m.canonicalURL,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode failed", http.StatusInternalServerError)
		}
		return
	case route == "" && r.Method == http.MethodDelete:
		if spriteName != m.canonicalName {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case route == "fs/write" && r.Method == http.MethodPut:
		if spriteName != m.canonicalName {
			http.NotFound(w, r)
			return
		}
		path := r.URL.Query().Get("path")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		m.files[path] = append([]byte(nil), body...)
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":true}`)
		return
	case route == "fs/read" && r.Method == http.MethodGet:
		if spriteName != m.canonicalName {
			http.NotFound(w, r)
			return
		}
		path := r.URL.Query().Get("path")
		m.mu.Lock()
		data, ok := m.files[path]
		m.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	default:
		http.NotFound(w, r)
		return
	}
}

func newAppsServiceWithMockSpriteAPI(t *testing.T, desiredName, canonicalName, canonicalURL string) (*Service, *mockSpriteAPI, func()) {
	t.Helper()

	userDB, closeDB := newUserDBForAppsTests(t, "user-apps-regression")
	mock := &mockSpriteAPI{
		desiredName:   desiredName,
		canonicalName: canonicalName,
		canonicalURL:  canonicalURL,
		files:         make(map[string][]byte),
	}
	server := httptest.NewServer(mock)

	svc := NewService(userDB, "user-apps-regression", "test-token")
	svc.client = sprites.New("test-token", sprites.WithBaseURL(server.URL), sprites.WithDisableControl())

	cleanup := func() {
		server.Close()
		closeDB()
	}
	return svc, mock, cleanup
}

func newUserDBForAppsTests(t *testing.T, userID string) (*db.UserDB, func()) {
	t.Helper()

	dekHex := hex.EncodeToString(db.GetHardcodedDEK())
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared&_pragma_key=x'%s'&_pragma_cipher_page_size=4096", userID, dekHex)
	sqlDB, err := sql.Open(db.SQLiteDriverName, dsn)
	if err != nil {
		t.Fatalf("failed to open test user db: %v", err)
	}
	if _, err := sqlDB.Exec(db.UserDBSchema); err != nil {
		_ = sqlDB.Close()
		t.Fatalf("failed to initialize test user schema: %v", err)
	}

	closeDB := func() {
		_ = sqlDB.Close()
	}
	return db.NewUserDBFromSQL(userID, sqlDB), closeDB
}
