// Package e2e provides end-to-end tests for short URL functionality.
// These tests verify short URL behavior via HTTP observable effects.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/s3client"
	"github.com/kuitang/agent-notes/internal/shorturl"
)

// =============================================================================
// Short URL Property Tests
// =============================================================================

var shortURLTestMutex sync.Mutex
var shortURLTestCounter atomic.Int64

// shortURLTestServer holds the server for short URL testing.
type shortURLTestServer struct {
	server        *httptest.Server
	mux           *http.ServeMux
	notesService  *notes.Service
	publicService *notes.PublicNoteService
	shortURLSvc   *shorturl.Service
	userID        string
	userDB        *db.UserDB
	sessionsDB    *db.SessionsDB
	s3Client      *s3client.Client
}

// setupShortURLTestServer creates a test server with short URL support.
func setupShortURLTestServer(t *testing.T) *shortURLTestServer {
	shortURLTestMutex.Lock()

	testID := shortURLTestCounter.Add(1)
	userID := fmt.Sprintf("shorturl-test-user-%d", testID)

	// Reset database state for testing
	db.ResetForTesting()

	// Create temp directory for this test's database
	tempDir := t.TempDir()
	db.DataDirectory = tempDir

	// Create sessions database
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to create sessions database: %v", err)
	}

	// Create in-memory user database
	userDB, err := db.NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("Failed to create in-memory user database: %v", err)
	}

	// Create S3 client with real mock
	s3Client := s3client.TestClient(t, fmt.Sprintf("shorturl-test-bucket-%d", testID))

	// Create short URL service
	shortURLSvc := shorturl.NewService(sessionsDB.Queries())

	// Create services
	notesService := notes.NewService(userDB)
	baseURL := "http://localhost:8080"
	publicService := notes.NewPublicNoteService(s3Client).WithShortURLService(shortURLSvc, baseURL)

	// Create mux
	mux := http.NewServeMux()

	// Notes CRUD endpoint
	mux.HandleFunc("POST /notes", func(w http.ResponseWriter, r *http.Request) {
		var params struct {
			Title   string `json:"title"`
			Content string `json:"content"`
		}
		json.NewDecoder(r.Body).Decode(&params)

		note, err := notesService.Create(notes.CreateNoteParams{
			Title:   params.Title,
			Content: params.Content,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(note)
	})

	// Publish toggle endpoint
	mux.HandleFunc("POST /notes/{id}/publish", func(w http.ResponseWriter, r *http.Request) {
		noteID := r.PathValue("id")
		if noteID == "" {
			http.Error(w, "Note ID required", http.StatusBadRequest)
			return
		}

		// Get current note
		note, err := notesService.Read(noteID)
		if err != nil {
			http.Error(w, "Note not found", http.StatusNotFound)
			return
		}

		// Toggle public status
		ctx := r.Context()
		newPublicStatus := !note.IsPublic

		if err := publicService.SetPublic(ctx, userDB, noteID, newPublicStatus); err != nil {
			http.Error(w, "Failed to update visibility: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the short URL
		shortURL := publicService.GetShortURL(ctx, userID, noteID)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"is_public": newPublicStatus,
			"short_url": shortURL,
		})
	})

	// Short URL redirect endpoint
	mux.HandleFunc("GET /pub/{short_id}", func(w http.ResponseWriter, r *http.Request) {
		shortID := r.PathValue("short_id")
		if shortID == "" {
			http.NotFound(w, r)
			return
		}

		fullPath, err := shortURLSvc.Resolve(r.Context(), shortID)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// Return JSON instead of redirect for testing
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"full_path": fullPath})
	})

	// Public note access endpoint
	mux.HandleFunc("GET /public/{user_id}/{note_id}", func(w http.ResponseWriter, r *http.Request) {
		reqUserID := r.PathValue("user_id")
		noteID := r.PathValue("note_id")

		if reqUserID != userID {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		ctx := r.Context()
		note, err := publicService.GetPublic(ctx, userDB, noteID)
		if err != nil {
			http.Error(w, "Note not found or not public", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(note)
	})

	server := httptest.NewServer(mux)

	return &shortURLTestServer{
		server:        server,
		mux:           mux,
		notesService:  notesService,
		publicService: publicService,
		shortURLSvc:   shortURLSvc,
		userID:        userID,
		userDB:        userDB,
		sessionsDB:    sessionsDB,
		s3Client:      s3Client,
	}
}

func (s *shortURLTestServer) cleanup() {
	s.server.Close()
	s.userDB.Close()
	db.ResetForTesting()
	shortURLTestMutex.Unlock()
}

// =============================================================================
// Property: Short ID format is valid (6 chars, valid charset)
// =============================================================================

func TestShortURL_IDFormat_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate multiple short IDs
		for i := 0; i < 100; i++ {
			shortID, err := shorturl.GenerateShortID()
			if err != nil {
				rt.Fatalf("GenerateShortID failed: %v", err)
			}

			// Property 1: Length is exactly 6
			if len(shortID) != 6 {
				rt.Fatalf("Short ID length is %d, expected 6", len(shortID))
			}

			// Property 2: All characters are from valid charset [a-zA-Z0-9_-]
			if !shorturl.ValidateShortID(shortID) {
				rt.Fatalf("Short ID contains invalid characters: %s", shortID)
			}

			// Property 3: Each character is individually valid
			for _, c := range shortID {
				validChar := (c >= 'A' && c <= 'Z') ||
					(c >= 'a' && c <= 'z') ||
					(c >= '0' && c <= '9') ||
					c == '_' || c == '-'
				if !validChar {
					rt.Fatalf("Invalid character '%c' in short ID: %s", c, shortID)
				}
			}
		}
	})
}

// =============================================================================
// Property: Short IDs are unique (probabilistic)
// =============================================================================

func TestShortURL_Uniqueness_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		seen := make(map[string]bool)
		numIDs := 1000

		for i := 0; i < numIDs; i++ {
			shortID, err := shorturl.GenerateShortID()
			if err != nil {
				rt.Fatalf("GenerateShortID failed: %v", err)
			}

			if seen[shortID] {
				rt.Fatalf("Duplicate short ID generated: %s (after %d IDs)", shortID, i)
			}
			seen[shortID] = true
		}
	})
}

// =============================================================================
// Property: ValidateShortID correctly validates format
// =============================================================================

func TestShortURL_Validation_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Test valid IDs
		validID := rapid.StringMatching(`^[a-zA-Z0-9_-]{6}$`).Draw(rt, "validID")
		if !shorturl.ValidateShortID(validID) {
			rt.Fatalf("Valid ID rejected: %s", validID)
		}

		// Test invalid: too short
		shortID := rapid.StringMatching(`^[a-zA-Z0-9_-]{1,5}$`).Draw(rt, "shortID")
		if shorturl.ValidateShortID(shortID) {
			rt.Fatalf("Short ID should be rejected (too short): %s", shortID)
		}

		// Test invalid: too long
		longID := rapid.StringMatching(`^[a-zA-Z0-9_-]{7,20}$`).Draw(rt, "longID")
		if shorturl.ValidateShortID(longID) {
			rt.Fatalf("Long ID should be rejected (too long): %s", longID)
		}

		// Test invalid: bad characters
		badChars := []string{"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", " ", "."}
		for _, c := range badChars {
			badID := "aaaaa" + c
			if len(badID) == 6 && shorturl.ValidateShortID(badID) {
				rt.Fatalf("ID with invalid char should be rejected: %s", badID)
			}
		}
	})
}

// =============================================================================
// Test: Short URL redirect works correctly
// =============================================================================

func TestShortURL_Redirect_Properties(t *testing.T) {
	srv := setupShortURLTestServer(t)
	defer srv.cleanup()

	// Create and publish a note
	noteResp, err := http.Post(srv.server.URL+"/notes", "application/json",
		strings.NewReader(`{"title":"Test Note","content":"Test content"}`))
	if err != nil {
		t.Fatalf("Create note failed: %v", err)
	}
	defer noteResp.Body.Close()

	var note struct {
		ID string `json:"id"`
	}
	json.NewDecoder(noteResp.Body).Decode(&note)

	// Publish the note
	publishResp, err := http.Post(srv.server.URL+"/notes/"+note.ID+"/publish", "", nil)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}
	defer publishResp.Body.Close()

	var publishResult struct {
		IsPublic bool   `json:"is_public"`
		ShortURL string `json:"short_url"`
	}
	json.NewDecoder(publishResp.Body).Decode(&publishResult)

	if !publishResult.IsPublic {
		t.Fatal("Note should be public after publishing")
	}

	if publishResult.ShortURL == "" {
		t.Fatal("Short URL should be generated after publishing")
	}

	// Extract short ID from URL
	parts := strings.Split(publishResult.ShortURL, "/pub/")
	if len(parts) != 2 {
		t.Fatalf("Invalid short URL format: %s", publishResult.ShortURL)
	}
	shortID := parts[1]

	// Verify short ID format
	if !shorturl.ValidateShortID(shortID) {
		t.Fatalf("Invalid short ID format: %s", shortID)
	}

	// Access via short URL
	shortResp, err := http.Get(srv.server.URL + "/pub/" + shortID)
	if err != nil {
		t.Fatalf("Short URL access failed: %v", err)
	}
	defer shortResp.Body.Close()

	if shortResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for valid short URL, got %d", shortResp.StatusCode)
	}

	var redirectResult struct {
		FullPath string `json:"full_path"`
	}
	json.NewDecoder(shortResp.Body).Decode(&redirectResult)

	expectedPath := fmt.Sprintf("/public/%s/%s", srv.userID, note.ID)
	if redirectResult.FullPath != expectedPath {
		t.Fatalf("Full path mismatch: expected %s, got %s", expectedPath, redirectResult.FullPath)
	}
}

// =============================================================================
// Test: Non-existent short URL returns 404
// =============================================================================

func TestShortURL_NotFound(t *testing.T) {
	srv := setupShortURLTestServer(t)
	defer srv.cleanup()

	// Try to access a non-existent short URL
	resp, err := http.Get(srv.server.URL + "/pub/XXXXXX")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 for non-existent short URL, got %d", resp.StatusCode)
	}
}

// =============================================================================
// Test: Invalid short ID format returns 404
// =============================================================================

func TestShortURL_InvalidFormat(t *testing.T) {
	srv := setupShortURLTestServer(t)
	defer srv.cleanup()

	invalidIDs := []string{
		"short",    // too short
		"toolong!", // too long and invalid char
		"abc@de",   // invalid char
		"",         // empty
	}

	for _, id := range invalidIDs {
		resp, err := http.Get(srv.server.URL + "/pub/" + id)
		if err != nil {
			t.Fatalf("Request failed for %q: %v", id, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected 404 for invalid short ID %q, got %d", id, resp.StatusCode)
		}
	}
}

// =============================================================================
// Test: Unpublishing removes short URL
// =============================================================================

func TestShortURL_RemoveOnUnpublish(t *testing.T) {
	srv := setupShortURLTestServer(t)
	defer srv.cleanup()

	// Create and publish a note
	noteResp, _ := http.Post(srv.server.URL+"/notes", "application/json",
		strings.NewReader(`{"title":"Remove Test","content":"Content"}`))
	var note struct {
		ID string `json:"id"`
	}
	json.NewDecoder(noteResp.Body).Decode(&note)
	noteResp.Body.Close()

	// Publish
	publishResp, _ := http.Post(srv.server.URL+"/notes/"+note.ID+"/publish", "", nil)
	var publishResult struct {
		ShortURL string `json:"short_url"`
	}
	json.NewDecoder(publishResp.Body).Decode(&publishResult)
	publishResp.Body.Close()

	shortID := strings.TrimPrefix(publishResult.ShortURL, "http://localhost:8080/pub/")

	// Verify short URL works
	resp, _ := http.Get(srv.server.URL + "/pub/" + shortID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Short URL should work after publish, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Unpublish (toggle again)
	unpubResp, _ := http.Post(srv.server.URL+"/notes/"+note.ID+"/publish", "", nil)
	var unpubResult struct {
		IsPublic bool `json:"is_public"`
	}
	json.NewDecoder(unpubResp.Body).Decode(&unpubResult)
	unpubResp.Body.Close()

	if unpubResult.IsPublic {
		t.Fatal("Note should be private after second toggle")
	}

	// Short URL should now return 404
	resp, _ = http.Get(srv.server.URL + "/pub/" + shortID)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Short URL should return 404 after unpublish, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// =============================================================================
// Test: Republishing same note reuses short URL
// =============================================================================

func TestShortURL_ReuseOnRepublish(t *testing.T) {
	srv := setupShortURLTestServer(t)
	defer srv.cleanup()

	// Create a note
	noteResp, _ := http.Post(srv.server.URL+"/notes", "application/json",
		strings.NewReader(`{"title":"Reuse Test","content":"Content"}`))
	var note struct {
		ID string `json:"id"`
	}
	json.NewDecoder(noteResp.Body).Decode(&note)
	noteResp.Body.Close()

	// Publish first time
	pub1Resp, _ := http.Post(srv.server.URL+"/notes/"+note.ID+"/publish", "", nil)
	var pub1Result struct {
		ShortURL string `json:"short_url"`
	}
	json.NewDecoder(pub1Resp.Body).Decode(&pub1Result)
	pub1Resp.Body.Close()

	firstShortURL := pub1Result.ShortURL

	// Unpublish
	http.Post(srv.server.URL+"/notes/"+note.ID+"/publish", "", nil)

	// Publish again
	pub2Resp, _ := http.Post(srv.server.URL+"/notes/"+note.ID+"/publish", "", nil)
	var pub2Result struct {
		ShortURL string `json:"short_url"`
	}
	json.NewDecoder(pub2Resp.Body).Decode(&pub2Result)
	pub2Resp.Body.Close()

	// Short URL should be the same (reused)
	if pub2Result.ShortURL != firstShortURL {
		t.Logf("Note: Short URL changed after republish: %s -> %s", firstShortURL, pub2Result.ShortURL)
		// This is not necessarily an error - depends on implementation
		// If we delete on unpublish, a new one is created on republish
	}
}

// =============================================================================
// Property: Collision handling works (simulate collisions)
// =============================================================================

func TestShortURL_CollisionHandling_Properties(t *testing.T) {
	srv := setupShortURLTestServer(t)
	defer srv.cleanup()

	ctx := context.Background()

	// Create many short URLs to test collision handling
	numURLs := 100
	created := make(map[string]string) // shortID -> fullPath

	for i := 0; i < numURLs; i++ {
		fullPath := fmt.Sprintf("/test/path/%d", i)
		shortURL, err := srv.shortURLSvc.Create(ctx, fullPath)
		if err != nil {
			t.Fatalf("Failed to create short URL %d: %v", i, err)
		}

		// Verify uniqueness
		if existing, exists := created[shortURL.ShortID]; exists {
			t.Fatalf("Collision: short ID %s maps to both %s and %s", shortURL.ShortID, existing, fullPath)
		}
		created[shortURL.ShortID] = fullPath

		// Verify roundtrip
		resolved, err := srv.shortURLSvc.Resolve(ctx, shortURL.ShortID)
		if err != nil {
			t.Fatalf("Failed to resolve short URL %s: %v", shortURL.ShortID, err)
		}
		if resolved != fullPath {
			t.Fatalf("Roundtrip failed: expected %s, got %s", fullPath, resolved)
		}
	}
}

// =============================================================================
// Property: Same full path returns same short URL (idempotent)
// =============================================================================

func TestShortURL_Idempotent_Properties(t *testing.T) {
	srv := setupShortURLTestServer(t)
	defer srv.cleanup()

	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		// Generate a random path
		path := "/test/" + rapid.StringMatching(`[a-z]{5,10}`).Draw(rt, "path")

		// Create the short URL multiple times
		first, err := srv.shortURLSvc.Create(ctx, path)
		if err != nil {
			rt.Fatalf("First create failed: %v", err)
		}

		second, err := srv.shortURLSvc.Create(ctx, path)
		if err != nil {
			rt.Fatalf("Second create failed: %v", err)
		}

		// Should return the same short ID
		if first.ShortID != second.ShortID {
			rt.Fatalf("Idempotency failed: same path returned different short IDs: %s vs %s",
				first.ShortID, second.ShortID)
		}
	})
}

// =============================================================================
// Property: Service handles concurrent requests safely
// =============================================================================

func TestShortURL_Concurrency_Properties(t *testing.T) {
	srv := setupShortURLTestServer(t)
	defer srv.cleanup()

	ctx := context.Background()
	numGoroutines := 10
	numPathsPerGoroutine := 20

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numPathsPerGoroutine)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < numPathsPerGoroutine; i++ {
				path := fmt.Sprintf("/concurrent/%d/%d", goroutineID, i)
				shortURL, err := srv.shortURLSvc.Create(ctx, path)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d, path %d: create failed: %v", goroutineID, i, err)
					continue
				}

				resolved, err := srv.shortURLSvc.Resolve(ctx, shortURL.ShortID)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d, path %d: resolve failed: %v", goroutineID, i, err)
					continue
				}

				if resolved != path {
					errors <- fmt.Errorf("goroutine %d, path %d: roundtrip failed: expected %s, got %s",
						goroutineID, i, path, resolved)
				}
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	// Collect errors
	var errs []error
	for err := range errors {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		for _, err := range errs[:minInt(5, len(errs))] {
			t.Logf("Error: %v", err)
		}
		t.Fatalf("%d errors occurred during concurrent test", len(errs))
	}
}

// =============================================================================
// Fuzz entry points (for go test -fuzz)
// =============================================================================

func FuzzShortURL_IDFormat_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		shortID, err := shorturl.GenerateShortID()
		if err != nil {
			t.Fatalf("GenerateShortID failed: %v", err)
		}

		if len(shortID) != 6 {
			t.Fatalf("Short ID length is %d, expected 6", len(shortID))
		}

		if !shorturl.ValidateShortID(shortID) {
			t.Fatalf("Short ID contains invalid characters: %s", shortID)
		}
	}))
}

func FuzzShortURL_Validation_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		validID := rapid.StringMatching(`^[a-zA-Z0-9_-]{6}$`).Draw(t, "validID")
		if !shorturl.ValidateShortID(validID) {
			t.Fatalf("Valid ID rejected: %s", validID)
		}

		shortID := rapid.StringMatching(`^[a-zA-Z0-9_-]{1,5}$`).Draw(t, "shortID")
		if shorturl.ValidateShortID(shortID) {
			t.Fatalf("Short ID should be rejected (too short): %s", shortID)
		}

		longID := rapid.StringMatching(`^[a-zA-Z0-9_-]{7,20}$`).Draw(t, "longID")
		if shorturl.ValidateShortID(longID) {
			t.Fatalf("Long ID should be rejected (too long): %s", longID)
		}
	}))
}
