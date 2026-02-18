// Package e2e provides end-to-end tests for public notes.
// These tests verify public notes behavior via HTTP observable effects.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/s3client"
	dbtestutil "github.com/kuitang/agent-notes/internal/testdb"
)

// =============================================================================
// Public Notes HTTP Tests - Observable Behavior (Deterministic)
// =============================================================================

var publicNotesTestMutex sync.Mutex
var publicNotesTestCounter atomic.Int64

// publicNotesTestServer holds the server for public notes testing.
type publicNotesTestServer struct {
	server        *httptest.Server
	mux           *http.ServeMux
	notesService  *notes.Service
	publicService *notes.PublicNoteService
	userID        string
	userDB        *db.UserDB
	s3Client      *s3client.Client
}

// setupPublicNotesTestServer creates a test server with real S3 mock.
func setupPublicNotesTestServer(t *testing.T) *publicNotesTestServer {
	publicNotesTestMutex.Lock()

	testID := publicNotesTestCounter.Add(1)
	userID := fmt.Sprintf("public-test-user-%d", testID)

	// Create in-memory database
	userDB, err := dbtestutil.NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("Failed to create in-memory database: %v", err)
	}

	// Create S3 client with real mock
	s3Client := s3client.TestClient(t, fmt.Sprintf("public-test-bucket-%d", testID))

	// Create services
	notesService := notes.NewService(userDB, notes.FreeStorageLimitBytes)
	publicService := notes.NewPublicNoteService(s3Client)

	// Create mux
	mux := http.NewServeMux()

	// Simple notes CRUD endpoint (POST to create)
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

		// Toggle public status using the public service
		ctx := r.Context()
		newPublicStatus := !note.IsPublic

		if err := publicService.SetPublic(ctx, userDB, noteID, newPublicStatus); err != nil {
			http.Error(w, "Failed to update visibility: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"is_public": newPublicStatus})
	})

	// Public note access endpoint
	mux.HandleFunc("GET /public/{user_id}/{note_id}", func(w http.ResponseWriter, r *http.Request) {
		reqUserID := r.PathValue("user_id")
		noteID := r.PathValue("note_id")

		if reqUserID != userID {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// Get note and check if public
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

	return &publicNotesTestServer{
		server:        server,
		mux:           mux,
		notesService:  notesService,
		publicService: publicService,
		userID:        userID,
		userDB:        userDB,
		s3Client:      s3Client,
	}
}

func (s *publicNotesTestServer) cleanup() {
	s.server.Close()
	publicNotesTestMutex.Unlock()
}

// createNote creates a note via HTTP
func (s *publicNotesTestServer) createNote(title, content string) (string, error) {
	body := map[string]string{"title": title, "content": content}
	jsonBody, _ := json.Marshal(body)
	resp, err := http.Post(s.server.URL+"/notes", "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create failed: %d", resp.StatusCode)
	}

	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&created)
	return created.ID, nil
}

// publishNote toggles note public status via HTTP
func (s *publicNotesTestServer) publishNote(noteID string) (bool, error) {
	req, _ := http.NewRequest(http.MethodPost, s.server.URL+"/notes/"+noteID+"/publish", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("publish failed: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		IsPublic bool `json:"is_public"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.IsPublic, nil
}

// getPublicNote gets a public note via HTTP
func (s *publicNotesTestServer) getPublicNote(noteID string) (*http.Response, []byte, error) {
	resp, err := http.Get(s.server.URL + "/public/" + s.userID + "/" + noteID)
	if err != nil {
		return nil, nil, err
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, data, nil
}

// =============================================================================
// Test: Private note returns 404 on public access
// =============================================================================

func TestPublicNotesAPI_PrivateReturns404(t *testing.T) {
	srv := setupPublicNotesTestServer(t)
	defer srv.cleanup()

	// Create a note (starts private)
	noteID, err := srv.createNote("Test Note", "Test content")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Private note should return 404 on public access
	resp, _, err := srv.getPublicNote(noteID)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 for private note, got %d", resp.StatusCode)
	}
}

// =============================================================================
// Test: Published note is accessible via public URL
// =============================================================================

func TestPublicNotesAPI_PublishedAccessible(t *testing.T) {
	srv := setupPublicNotesTestServer(t)
	defer srv.cleanup()

	title := "Public Test Note"
	content := "This is public content"

	// Create and publish note
	noteID, err := srv.createNote(title, content)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	isPublic, err := srv.publishNote(noteID)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}
	if !isPublic {
		t.Fatal("Expected note to be public after publish")
	}

	// Published note should return 200 on public access
	resp, data, err := srv.getPublicNote(noteID)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for public note, got %d: %s", resp.StatusCode, string(data))
	}

	// Response should contain note data
	var note struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Content  string `json:"content"`
		IsPublic bool   `json:"is_public"`
	}
	if err := json.Unmarshal(data, &note); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if note.ID != noteID {
		t.Fatalf("ID mismatch: expected %s, got %s", noteID, note.ID)
	}
	if note.Title != title {
		t.Fatalf("Title mismatch: expected %s, got %s", title, note.Title)
	}
	if !note.IsPublic {
		t.Fatal("Expected IsPublic=true")
	}
}

// =============================================================================
// Test: Unpublished note returns 404 again
// =============================================================================

func TestPublicNotesAPI_UnpublishedReturns404(t *testing.T) {
	srv := setupPublicNotesTestServer(t)
	defer srv.cleanup()

	// Create, publish, then unpublish
	noteID, err := srv.createNote("Toggle Note", "Toggle content")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Publish
	_, err = srv.publishNote(noteID)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Verify accessible
	resp, _, _ := srv.getPublicNote(noteID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Note should be accessible after publish, got %d", resp.StatusCode)
	}

	// Unpublish (toggle again)
	isPublic, err := srv.publishNote(noteID)
	if err != nil {
		t.Fatalf("Unpublish failed: %v", err)
	}
	if isPublic {
		t.Fatal("Expected note to be private after second toggle")
	}

	// Unpublished note should return 404
	resp, _, _ = srv.getPublicNote(noteID)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 after unpublish, got %d", resp.StatusCode)
	}
}

// =============================================================================
// Test: Toggle public multiple times maintains consistency
// =============================================================================

func TestPublicNotesAPI_ToggleConsistency(t *testing.T) {
	srv := setupPublicNotesTestServer(t)
	defer srv.cleanup()

	noteID, err := srv.createNote("Toggle Test", "Content")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Toggle 5 times and verify consistency
	expectedPublic := false // Starts private

	for i := 0; i < 5; i++ {
		isPublic, err := srv.publishNote(noteID)
		if err != nil {
			t.Fatalf("Toggle %d failed: %v", i, err)
		}

		expectedPublic = !expectedPublic

		if isPublic != expectedPublic {
			t.Fatalf("Toggle %d: expected public=%v, got %v", i, expectedPublic, isPublic)
		}

		// Public access should match expected state
		resp, _, _ := srv.getPublicNote(noteID)
		if expectedPublic {
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Toggle %d: expected 200 when public, got %d", i, resp.StatusCode)
			}
		} else {
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("Toggle %d: expected 404 when private, got %d", i, resp.StatusCode)
			}
		}
	}
}

// =============================================================================
// Test: Non-existent note returns 404 on publish
// =============================================================================

func TestPublicNotesAPI_PublishNonExistent(t *testing.T) {
	srv := setupPublicNotesTestServer(t)
	defer srv.cleanup()

	req, _ := http.NewRequest(http.MethodPost, srv.server.URL+"/notes/nonexistent-id/publish", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 for non-existent note, got %d", resp.StatusCode)
	}
}

// =============================================================================
// Test: Non-existent user returns 404 on public access
// =============================================================================

func TestPublicNotesAPI_NonExistentUser(t *testing.T) {
	srv := setupPublicNotesTestServer(t)
	defer srv.cleanup()

	resp, err := http.Get(srv.server.URL + "/public/fake-user/fake-note")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 for non-existent user, got %d", resp.StatusCode)
	}
}

// =============================================================================
// Test: S3 object is created when publishing
// =============================================================================

func TestPublicNotesAPI_S3ObjectCreated(t *testing.T) {
	srv := setupPublicNotesTestServer(t)
	defer srv.cleanup()

	title := "S3 Test Note"
	content := "Content to upload to S3"

	noteID, err := srv.createNote(title, content)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Publish
	_, err = srv.publishNote(noteID)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Verify S3 object exists
	ctx := context.Background()
	key := fmt.Sprintf("public/%s/%s.html", srv.userID, noteID)
	s3Content, err := srv.s3Client.GetObject(ctx, key)
	if err != nil {
		t.Fatalf("S3 object should exist after publish: %v", err)
	}

	// Content should contain title
	if !bytes.Contains(s3Content, []byte(title)) {
		t.Fatalf("S3 content should contain title")
	}
}
