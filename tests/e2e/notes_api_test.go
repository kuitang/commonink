// Package e2e provides end-to-end property-based tests for the Notes API.
// These tests hit actual HTTP handlers via httptest.Server.
// All tests follow the property-based testing approach per CLAUDE.md.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kuitang/agent-notes/internal/api"
	"github.com/kuitang/agent-notes/internal/notes"
	dbtestutil "github.com/kuitang/agent-notes/internal/testdb"
	"github.com/kuitang/agent-notes/tests/e2e/testutil"
	"pgregory.net/rapid"
)

// =============================================================================
// Test Setup Helpers
// =============================================================================

// Global mutex to ensure tests don't run in parallel (database isolation)
var notesTestMutex sync.Mutex
var notesTestCounter atomic.Int64
var notesRapidServerOverride *notesTestServer
var notesSharedMu sync.Mutex
var notesSharedFixture *notesTestServer

// notesTestServer holds the server and services for Notes API testing.
type notesTestServer struct {
	server       *httptest.Server
	mux          *http.ServeMux
	notesService *notes.Service
	handler      *api.Handler
	shared       bool
}

// setupNotesTestServer creates a test server with all Notes API routes.
func setupNotesTestServer(t testing.TB) *notesTestServer {
	t.Helper()
	notesTestMutex.Lock()
	t.Cleanup(notesTestMutex.Unlock)

	srv := getOrCreateSharedNotesServer()
	resetNotesServerState(t, srv)
	return srv
}

// setupNotesTestServerRapid creates a test server for rapid.T tests.
func setupNotesTestServerRapid(t *rapid.T) *notesTestServer {
	notesTestMutex.Lock()
	return createNotesTestServer()
}

// createNotesTestServer creates a test server with an in-memory database.
func createNotesTestServer() *notesTestServer {
	// Use unique ID for each test to ensure complete isolation
	testID := notesTestCounter.Add(1)
	userID := fmt.Sprintf("api-test-user-%d", testID)

	// Create in-memory database for this test
	userDB, err := dbtestutil.NewUserDBInMemory(userID)
	if err != nil {
		panic("Failed to create in-memory database: " + err.Error())
	}

	// Create notes service and handler
	notesService := notes.NewService(userDB)
	handler := api.NewHandler(notesService)

	// Create mux and register routes
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Create test server
	server := httptest.NewServer(mux)

	return &notesTestServer{
		server:       server,
		mux:          mux,
		notesService: notesService,
		handler:      handler,
	}
}

// cleanup closes the test server and releases the lock.
func (s *notesTestServer) cleanup() {
	if s.shared {
		return
	}
	s.server.Close()
	notesTestMutex.Unlock()
}

func getOrCreateSharedNotesServer() *notesTestServer {
	notesSharedMu.Lock()
	defer notesSharedMu.Unlock()
	if notesSharedFixture != nil {
		return notesSharedFixture
	}
	notesSharedFixture = createNotesTestServer()
	notesSharedFixture.shared = true
	return notesSharedFixture
}

func resetNotesServerState(t interface {
	Fatalf(format string, args ...any)
}, srv *notesTestServer) {
	for {
		list, err := srv.notesService.List(500, 0)
		if err != nil {
			t.Fatalf("failed to list notes for reset: %v", err)
		}
		if len(list.Notes) == 0 {
			return
		}
		for _, n := range list.Notes {
			if err := srv.notesService.Delete(n.ID); err != nil {
				t.Fatalf("failed to delete note %s during reset: %v", n.ID, err)
			}
		}
	}
}

func withNotesRapidServer(srv *notesTestServer, fn func()) {
	notesRapidServerOverride = srv
	defer func() {
		notesRapidServerOverride = nil
	}()
	fn()
}

func getNotesTestServerForRapid(t *rapid.T) (*notesTestServer, func()) {
	if notesRapidServerOverride != nil {
		resetNotesServerState(t, notesRapidServerOverride)
		return notesRapidServerOverride, func() {}
	}
	srv := setupNotesTestServerRapid(t)
	return srv, srv.cleanup
}

func runNotesRapidCheckWithSharedServer(t *testing.T, prop func(*rapid.T)) {
	t.Helper()
	srv := setupNotesTestServer(t)
	t.Cleanup(srv.cleanup)
	withNotesRapidServer(srv, func() {
		rapid.Check(t, prop)
	})
}

// =============================================================================
// HTTP Client Helpers
// =============================================================================

// noteResponse represents a note from the API
type noteResponse struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// listResponse represents the list notes response
type listResponse struct {
	Notes      []noteResponse `json:"notes"`
	TotalCount int            `json:"total_count"`
	Limit      int            `json:"limit"`
	Offset     int            `json:"offset"`
}

// searchResultItem represents a single search result
type searchResultItem struct {
	Note noteResponse `json:"note"`
	Rank float64      `json:"rank"`
}

// searchResponse represents the search notes response
type searchResponse struct {
	Results    []searchResultItem `json:"results"`
	Query      string             `json:"query"`
	TotalCount int                `json:"total_count"`
}

// errorResponse represents an error from the API
type errorResponse struct {
	Error string `json:"error"`
}

// createNote creates a note via HTTP POST and returns the response
func (s *notesTestServer) createNote(title, content string) (*http.Response, []byte, error) {
	body := map[string]string{"title": title, "content": content}
	jsonBody, _ := json.Marshal(body)
	resp, err := http.Post(s.server.URL+"/notes", "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

// getNote gets a note via HTTP GET
func (s *notesTestServer) getNote(id string) (*http.Response, []byte, error) {
	resp, err := http.Get(s.server.URL + "/notes/" + id)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

// listNotes lists notes via HTTP GET
func (s *notesTestServer) listNotes(limit, offset int) (*http.Response, []byte, error) {
	url := fmt.Sprintf("%s/notes?limit=%d&offset=%d", s.server.URL, limit, offset)
	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

// updateNote updates a note via HTTP PUT
func (s *notesTestServer) updateNote(id string, title, content *string) (*http.Response, []byte, error) {
	body := make(map[string]string)
	if title != nil {
		body["title"] = *title
	}
	if content != nil {
		body["content"] = *content
	}
	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequest(http.MethodPut, s.server.URL+"/notes/"+id, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

// deleteNote deletes a note via HTTP DELETE
func (s *notesTestServer) deleteNote(id string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, s.server.URL+"/notes/"+id, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

// searchNotes searches notes via HTTP POST
func (s *notesTestServer) searchNotes(query string) (*http.Response, []byte, error) {
	body := map[string]string{"query": query}
	jsonBody, _ := json.Marshal(body)
	resp, err := http.Post(s.server.URL+"/notes/search", "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

// =============================================================================
// Property: Create roundtrip via HTTP - created note can be read back
// =============================================================================

func testNotesAPI_Create_Roundtrip_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	title := testutil.NoteTitleGenerator().Draw(t, "title")
	content := testutil.NoteContentGenerator().Draw(t, "content")

	// Property: POST /notes returns 201 with created note
	resp, data, err := srv.createNote(title, content)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201, got %d: %s", resp.StatusCode, string(data))
	}

	var created noteResponse
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if created.ID == "" {
		t.Fatal("Note ID should not be empty")
	}
	if created.Title != title {
		t.Fatalf("Title mismatch: expected %q, got %q", title, created.Title)
	}
	if created.Content != content {
		t.Fatalf("Content mismatch: expected %q, got %q", content, created.Content)
	}

	// Property: GET /notes/{id} returns same note
	resp, data, err = srv.getNote(created.ID)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(data))
	}

	var retrieved noteResponse
	if err := json.Unmarshal(data, &retrieved); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if retrieved.ID != created.ID {
		t.Fatalf("ID mismatch: expected %q, got %q", created.ID, retrieved.ID)
	}
	if retrieved.Title != title {
		t.Fatalf("Retrieved title mismatch: expected %q, got %q", title, retrieved.Title)
	}
	if retrieved.Content != content {
		t.Fatalf("Retrieved content mismatch: expected %q, got %q", content, retrieved.Content)
	}
}

func TestNotesAPI_Create_Roundtrip_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Create_Roundtrip_Properties)
}

func FuzzNotesAPI_Create_Roundtrip_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Create_Roundtrip_Properties))
}

// =============================================================================
// Property: Create requires title via HTTP
// =============================================================================

func testNotesAPI_Create_RequiresTitle_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	content := testutil.NoteContentGenerator().Draw(t, "content")

	// Property: POST /notes with empty title returns 400
	resp, data, err := srv.createNote("", content)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d: %s", resp.StatusCode, string(data))
	}

	var errResp errorResponse
	if err := json.Unmarshal(data, &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if errResp.Error == "" {
		t.Fatal("Expected error message")
	}
}

func TestNotesAPI_Create_RequiresTitle_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Create_RequiresTitle_Properties)
}

func FuzzNotesAPI_Create_RequiresTitle_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Create_RequiresTitle_Properties))
}

// =============================================================================
// Property: Get returns 404 for non-existent note
// =============================================================================

func testNotesAPI_Get_NonExistent_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(t, "nonExistentID")

	// Property: GET /notes/{id} for non-existent note returns 404
	resp, data, err := srv.getNote(nonExistentID)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d: %s", resp.StatusCode, string(data))
	}
}

func TestNotesAPI_Get_NonExistent_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Get_NonExistent_Properties)
}

func FuzzNotesAPI_Get_NonExistent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Get_NonExistent_Properties))
}

// =============================================================================
// Property: Update modifies fields via HTTP
// =============================================================================

func testNotesAPI_Update_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	// Create initial note
	title := testutil.NoteTitleGenerator().Draw(t, "title")
	content := testutil.NoteContentGenerator().Draw(t, "content")

	resp, data, err := srv.createNote(title, content)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201, got %d", resp.StatusCode)
	}

	var created noteResponse
	json.Unmarshal(data, &created)

	// Generate new values
	newTitle := testutil.NoteTitleGenerator().Draw(t, "newTitle")
	newContent := testutil.NoteContentGenerator().Draw(t, "newContent")

	// Property: PUT /notes/{id} updates the note
	resp, data, err = srv.updateNote(created.ID, &newTitle, &newContent)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(data))
	}

	var updated noteResponse
	json.Unmarshal(data, &updated)

	if updated.Title != newTitle {
		t.Fatalf("Title not updated: expected %q, got %q", newTitle, updated.Title)
	}
	if updated.Content != newContent {
		t.Fatalf("Content not updated: expected %q, got %q", newContent, updated.Content)
	}

	// Property: GET returns updated values
	resp, data, _ = srv.getNote(created.ID)
	var retrieved noteResponse
	json.Unmarshal(data, &retrieved)

	if retrieved.Title != newTitle {
		t.Fatalf("Retrieved title not updated: expected %q, got %q", newTitle, retrieved.Title)
	}
	if retrieved.Content != newContent {
		t.Fatalf("Retrieved content not updated: expected %q, got %q", newContent, retrieved.Content)
	}
}

func TestNotesAPI_Update_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Update_Properties)
}

func FuzzNotesAPI_Update_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Update_Properties))
}

// =============================================================================
// Property: Update returns 404 for non-existent note
// =============================================================================

func testNotesAPI_Update_NonExistent_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(t, "nonExistentID")
	newTitle := testutil.NoteTitleGenerator().Draw(t, "newTitle")

	// Property: PUT /notes/{id} for non-existent note returns 404
	resp, data, err := srv.updateNote(nonExistentID, &newTitle, nil)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d: %s", resp.StatusCode, string(data))
	}
}

func TestNotesAPI_Update_NonExistent_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Update_NonExistent_Properties)
}

func FuzzNotesAPI_Update_NonExistent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Update_NonExistent_Properties))
}

// =============================================================================
// Property: Delete removes note via HTTP
// =============================================================================

func testNotesAPI_Delete_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	// Create a note
	title := testutil.NoteTitleGenerator().Draw(t, "title")
	content := testutil.NoteContentGenerator().Draw(t, "content")

	resp, data, _ := srv.createNote(title, content)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Create failed: %d", resp.StatusCode)
	}

	var created noteResponse
	json.Unmarshal(data, &created)

	// Property: DELETE /notes/{id} returns 204
	resp, err := srv.deleteNote(created.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("Expected 204, got %d", resp.StatusCode)
	}

	// Property: GET after delete returns 404
	resp, _, _ = srv.getNote(created.ID)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 after delete, got %d", resp.StatusCode)
	}
}

func TestNotesAPI_Delete_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Delete_Properties)
}

func FuzzNotesAPI_Delete_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Delete_Properties))
}

// =============================================================================
// Property: Delete returns 404 for non-existent note
// =============================================================================

func testNotesAPI_Delete_NonExistent_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(t, "nonExistentID")

	// Property: DELETE /notes/{id} for non-existent note returns 404
	resp, err := srv.deleteNote(nonExistentID)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d", resp.StatusCode)
	}
}

func TestNotesAPI_Delete_NonExistent_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Delete_NonExistent_Properties)
}

func FuzzNotesAPI_Delete_NonExistent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Delete_NonExistent_Properties))
}

// =============================================================================
// Property: List pagination via HTTP
// =============================================================================

func testNotesAPI_List_Pagination_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	// Create multiple notes with valid non-whitespace titles
	numNotes := rapid.IntRange(3, 10).Draw(t, "numNotes")
	createdIDs := make([]string, 0, numNotes)

	for i := 0; i < numNotes; i++ {
		// Use fixed prefix to ensure non-empty title
		title := fmt.Sprintf("Note%d", i)
		content := testutil.NoteContentGenerator().Draw(t, fmt.Sprintf("content%d", i))
		resp, data, _ := srv.createNote(title, content)
		if resp.StatusCode == http.StatusCreated {
			var created noteResponse
			json.Unmarshal(data, &created)
			createdIDs = append(createdIDs, created.ID)
		}
	}

	// Property: List with limit returns at most limit notes
	limit := rapid.IntRange(1, len(createdIDs)).Draw(t, "limit")
	resp, data, err := srv.listNotes(limit, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(data))
	}

	var listResp listResponse
	if err := json.Unmarshal(data, &listResp); err != nil {
		t.Fatalf("Failed to parse list response: %v", err)
	}

	if len(listResp.Notes) > limit {
		t.Fatalf("Expected at most %d notes, got %d", limit, len(listResp.Notes))
	}

	// Property: Total reflects actual count
	if listResp.TotalCount < len(createdIDs) {
		t.Fatalf("Expected total >= %d, got %d", len(createdIDs), listResp.TotalCount)
	}
}

func TestNotesAPI_List_Pagination_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_List_Pagination_Properties)
}

func FuzzNotesAPI_List_Pagination_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_List_Pagination_Properties))
}

// =============================================================================
// Property: Search finds matching notes via HTTP
// =============================================================================

func testNotesAPI_Search_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	// Generate a unique search term
	searchTerm := testutil.NoteSearchTermGenerator().Draw(t, "searchTerm")

	// Create a note containing the search term
	title := searchTerm + " " + testutil.NoteTitleGenerator().Draw(t, "titleSuffix")
	content := testutil.NoteContentGenerator().Draw(t, "content")

	resp, data, _ := srv.createNote(title, content)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Create failed: %d", resp.StatusCode)
	}

	var created noteResponse
	json.Unmarshal(data, &created)

	// Property: Search returns the note containing the term
	resp, data, err := srv.searchNotes(searchTerm)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(data))
	}

	var searchResp searchResponse
	if err := json.Unmarshal(data, &searchResp); err != nil {
		t.Fatalf("Failed to parse search results: %v", err)
	}

	// Check that created note is in results
	found := false
	for _, result := range searchResp.Results {
		if result.Note.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Created note not found in search results for term %q", searchTerm)
	}
}

func TestNotesAPI_Search_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Search_Properties)
}

func FuzzNotesAPI_Search_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Search_Properties))
}

// =============================================================================
// Property: Search with empty query returns 400
// =============================================================================

func testNotesAPI_Search_EmptyQuery_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	// Property: POST /notes/search with empty query returns 400
	resp, data, err := srv.searchNotes("")
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d: %s", resp.StatusCode, string(data))
	}
}

func TestNotesAPI_Search_EmptyQuery_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Search_EmptyQuery_Properties)
}

func FuzzNotesAPI_Search_EmptyQuery_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Search_EmptyQuery_Properties))
}

// =============================================================================
// Property: CRUD workflow consistency via HTTP
// =============================================================================

func testNotesAPI_CRUD_Workflow_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	title := testutil.NoteTitleGenerator().Draw(t, "title")
	content := testutil.NoteContentGenerator().Draw(t, "content")
	newTitle := testutil.NoteTitleGenerator().Draw(t, "newTitle")
	newContent := testutil.NoteContentGenerator().Draw(t, "newContent")

	// Create
	resp, data, _ := srv.createNote(title, content)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Create failed: %d", resp.StatusCode)
	}
	var created noteResponse
	json.Unmarshal(data, &created)

	// Read
	resp, data, _ = srv.getNote(created.ID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Read failed: %d", resp.StatusCode)
	}

	// Update
	resp, data, _ = srv.updateNote(created.ID, &newTitle, &newContent)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Update failed: %d", resp.StatusCode)
	}

	// Verify update
	resp, data, _ = srv.getNote(created.ID)
	var retrieved noteResponse
	json.Unmarshal(data, &retrieved)
	if retrieved.Title != newTitle || retrieved.Content != newContent {
		t.Fatalf("Update not persisted")
	}

	// Delete
	resp, _ = srv.deleteNote(created.ID)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("Delete failed: %d", resp.StatusCode)
	}

	// Verify delete
	resp, _, _ = srv.getNote(created.ID)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Note still exists after delete")
	}
}

func TestNotesAPI_CRUD_Workflow_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_CRUD_Workflow_Properties)
}

func FuzzNotesAPI_CRUD_Workflow_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_CRUD_Workflow_Properties))
}

// =============================================================================
// Property: Create allows empty content via HTTP
// =============================================================================

func testNotesAPI_Create_AllowsEmptyContent_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	title := testutil.NoteTitleGenerator().Draw(t, "title")

	// Property: POST /notes with empty content returns 201
	resp, data, err := srv.createNote(title, "")
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201, got %d: %s", resp.StatusCode, string(data))
	}

	var created noteResponse
	json.Unmarshal(data, &created)
	if created.Content != "" {
		t.Fatalf("Expected empty content, got %q", created.Content)
	}
}

func TestNotesAPI_Create_AllowsEmptyContent_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Create_AllowsEmptyContent_Properties)
}

func FuzzNotesAPI_Create_AllowsEmptyContent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Create_AllowsEmptyContent_Properties))
}

// =============================================================================
// Property: Search returns empty results for no matches
// =============================================================================

func testNotesAPI_Search_NoMatches_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	// Create some notes without the search term
	numNotes := rapid.IntRange(1, 5).Draw(t, "numNotes")
	for i := 0; i < numNotes; i++ {
		title := testutil.NoteTitleGenerator().Draw(t, fmt.Sprintf("title%d", i))
		content := testutil.NoteContentGenerator().Draw(t, fmt.Sprintf("content%d", i))
		srv.createNote(title, content)
	}

	// Generate a unique term unlikely to be in the content
	uniqueSearchTerm := "zzzznonexistentterm" + rapid.StringMatching(`[0-9]{6}`).Draw(t, "unique")

	// Property: Non-matching search returns 0 results
	resp, data, err := srv.searchNotes(uniqueSearchTerm)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(data))
	}

	var searchResp searchResponse
	json.Unmarshal(data, &searchResp)
	if len(searchResp.Results) != 0 {
		t.Fatalf("Expected 0 results, got %d", len(searchResp.Results))
	}
}

func TestNotesAPI_Search_NoMatches_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Search_NoMatches_Properties)
}

func FuzzNotesAPI_Search_NoMatches_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Search_NoMatches_Properties))
}

// =============================================================================
// Property: Multiple notes maintain independence via HTTP
// =============================================================================

func testNotesAPI_MultipleNotes_Independence_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	numNotes := rapid.IntRange(2, 10).Draw(t, "numNotes")
	noteIDs := make([]string, 0, numNotes)

	// Create multiple notes
	for i := 0; i < numNotes; i++ {
		title := testutil.NoteTitleGenerator().Draw(t, fmt.Sprintf("title%d", i))
		content := testutil.NoteContentGenerator().Draw(t, fmt.Sprintf("content%d", i))

		resp, data, _ := srv.createNote(title, content)
		if resp.StatusCode == http.StatusCreated {
			var created noteResponse
			json.Unmarshal(data, &created)
			noteIDs = append(noteIDs, created.ID)
		}
	}

	// Property: Each note can be read independently
	for _, id := range noteIDs {
		resp, _, _ := srv.getNote(id)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET failed for %s: %d", id, resp.StatusCode)
		}
	}

	// Property: Deleting one note doesn't affect others
	if len(noteIDs) > 0 {
		indexToDelete := rapid.IntRange(0, len(noteIDs)-1).Draw(t, "indexToDelete")
		resp, _ := srv.deleteNote(noteIDs[indexToDelete])
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("Delete failed: %d", resp.StatusCode)
		}

		// Verify others still exist
		for i, id := range noteIDs {
			if i == indexToDelete {
				continue
			}
			resp, _, _ := srv.getNote(id)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Note %s should still exist after deleting note %d", id, indexToDelete)
			}
		}
	}
}

func TestNotesAPI_MultipleNotes_Independence_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_MultipleNotes_Independence_Properties)
}

func FuzzNotesAPI_MultipleNotes_Independence_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_MultipleNotes_Independence_Properties))
}

// =============================================================================
// Property: List with offset via HTTP
// =============================================================================

func testNotesAPI_List_Offset_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	// Create a set of notes
	numNotes := rapid.IntRange(5, 15).Draw(t, "numNotes")
	for i := 0; i < numNotes; i++ {
		title := testutil.NoteTitleGenerator().Draw(t, fmt.Sprintf("title%d", i))
		content := testutil.NoteContentGenerator().Draw(t, fmt.Sprintf("content%d", i))
		srv.createNote(title, content)
	}

	// Property: Offset skips correct number of notes
	offset := rapid.IntRange(0, numNotes).Draw(t, "offset")
	resp, data, err := srv.listNotes(100, offset)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	var listResp listResponse
	json.Unmarshal(data, &listResp)

	expectedCount := numNotes - offset
	if expectedCount < 0 {
		expectedCount = 0
	}
	if len(listResp.Notes) != expectedCount {
		t.Fatalf("Expected %d notes with offset %d, got %d", expectedCount, offset, len(listResp.Notes))
	}
}

func TestNotesAPI_List_Offset_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_List_Offset_Properties)
}

func FuzzNotesAPI_List_Offset_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_List_Offset_Properties))
}

// =============================================================================
// Property: Partial update preserves unchanged fields via HTTP
// =============================================================================

func testNotesAPI_Update_PartialUpdate_Properties(t *rapid.T) {
	srv, cleanup := getNotesTestServerForRapid(t)
	defer cleanup()

	// Create initial note
	originalTitle := testutil.NoteTitleGenerator().Draw(t, "originalTitle")
	originalContent := testutil.NoteContentGenerator().Draw(t, "originalContent")

	resp, data, _ := srv.createNote(originalTitle, originalContent)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Create failed: %d", resp.StatusCode)
	}

	var created noteResponse
	json.Unmarshal(data, &created)

	// Update only title
	newTitle := testutil.NoteTitleGenerator().Draw(t, "newTitle")
	resp, data, _ = srv.updateNote(created.ID, &newTitle, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Update failed: %d", resp.StatusCode)
	}

	var updated noteResponse
	json.Unmarshal(data, &updated)

	// Property: Title updated, content unchanged
	if updated.Title != newTitle {
		t.Fatalf("Title not updated: expected %q, got %q", newTitle, updated.Title)
	}
	if updated.Content != originalContent {
		t.Fatalf("Content should be unchanged: expected %q, got %q", originalContent, updated.Content)
	}
}

func TestNotesAPI_Update_PartialUpdate_Properties(t *testing.T) {
	runNotesRapidCheckWithSharedServer(t, testNotesAPI_Update_PartialUpdate_Properties)
}

func FuzzNotesAPI_Update_PartialUpdate_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNotesAPI_Update_PartialUpdate_Properties))
}
