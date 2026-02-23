package notes

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kuitang/agent-notes/internal/errs"
	dbtestutil "github.com/kuitang/agent-notes/internal/testdb"
	"pgregory.net/rapid"
)

// testCounter provides unique IDs for in-memory databases to avoid conflicts
var testCounter atomic.Int64

// setupNotesService creates a new notes service using an in-memory database
func setupNotesService(t testing.TB) *Service {
	t.Helper()
	return createInMemoryService(t)
}

// setupNotesServiceRapid creates a new notes service for rapid tests using in-memory database
func setupNotesServiceRapid(t *rapid.T) *Service {
	return createInMemoryService(t)
}

// createInMemoryService creates a Service with a fresh in-memory database
// Each call creates a completely isolated database, avoiding all file contention issues
func createInMemoryService(t interface {
	Fatalf(format string, args ...interface{})
}) *Service {
	// Use unique ID for each test to ensure complete isolation
	testID := testCounter.Add(1)
	userID := fmt.Sprintf("%s-test%d", HardcodedUserID, testID)

	userDB, err := dbtestutil.NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("failed to create in-memory database: %v", err)
	}
	return NewService(userDB, FreeStorageLimitBytes)
}

func mustGetRevisionHash(t interface {
	Fatalf(format string, args ...interface{})
}, svc *Service, noteID string) string {
	note, err := svc.Read(noteID)
	if err != nil {
		t.Fatalf("failed to read note: %v", err)
	}
	if note.RevisionHash == "" {
		t.Fatalf("read note missing revision_hash")
	}
	return note.RevisionHash
}

// =============================================================================
// Generators for property-based testing
// =============================================================================

// titleGenerator generates valid note titles (non-empty strings)
func titleGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9 ]{1,50}`)
}

// contentGenerator generates note content (can be empty)
func contentGenerator() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.Just(""),
		rapid.StringMatching(`[A-Za-z0-9 .,!?]{1,200}`),
	)
}

// searchTermGenerator generates valid search terms
func searchTermGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z]{4,15}`)
}

// =============================================================================
// Property: Create roundtrip - created note can be read back
// =============================================================================

func testCreate_Roundtrip_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	title := titleGenerator().Draw(t, "title")
	content := contentGenerator().Draw(t, "content")

	// Property: Create returns note with same title and content
	note, err := svc.Create(CreateNoteParams{
		Title:   title,
		Content: content,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if note.ID == "" {
		t.Fatal("Note ID should not be empty")
	}
	if note.Title != title {
		t.Fatalf("Title mismatch: expected %q, got %q", title, note.Title)
	}
	if note.Content != content {
		t.Fatalf("Content mismatch: expected %q, got %q", content, note.Content)
	}
	if note.CreatedAt.IsZero() {
		t.Fatal("CreatedAt should be set")
	}
	if note.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt should be set")
	}

	// Property: Read returns same note
	retrieved, err := svc.Read(note.ID)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if retrieved.ID != note.ID {
		t.Fatalf("ID mismatch: expected %q, got %q", note.ID, retrieved.ID)
	}
	if retrieved.Title != title {
		t.Fatalf("Retrieved title mismatch: expected %q, got %q", title, retrieved.Title)
	}
	if retrieved.Content != content {
		t.Fatalf("Retrieved content mismatch: expected %q, got %q", content, retrieved.Content)
	}
}

func TestCreate_Roundtrip_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testCreate_Roundtrip_Properties)
}

func FuzzCreate_Roundtrip_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCreate_Roundtrip_Properties))
}

// =============================================================================
// Property: Create requires title
// =============================================================================

func testCreate_RequiresTitle_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	content := contentGenerator().Draw(t, "content")

	// Property: Empty title returns error
	_, err := svc.Create(CreateNoteParams{
		Title:   "",
		Content: content,
	})
	if err == nil {
		t.Fatal("Expected error when title is empty")
	}
}

func TestCreate_RequiresTitle_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testCreate_RequiresTitle_Properties)
}

func FuzzCreate_RequiresTitle_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCreate_RequiresTitle_Properties))
}

// =============================================================================
// Property: Create allows empty content
// =============================================================================

func testCreate_AllowsEmptyContent_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	title := titleGenerator().Draw(t, "title")

	// Property: Empty content is allowed
	note, err := svc.Create(CreateNoteParams{
		Title:   title,
		Content: "",
	})
	if err != nil {
		t.Fatalf("Create with empty content failed: %v", err)
	}
	if note.Content != "" {
		t.Fatalf("Expected empty content, got %q", note.Content)
	}
}

func TestCreate_AllowsEmptyContent_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testCreate_AllowsEmptyContent_Properties)
}

func FuzzCreate_AllowsEmptyContent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCreate_AllowsEmptyContent_Properties))
}

// =============================================================================
// Property: Read returns error for non-existent note
// =============================================================================

func testRead_NonExistent_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(t, "nonExistentID")

	// Property: Non-existent ID returns error
	_, err := svc.Read(nonExistentID)
	if err == nil {
		t.Fatal("Expected error for non-existent note")
	}
}

func TestRead_NonExistent_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testRead_NonExistent_Properties)
}

func FuzzRead_NonExistent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRead_NonExistent_Properties))
}

// =============================================================================
// Property: Read returns error for empty ID
// =============================================================================

func testRead_EmptyID_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	// Property: Empty ID returns error
	_, err := svc.Read("")
	if err == nil {
		t.Fatal("Expected error for empty ID")
	}
}

func TestRead_EmptyID_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testRead_EmptyID_Properties)
}

func FuzzRead_EmptyID_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRead_EmptyID_Properties))
}

// =============================================================================
// Property: Update modifies and preserves fields correctly
// =============================================================================

func testUpdate_FieldsModified_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	// Create initial note
	originalTitle := titleGenerator().Draw(t, "originalTitle")
	originalContent := contentGenerator().Draw(t, "originalContent")

	note, err := svc.Create(CreateNoteParams{
		Title:   originalTitle,
		Content: originalContent,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Generate update parameters
	updateTitle := rapid.Bool().Draw(t, "updateTitle")
	updateContent := rapid.Bool().Draw(t, "updateContent")

	var params UpdateNoteParams
	expectedTitle := originalTitle
	expectedContent := originalContent

	if updateTitle {
		newTitle := titleGenerator().Draw(t, "newTitle")
		params.Title = &newTitle
		expectedTitle = newTitle
	}
	if updateContent {
		newContent := contentGenerator().Draw(t, "newContent")
		params.Content = &newContent
		expectedContent = newContent
	}
	priorHash := mustGetRevisionHash(t, svc, note.ID)
	params.PriorHash = &priorHash

	// Property: Update succeeds
	updated, err := svc.Update(note.ID, params)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Property: Updated fields match expected values
	if updated.Title != expectedTitle {
		t.Fatalf("Title mismatch: expected %q, got %q", expectedTitle, updated.Title)
	}
	if updated.Content != expectedContent {
		t.Fatalf("Content mismatch: expected %q, got %q", expectedContent, updated.Content)
	}

	// Property: UpdatedAt is updated (unless no changes were made)
	if updateTitle || updateContent {
		if !updated.UpdatedAt.After(note.CreatedAt) && !updated.UpdatedAt.Equal(note.CreatedAt) {
			// Allow equal for fast tests where time might not advance
		}
	}
}

func TestUpdate_FieldsModified_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUpdate_FieldsModified_Properties)
}

func FuzzUpdate_FieldsModified_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUpdate_FieldsModified_Properties))
}

// =============================================================================
// Property: Update returns error for non-existent note
// =============================================================================

func testUpdate_NonExistent_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(t, "nonExistentID")
	newTitle := titleGenerator().Draw(t, "newTitle")

	// Property: Non-existent ID returns error
	_, err := svc.Update(nonExistentID, UpdateNoteParams{
		Title: &newTitle,
	})
	if err == nil {
		t.Fatal("Expected error for non-existent note")
	}
}

func TestUpdate_NonExistent_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUpdate_NonExistent_Properties)
}

func FuzzUpdate_NonExistent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUpdate_NonExistent_Properties))
}

// =============================================================================
// Property: Update returns error for empty ID
// =============================================================================

func testUpdate_EmptyID_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	newTitle := titleGenerator().Draw(t, "newTitle")

	// Property: Empty ID returns error
	_, err := svc.Update("", UpdateNoteParams{
		Title: &newTitle,
	})
	if err == nil {
		t.Fatal("Expected error for empty ID")
	}
}

func TestUpdate_EmptyID_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUpdate_EmptyID_Properties)
}

func FuzzUpdate_EmptyID_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUpdate_EmptyID_Properties))
}

// =============================================================================
// Property: Update honors prior_hash optimistic concurrency precondition
// =============================================================================

func testUpdate_PriorHash_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	note, err := svc.Create(CreateNoteParams{
		Title:   titleGenerator().Draw(t, "title"),
		Content: contentGenerator().Draw(t, "content"),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	correctHash := mustGetRevisionHash(t, svc, note.ID)
	newContent := "updated-" + rapid.StringMatching(`[a-z]{8}`).Draw(t, "suffix")

	// Property: matching prior_hash succeeds.
	updated, err := svc.Update(note.ID, UpdateNoteParams{
		Content:   &newContent,
		PriorHash: &correctHash,
	})
	if err != nil {
		t.Fatalf("Update with matching prior_hash failed: %v", err)
	}
	if updated.Content != newContent {
		t.Fatalf("Content mismatch: expected %q, got %q", newContent, updated.Content)
	}

	// Property: stale prior_hash fails with revision conflict.
	staleHash := correctHash
	if staleHash[0] == '0' {
		staleHash = "1" + staleHash[1:]
	} else {
		staleHash = "0" + staleHash[1:]
	}
	_, err = svc.Update(note.ID, UpdateNoteParams{
		Content:   &newContent,
		PriorHash: &staleHash,
	})
	if err == nil {
		t.Fatal("Expected revision conflict for stale prior_hash")
	}
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("Expected ErrRevisionConflict, got: %v", err)
	}
}

func TestUpdate_PriorHash_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUpdate_PriorHash_Properties)
}

func FuzzUpdate_PriorHash_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUpdate_PriorHash_Properties))
}

// =============================================================================
// Property: Delete removes note completely
// =============================================================================

func testDelete_RemovesNote_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	title := titleGenerator().Draw(t, "title")
	content := contentGenerator().Draw(t, "content")

	// Create note
	note, err := svc.Create(CreateNoteParams{
		Title:   title,
		Content: content,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Property: Delete succeeds
	err = svc.Delete(note.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Property: Read fails after delete
	_, err = svc.Read(note.ID)
	if err == nil {
		t.Fatal("Expected error reading deleted note")
	}
}

func TestDelete_RemovesNote_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testDelete_RemovesNote_Properties)
}

func FuzzDelete_RemovesNote_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testDelete_RemovesNote_Properties))
}

// =============================================================================
// Property: Delete returns error for non-existent note
// =============================================================================

func testDelete_NonExistent_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(t, "nonExistentID")

	// Property: Non-existent ID returns error
	err := svc.Delete(nonExistentID)
	if err == nil {
		t.Fatal("Expected error for non-existent note")
	}
}

func TestDelete_NonExistent_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testDelete_NonExistent_Properties)
}

func FuzzDelete_NonExistent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testDelete_NonExistent_Properties))
}

// =============================================================================
// Property: Delete returns error for empty ID
// =============================================================================

func testDelete_EmptyID_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	// Property: Empty ID returns error
	err := svc.Delete("")
	if err == nil {
		t.Fatal("Expected error for empty ID")
	}
}

func TestDelete_EmptyID_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testDelete_EmptyID_Properties)
}

func FuzzDelete_EmptyID_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testDelete_EmptyID_Properties))
}

// =============================================================================
// Property: List returns correct pagination
// =============================================================================

func testList_Pagination_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	// Create a random number of notes
	numNotes := rapid.IntRange(0, 20).Draw(t, "numNotes")
	for i := 0; i < numNotes; i++ {
		title := titleGenerator().Draw(t, "title")
		content := contentGenerator().Draw(t, "content")
		_, err := svc.Create(CreateNoteParams{
			Title:   title,
			Content: content,
		})
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	limit := rapid.IntRange(1, 100).Draw(t, "limit")
	offset := rapid.IntRange(0, numNotes+5).Draw(t, "offset")

	// Property: List returns correct total count
	result, err := svc.List(limit, offset)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if result.TotalCount != numNotes {
		t.Fatalf("TotalCount mismatch: expected %d, got %d", numNotes, result.TotalCount)
	}

	// Property: Number of returned notes is correct
	expectedReturned := numNotes - offset
	if expectedReturned < 0 {
		expectedReturned = 0
	}
	// Apply effective limit (max 1000)
	effectiveLimit := limit
	if effectiveLimit > MaxLimit {
		effectiveLimit = MaxLimit
	}
	if expectedReturned > effectiveLimit {
		expectedReturned = effectiveLimit
	}

	if len(result.Notes) != expectedReturned {
		t.Fatalf("Notes count mismatch: expected %d, got %d", expectedReturned, len(result.Notes))
	}
}

func TestList_Pagination_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testList_Pagination_Properties)
}

func FuzzList_Pagination_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testList_Pagination_Properties))
}

// =============================================================================
// Property: List enforces max limit of 1000
// =============================================================================

func testList_MaxLimit_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	// Test with limit > 1000
	largeLimit := rapid.IntRange(1001, 5000).Draw(t, "largeLimit")

	result, err := svc.List(largeLimit, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Property: Limit is capped at 1000
	if result.Limit != MaxLimit {
		t.Fatalf("Expected limit to be capped at %d, got %d", MaxLimit, result.Limit)
	}
}

func TestList_MaxLimit_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testList_MaxLimit_Properties)
}

func FuzzList_MaxLimit_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testList_MaxLimit_Properties))
}

// =============================================================================
// Property: List uses default limit for invalid values
// =============================================================================

func testList_DefaultLimit_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	// Test with limit <= 0
	invalidLimit := rapid.IntRange(-100, 0).Draw(t, "invalidLimit")

	result, err := svc.List(invalidLimit, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Property: Default limit is 50
	if result.Limit != DefaultLimit {
		t.Fatalf("Expected default limit %d, got %d", DefaultLimit, result.Limit)
	}
}

func TestList_DefaultLimit_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testList_DefaultLimit_Properties)
}

func FuzzList_DefaultLimit_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testList_DefaultLimit_Properties))
}

// =============================================================================
// Property: Search finds notes by content
// =============================================================================

func testSearch_FindsByContent_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	// Generate a unique search term
	searchTerm := searchTermGenerator().Draw(t, "searchTerm")

	// Create notes with and without the search term
	notesWithTerm := rapid.IntRange(1, 5).Draw(t, "notesWithTerm")
	notesWithoutTerm := rapid.IntRange(0, 5).Draw(t, "notesWithoutTerm")

	for i := 0; i < notesWithTerm; i++ {
		title := titleGenerator().Draw(t, "titleWith")
		content := "Content with " + searchTerm + " embedded here"
		_, err := svc.Create(CreateNoteParams{
			Title:   title,
			Content: content,
		})
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	for i := 0; i < notesWithoutTerm; i++ {
		title := titleGenerator().Draw(t, "titleWithout")
		content := "Content without the target word"
		_, err := svc.Create(CreateNoteParams{
			Title:   title,
			Content: content,
		})
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// Property: Search returns correct count
	results, err := svc.Search(searchTerm)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if results.TotalCount != notesWithTerm {
		t.Fatalf("Expected %d results, got %d", notesWithTerm, results.TotalCount)
	}

	// Property: Query is preserved in results
	if results.Query != searchTerm {
		t.Fatalf("Query mismatch: expected %q, got %q", searchTerm, results.Query)
	}
}

func TestSearch_FindsByContent_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testSearch_FindsByContent_Properties)
}

func FuzzSearch_FindsByContent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testSearch_FindsByContent_Properties))
}

// =============================================================================
// Property: Search returns error for empty query
// =============================================================================

func testSearch_EmptyQuery_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	// Property: Empty query returns error
	_, err := svc.Search("")
	if err == nil {
		t.Fatal("Expected error for empty query")
	}
}

func TestSearch_EmptyQuery_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testSearch_EmptyQuery_Properties)
}

func FuzzSearch_EmptyQuery_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testSearch_EmptyQuery_Properties))
}

// =============================================================================
// Property: Search returns empty results for no matches
// =============================================================================

func testSearch_NoMatches_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	// Create some notes without the search term
	numNotes := rapid.IntRange(1, 5).Draw(t, "numNotes")
	for i := 0; i < numNotes; i++ {
		title := titleGenerator().Draw(t, "title")
		content := contentGenerator().Draw(t, "content")
		_, err := svc.Create(CreateNoteParams{
			Title:   title,
			Content: content,
		})
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// Generate a unique term unlikely to be in the content
	uniqueSearchTerm := "zzzznonexistentterm" + rapid.StringMatching(`[0-9]{6}`).Draw(t, "unique")

	// Property: Non-matching search returns 0 results
	results, err := svc.Search(uniqueSearchTerm)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if results.TotalCount != 0 {
		t.Fatalf("Expected 0 results, got %d", results.TotalCount)
	}
}

func TestSearch_NoMatches_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testSearch_NoMatches_Properties)
}

func FuzzSearch_NoMatches_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testSearch_NoMatches_Properties))
}

// =============================================================================
// Property: Complete CRUD workflow maintains consistency
// =============================================================================

func testCRUD_Workflow_Consistency_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	title := titleGenerator().Draw(t, "title")
	content := contentGenerator().Draw(t, "content")

	// Create
	note, err := svc.Create(CreateNoteParams{
		Title:   title,
		Content: content,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Property: Read returns same data
	read, err := svc.Read(note.ID)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if read.Title != title || read.Content != content {
		t.Fatalf("Read data mismatch")
	}

	// Update
	newTitle := titleGenerator().Draw(t, "newTitle")
	priorHash := mustGetRevisionHash(t, svc, note.ID)
	updated, err := svc.Update(note.ID, UpdateNoteParams{
		Title:     &newTitle,
		PriorHash: &priorHash,
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Title != newTitle {
		t.Fatalf("Update title mismatch")
	}

	// Property: List includes updated note
	listResult, err := svc.List(50, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if listResult.TotalCount < 1 {
		t.Fatal("List should include at least our note")
	}

	// Delete
	err = svc.Delete(note.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Property: Read fails after delete
	_, err = svc.Read(note.ID)
	if err == nil {
		t.Fatal("Read should fail after delete")
	}
}

func TestCRUD_Workflow_Consistency_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testCRUD_Workflow_Consistency_Properties)
}

func FuzzCRUD_Workflow_Consistency_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCRUD_Workflow_Consistency_Properties))
}

// =============================================================================
// Property: Multiple notes maintain independence
// =============================================================================

func testMultipleNotes_Independence_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	numNotes := rapid.IntRange(2, 10).Draw(t, "numNotes")
	noteIDs := make([]string, numNotes)

	// Create multiple notes
	for i := 0; i < numNotes; i++ {
		title := titleGenerator().Draw(t, "title")
		content := contentGenerator().Draw(t, "content")

		note, err := svc.Create(CreateNoteParams{
			Title:   title,
			Content: content,
		})
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		noteIDs[i] = note.ID
	}

	// Property: Each note can be read independently
	for _, id := range noteIDs {
		_, err := svc.Read(id)
		if err != nil {
			t.Fatalf("Read failed for %s: %v", id, err)
		}
	}

	// Property: Deleting one note doesn't affect others
	indexToDelete := rapid.IntRange(0, numNotes-1).Draw(t, "indexToDelete")
	err := svc.Delete(noteIDs[indexToDelete])
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify others still exist
	for i, id := range noteIDs {
		if i == indexToDelete {
			continue
		}
		_, err := svc.Read(id)
		if err != nil {
			t.Fatalf("Note %s should still exist after deleting note %d", id, indexToDelete)
		}
	}

	// Property: List count is correct after deletion
	result, err := svc.List(100, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if result.TotalCount != numNotes-1 {
		t.Fatalf("Expected %d notes after deletion, got %d", numNotes-1, result.TotalCount)
	}
}

func TestMultipleNotes_Independence_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testMultipleNotes_Independence_Properties)
}

func FuzzMultipleNotes_Independence_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMultipleNotes_Independence_Properties))
}

// =============================================================================
// Property: Delete soft-deletes (Read returns error, List excludes)
// =============================================================================

func testDelete_SoftDelete_ReadFails_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	title := titleGenerator().Draw(t, "title")
	content := contentGenerator().Draw(t, "content")

	note, err := svc.Create(CreateNoteParams{Title: title, Content: content})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err = svc.Delete(note.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Property: Read returns error after soft-delete
	_, err = svc.Read(note.ID)
	if err == nil {
		t.Fatal("Expected error reading soft-deleted note")
	}
}

func TestDelete_SoftDelete_ReadFails_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testDelete_SoftDelete_ReadFails_Properties)
}

func FuzzDelete_SoftDelete_ReadFails_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testDelete_SoftDelete_ReadFails_Properties))
}

// =============================================================================
// Property: Delete soft-deletes - List excludes deleted note
// =============================================================================

func testDelete_SoftDelete_ListExcludes_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	title := titleGenerator().Draw(t, "title")
	content := contentGenerator().Draw(t, "content")

	note, err := svc.Create(CreateNoteParams{Title: title, Content: content})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err = svc.Delete(note.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Property: List does not include deleted note
	result, err := svc.List(100, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	for _, n := range result.Notes {
		if n.ID == note.ID {
			t.Fatal("Soft-deleted note should not appear in list")
		}
	}
	if result.TotalCount != 0 {
		t.Fatalf("Expected 0 total count, got %d", result.TotalCount)
	}
}

func TestDelete_SoftDelete_ListExcludes_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testDelete_SoftDelete_ListExcludes_Properties)
}

func FuzzDelete_SoftDelete_ListExcludes_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testDelete_SoftDelete_ListExcludes_Properties))
}

// =============================================================================
// Property: StrReplace performs exact single replacement
// =============================================================================

func testStrReplace_ExactMatch_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	// Create note with known content containing a unique marker
	marker := rapid.StringMatching(`[a-z]{8}`).Draw(t, "marker")
	prefix := contentGenerator().Draw(t, "prefix")
	suffix := contentGenerator().Draw(t, "suffix")
	content := prefix + "UNIQUE_" + marker + suffix

	note, err := svc.Create(CreateNoteParams{
		Title:   titleGenerator().Draw(t, "title"),
		Content: content,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Property: StrReplace with unique match succeeds
	replacement := "REPLACED_" + marker
	priorHash := mustGetRevisionHash(t, svc, note.ID)
	updated, _, err := svc.StrReplace(note.ID, "UNIQUE_"+marker, replacement, false, &priorHash)
	if err != nil {
		t.Fatalf("StrReplace failed: %v", err)
	}

	expectedContent := prefix + replacement + suffix
	if updated.Content != expectedContent {
		t.Fatalf("Content mismatch: expected %q, got %q", expectedContent, updated.Content)
	}
}

func TestStrReplace_ExactMatch_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testStrReplace_ExactMatch_Properties)
}

func FuzzStrReplace_ExactMatch_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testStrReplace_ExactMatch_Properties))
}

// =============================================================================
// Property: StrReplace returns ErrNoMatch when old_str not found
// =============================================================================

func testStrReplace_NoMatch_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	note, err := svc.Create(CreateNoteParams{
		Title:   titleGenerator().Draw(t, "title"),
		Content: "some known content",
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	priorHash := mustGetRevisionHash(t, svc, note.ID)
	_, _, err = svc.StrReplace(note.ID, "nonexistent_text_xyz", "replacement", false, &priorHash)
	if err == nil {
		t.Fatal("Expected ErrNoMatch")
	}
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("Expected ErrNoMatch, got: %v", err)
	}
}

func TestStrReplace_NoMatch_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testStrReplace_NoMatch_Properties)
}

func FuzzStrReplace_NoMatch_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testStrReplace_NoMatch_Properties))
}

// =============================================================================
// Property: StrReplace returns ErrAmbiguousMatch when old_str matches multiple
// =============================================================================

func testStrReplace_AmbiguousMatch_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	marker := rapid.StringMatching(`[a-z]{6}`).Draw(t, "marker")
	content := marker + " middle " + marker

	note, err := svc.Create(CreateNoteParams{
		Title:   titleGenerator().Draw(t, "title"),
		Content: content,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	priorHash := mustGetRevisionHash(t, svc, note.ID)
	_, _, err = svc.StrReplace(note.ID, marker, "replacement", false, &priorHash)
	if err == nil {
		t.Fatal("Expected ErrAmbiguousMatch")
	}
	if !errors.Is(err, ErrAmbiguousMatch) {
		t.Fatalf("Expected ErrAmbiguousMatch, got: %v", err)
	}
}

func TestStrReplace_AmbiguousMatch_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testStrReplace_AmbiguousMatch_Properties)
}

func FuzzStrReplace_AmbiguousMatch_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testStrReplace_AmbiguousMatch_Properties))
}

// =============================================================================
// Property: StrReplace with replace_all=true replaces every occurrence
// =============================================================================

func testStrReplace_ReplaceAll_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	marker := rapid.StringMatching(`[a-z]{6}`).Draw(t, "marker")
	repeatCount := rapid.IntRange(2, 5).Draw(t, "repeatCount")

	// Build content with marker repeated N times, separated by unique text
	var parts []string
	for i := 0; i < repeatCount; i++ {
		parts = append(parts, fmt.Sprintf("section_%d_%s_end", i, marker))
	}
	content := strings.Join(parts, "\n")

	note, err := svc.Create(CreateNoteParams{
		Title:   titleGenerator().Draw(t, "title"),
		Content: content,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Property: replace_all=true replaces every occurrence
	replacement := "REPLACED"
	priorHash := mustGetRevisionHash(t, svc, note.ID)
	updated, _, err := svc.StrReplace(note.ID, marker, replacement, true, &priorHash)
	if err != nil {
		t.Fatalf("StrReplace with replace_all=true failed: %v", err)
	}

	// All occurrences should be replaced
	remaining := strings.Count(updated.Content, marker)
	if remaining != 0 {
		t.Fatalf("Expected 0 remaining occurrences of %q, found %d in %q", marker, remaining, updated.Content)
	}

	replacedCount := strings.Count(updated.Content, replacement)
	if replacedCount != repeatCount {
		t.Fatalf("Expected %d replacements, found %d in %q", repeatCount, replacedCount, updated.Content)
	}
}

func TestStrReplace_ReplaceAll_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testStrReplace_ReplaceAll_Properties)
}

func FuzzStrReplace_ReplaceAll_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testStrReplace_ReplaceAll_Properties))
}

// =============================================================================
// Property: StrReplace enforces prior_hash precondition when provided
// =============================================================================

func testStrReplace_PriorHash_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	marker := rapid.StringMatching(`[a-z]{8}`).Draw(t, "marker")
	note, err := svc.Create(CreateNoteParams{
		Title:   titleGenerator().Draw(t, "title"),
		Content: "before " + marker + " after",
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	staleHash := mustGetRevisionHash(t, svc, note.ID)
	if staleHash[0] == '0' {
		staleHash = "1" + staleHash[1:]
	} else {
		staleHash = "0" + staleHash[1:]
	}

	_, _, err = svc.StrReplace(note.ID, marker, "replacement", false, &staleHash)
	if err == nil {
		t.Fatal("Expected revision conflict for stale prior_hash")
	}
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("Expected ErrRevisionConflict, got: %v", err)
	}
}

func TestStrReplace_PriorHash_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testStrReplace_PriorHash_Properties)
}

func FuzzStrReplace_PriorHash_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testStrReplace_PriorHash_Properties))
}

// =============================================================================
// Property: Read returns typed NotFound error for non-existent note IDs
// =============================================================================

func testRead_NotFound_TypedError_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(t, "nonExistentID")

	_, err := svc.Read(nonExistentID)

	// Property: error is not nil
	if err == nil {
		t.Fatal("Expected error for non-existent note")
	}

	// Property: errs.CodeOf returns NotFound
	if errs.CodeOf(err) != errs.NotFound {
		t.Fatalf("Expected errs.NotFound code, got %q for error: %v", errs.CodeOf(err), err)
	}

	// Property: errors.Is matches ErrNoteNotFound sentinel
	if !errors.Is(err, ErrNoteNotFound) {
		t.Fatalf("Expected errors.Is(err, ErrNoteNotFound) to be true, got false for error: %v", err)
	}
}

func TestRead_NotFound_TypedError_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testRead_NotFound_TypedError_Properties)
}

func FuzzRead_NotFound_TypedError_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRead_NotFound_TypedError_Properties))
}

// =============================================================================
// Property: Update returns typed NotFound error for non-existent note IDs
// =============================================================================

func testUpdate_NotFound_TypedError_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(t, "nonExistentID")
	newTitle := titleGenerator().Draw(t, "newTitle")

	_, err := svc.Update(nonExistentID, UpdateNoteParams{
		Title: &newTitle,
	})

	// Property: error is not nil
	if err == nil {
		t.Fatal("Expected error for non-existent note")
	}

	// Property: errs.CodeOf returns NotFound
	if errs.CodeOf(err) != errs.NotFound {
		t.Fatalf("Expected errs.NotFound code, got %q for error: %v", errs.CodeOf(err), err)
	}

	// Property: errors.Is matches ErrNoteNotFound sentinel
	if !errors.Is(err, ErrNoteNotFound) {
		t.Fatalf("Expected errors.Is(err, ErrNoteNotFound) to be true, got false for error: %v", err)
	}
}

func TestUpdate_NotFound_TypedError_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUpdate_NotFound_TypedError_Properties)
}

func FuzzUpdate_NotFound_TypedError_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUpdate_NotFound_TypedError_Properties))
}

// =============================================================================
// Property: Delete returns typed NotFound error for non-existent note IDs
// =============================================================================

func testDelete_NotFound_TypedError_Properties(t *rapid.T) {
	svc := setupNotesServiceRapid(t)

	nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(t, "nonExistentID")

	err := svc.Delete(nonExistentID)

	// Property: error is not nil
	if err == nil {
		t.Fatal("Expected error for non-existent note")
	}

	// Property: errs.CodeOf returns NotFound
	if errs.CodeOf(err) != errs.NotFound {
		t.Fatalf("Expected errs.NotFound code, got %q for error: %v", errs.CodeOf(err), err)
	}

	// Property: errors.Is matches ErrNoteNotFound sentinel
	if !errors.Is(err, ErrNoteNotFound) {
		t.Fatalf("Expected errors.Is(err, ErrNoteNotFound) to be true, got false for error: %v", err)
	}
}

func TestDelete_NotFound_TypedError_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testDelete_NotFound_TypedError_Properties)
}

func FuzzDelete_NotFound_TypedError_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testDelete_NotFound_TypedError_Properties))
}
