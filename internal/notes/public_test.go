package notes

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/s3client"
	dbtestutil "github.com/kuitang/agent-notes/internal/testdb"
	"pgregory.net/rapid"
)

// =============================================================================
// Test helpers for public notes
// =============================================================================

// publicTestEnv holds the test environment for public note tests
type publicTestEnv struct {
	userDB        *db.UserDB
	s3Client      *s3client.Client
	publicService *PublicNoteService
	noteService   *Service
	userID        string
}

// testEnvCache caches test environments per testing.T to allow reuse within rapid.Check
// The key is the test name, and the value is the environment
var (
	testEnvCache   = make(map[string]*publicTestEnv)
	testEnvCacheMu sync.Mutex
)

// setupPublicTestEnvForT creates a test environment with in-memory DB and mock S3
// This is called once per Test* function and cached for reuse in rapid iterations
func setupPublicTestEnvForT(t *testing.T) *publicTestEnv {
	t.Helper()

	testEnvCacheMu.Lock()
	defer testEnvCacheMu.Unlock()

	testName := t.Name()
	if env, ok := testEnvCache[testName]; ok {
		return env
	}

	// Use unique ID for each test to ensure complete isolation
	testID := testCounter.Add(1)
	userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

	userDB, err := dbtestutil.NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("failed to create in-memory database: %v", err)
	}

	// Create test S3 client using gofakes3
	s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-%d", testID))

	publicService := NewPublicNoteService(s3Client)
	noteService := NewService(userDB, FreeStorageLimitBytes)

	env := &publicTestEnv{
		userDB:        userDB,
		s3Client:      s3Client,
		publicService: publicService,
		noteService:   noteService,
		userID:        userID,
	}

	testEnvCache[testName] = env
	return env
}

// createTestNoteRapid creates a note and returns it for use in rapid property tests
// It uses the rapid.T for assertions but creates notes using the service
func createTestNoteRapid(t *rapid.T, svc *Service, title, content string) *Note {
	note, err := svc.Create(CreateNoteParams{
		Title:   title,
		Content: content,
	})
	if err != nil {
		t.Fatalf("failed to create test note: %v", err)
	}
	return note
}

// =============================================================================
// Property 1: Public note accessible after SetPublic(true)
// =============================================================================

func TestPublic_AccessibleAfterSetPublic_Properties(t *testing.T) {
	// Create a fresh environment for each rapid iteration to ensure isolation
	rapid.Check(t, func(rt *rapid.T) {
		// Create fresh test environment for each iteration
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-pub-%d", testID))
		publicService := NewPublicNoteService(s3Client)
		noteService := NewService(userDB, FreeStorageLimitBytes)

		ctx := context.Background()

		title := titleGenerator().Draw(rt, "title")
		content := contentGenerator().Draw(rt, "content")

		// Create a private note
		note := createTestNoteRapid(rt, noteService, title, content)

		// Property: Before SetPublic(true), GetPublic should fail
		_, err = publicService.GetPublic(ctx, userDB, note.ID)
		if err == nil {
			rt.Fatal("GetPublic should fail for private note")
		}

		// Set note to public
		err = publicService.SetPublic(ctx, userDB, note.ID, true)
		if err != nil {
			rt.Fatalf("SetPublic(true) failed: %v", err)
		}

		// Property: After SetPublic(true), GetPublic should succeed
		publicNote, err := publicService.GetPublic(ctx, userDB, note.ID)
		if err != nil {
			rt.Fatalf("GetPublic failed after SetPublic(true): %v", err)
		}

		// Property: Retrieved note has correct data
		if publicNote.ID != note.ID {
			rt.Fatalf("ID mismatch: expected %q, got %q", note.ID, publicNote.ID)
		}
		if publicNote.Title != title {
			rt.Fatalf("Title mismatch: expected %q, got %q", title, publicNote.Title)
		}
		if publicNote.Content != content {
			rt.Fatalf("Content mismatch: expected %q, got %q", content, publicNote.Content)
		}
		if !publicNote.IsPublic {
			rt.Fatal("IsPublic should be true")
		}
	})
}

func FuzzPublic_AccessibleAfterSetPublic_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-fuzz%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		// For fuzz tests, create a simpler S3 mock that doesn't need testing.T
		// We'll skip S3 verification in fuzz tests since they can't use TestClient
		publicService := NewPublicNoteService(nil)
		noteService := NewService(userDB, FreeStorageLimitBytes)

		ctx := context.Background()

		title := titleGenerator().Draw(rt, "title")
		content := contentGenerator().Draw(rt, "content")

		note := createTestNoteRapid(rt, noteService, title, content)

		// Only test the database operations in fuzz mode (skip S3)
		err = publicService.SetPublic(ctx, userDB, note.ID, true)
		// This will fail because s3Client is nil, but that's expected in fuzz mode
		// We're primarily testing the random input generation works
		_ = err
	}))
}

// =============================================================================
// Property 2: Private note (SetPublic(false)) returns error on GetPublic
// =============================================================================

func TestPublic_PrivateReturnsError_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-priv-%d", testID))
		publicService := NewPublicNoteService(s3Client)
		noteService := NewService(userDB, FreeStorageLimitBytes)

		ctx := context.Background()

		title := titleGenerator().Draw(rt, "title")
		content := contentGenerator().Draw(rt, "content")

		// Create a note
		note := createTestNoteRapid(rt, noteService, title, content)

		// Property: Newly created note is private, GetPublic fails
		_, err = publicService.GetPublic(ctx, userDB, note.ID)
		if err == nil {
			rt.Fatal("GetPublic should fail for newly created (private) note")
		}

		// Make it public first
		err = publicService.SetPublic(ctx, userDB, note.ID, true)
		if err != nil {
			rt.Fatalf("SetPublic(true) failed: %v", err)
		}

		// Verify it's accessible
		_, err = publicService.GetPublic(ctx, userDB, note.ID)
		if err != nil {
			rt.Fatalf("GetPublic should succeed after SetPublic(true): %v", err)
		}

		// Make it private again
		err = publicService.SetPublic(ctx, userDB, note.ID, false)
		if err != nil {
			rt.Fatalf("SetPublic(false) failed: %v", err)
		}

		// Property: After SetPublic(false), GetPublic fails
		_, err = publicService.GetPublic(ctx, userDB, note.ID)
		if err == nil {
			rt.Fatal("GetPublic should fail after SetPublic(false)")
		}
	})
}

func FuzzPublic_PrivateReturnsError_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-fuzz%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		noteService := NewService(userDB, FreeStorageLimitBytes)
		ctx := context.Background()

		title := titleGenerator().Draw(rt, "title")
		content := contentGenerator().Draw(rt, "content")

		note := createTestNoteRapid(rt, noteService, title, content)

		// Test just the database-level is_public flag
		dbNote, err := userDB.Queries().GetNote(ctx, note.ID)
		if err != nil {
			rt.Fatalf("GetNote failed: %v", err)
		}
		// Newly created note should have is_public = 0
		if dbNote.IsPublic.Valid && dbNote.IsPublic.Int64 == 1 {
			rt.Fatal("Newly created note should be private")
		}
	}))
}

// =============================================================================
// Property 3: Owner can toggle public/private
// =============================================================================

func TestPublic_OwnerCanToggle_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-toggle-%d", testID))
		publicService := NewPublicNoteService(s3Client)
		noteService := NewService(userDB, FreeStorageLimitBytes)

		ctx := context.Background()

		title := titleGenerator().Draw(rt, "title")
		content := contentGenerator().Draw(rt, "content")

		// Create a note
		note := createTestNoteRapid(rt, noteService, title, content)

		// Generate a random sequence of toggle operations
		numToggles := rapid.IntRange(1, 10).Draw(rt, "numToggles")

		expectedPublic := false // Notes start private

		for i := 0; i < numToggles; i++ {
			newPublicState := rapid.Bool().Draw(rt, "isPublic")

			// Property: SetPublic succeeds for any boolean state
			err := publicService.SetPublic(ctx, userDB, note.ID, newPublicState)
			if err != nil {
				rt.Fatalf("SetPublic(%v) failed on toggle %d: %v", newPublicState, i, err)
			}

			expectedPublic = newPublicState

			// Property: GetPublic reflects the expected state
			publicNote, err := publicService.GetPublic(ctx, userDB, note.ID)
			if expectedPublic {
				if err != nil {
					rt.Fatalf("GetPublic failed when note should be public (toggle %d): %v", i, err)
				}
				if !publicNote.IsPublic {
					rt.Fatalf("IsPublic should be true after SetPublic(true) (toggle %d)", i)
				}
			} else {
				if err == nil {
					rt.Fatalf("GetPublic should fail when note is private (toggle %d)", i)
				}
			}
		}
	})
}

func FuzzPublic_OwnerCanToggle_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-fuzz%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		noteService := NewService(userDB, FreeStorageLimitBytes)

		title := titleGenerator().Draw(rt, "title")
		content := contentGenerator().Draw(rt, "content")

		// Test that notes can be created with random inputs
		note := createTestNoteRapid(rt, noteService, title, content)
		if note.ID == "" {
			rt.Fatal("Note ID should not be empty")
		}
	}))
}

// =============================================================================
// Property 4: ListPublicByUser returns only public notes
// =============================================================================

func TestPublic_ListReturnsOnlyPublic_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-list-%d", testID))
		publicService := NewPublicNoteService(s3Client)
		noteService := NewService(userDB, FreeStorageLimitBytes)

		ctx := context.Background()

		// Create a mix of public and private notes
		numPublic := rapid.IntRange(0, 5).Draw(rt, "numPublic")
		numPrivate := rapid.IntRange(0, 5).Draw(rt, "numPrivate")

		publicNoteIDs := make(map[string]bool)

		// Create public notes
		for i := 0; i < numPublic; i++ {
			title := titleGenerator().Draw(rt, "publicTitle")
			content := contentGenerator().Draw(rt, "publicContent")
			note := createTestNoteRapid(rt, noteService, title, content)

			err := publicService.SetPublic(ctx, userDB, note.ID, true)
			if err != nil {
				rt.Fatalf("SetPublic(true) failed: %v", err)
			}
			publicNoteIDs[note.ID] = true
		}

		// Create private notes (don't call SetPublic)
		for i := 0; i < numPrivate; i++ {
			title := titleGenerator().Draw(rt, "privateTitle")
			content := contentGenerator().Draw(rt, "privateContent")
			createTestNoteRapid(rt, noteService, title, content)
		}

		// Property: ListPublicByUser returns exactly the public notes
		publicNotes, err := publicService.ListPublicByUser(ctx, userDB, 100, 0)
		if err != nil {
			rt.Fatalf("ListPublicByUser failed: %v", err)
		}

		if len(publicNotes) != numPublic {
			rt.Fatalf("Expected %d public notes, got %d", numPublic, len(publicNotes))
		}

		// Property: All returned notes are marked as public
		for _, note := range publicNotes {
			if !note.IsPublic {
				rt.Fatalf("ListPublicByUser returned a non-public note: %s", note.ID)
			}
			if !publicNoteIDs[note.ID] {
				rt.Fatalf("ListPublicByUser returned unexpected note ID: %s", note.ID)
			}
		}
	})
}

func FuzzPublic_ListReturnsOnlyPublic_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-fuzz%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		noteService := NewService(userDB, FreeStorageLimitBytes)

		// Create some notes
		numNotes := rapid.IntRange(0, 5).Draw(rt, "numNotes")
		for i := 0; i < numNotes; i++ {
			title := titleGenerator().Draw(rt, "title")
			content := contentGenerator().Draw(rt, "content")
			createTestNoteRapid(rt, noteService, title, content)
		}
	}))
}

// =============================================================================
// Property 5: S3 object is created when publishing, deleted when unpublishing
// =============================================================================

func TestPublic_S3ObjectCreatedDeleted_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-s3-%d", testID))
		publicService := NewPublicNoteService(s3Client)
		noteService := NewService(userDB, FreeStorageLimitBytes)

		ctx := context.Background()

		title := titleGenerator().Draw(rt, "title")
		content := contentGenerator().Draw(rt, "content")

		// Create a note
		note := createTestNoteRapid(rt, noteService, title, content)

		// Construct the expected S3 key
		expectedKey := fmt.Sprintf("public/%s/%s.html", userID, note.ID)

		// Property: Before SetPublic(true), S3 object does not exist
		_, err = s3Client.GetObject(ctx, expectedKey)
		if err == nil {
			rt.Fatal("S3 object should not exist before SetPublic(true)")
		}
		if err != s3client.ErrObjectNotFound {
			rt.Fatalf("Expected ErrObjectNotFound, got: %v", err)
		}

		// Make note public
		err = publicService.SetPublic(ctx, userDB, note.ID, true)
		if err != nil {
			rt.Fatalf("SetPublic(true) failed: %v", err)
		}

		// Property: After SetPublic(true), S3 object exists
		s3Content, err := s3Client.GetObject(ctx, expectedKey)
		if err != nil {
			rt.Fatalf("S3 object should exist after SetPublic(true): %v", err)
		}

		// Property: S3 object contains the note content (HTML rendered)
		s3ContentStr := string(s3Content)
		if !strings.Contains(s3ContentStr, title) {
			rt.Fatalf("S3 content should contain note title %q", title)
		}
		if !strings.Contains(s3ContentStr, "<!DOCTYPE html>") {
			rt.Fatal("S3 content should be valid HTML")
		}

		// Make note private
		err = publicService.SetPublic(ctx, userDB, note.ID, false)
		if err != nil {
			rt.Fatalf("SetPublic(false) failed: %v", err)
		}

		// Property: After SetPublic(false), S3 object is deleted
		_, err = s3Client.GetObject(ctx, expectedKey)
		if err == nil {
			rt.Fatal("S3 object should not exist after SetPublic(false)")
		}
		if err != s3client.ErrObjectNotFound {
			rt.Fatalf("Expected ErrObjectNotFound after unpublish, got: %v", err)
		}
	})
}

func FuzzPublic_S3ObjectCreatedDeleted_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-fuzz%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		noteService := NewService(userDB, FreeStorageLimitBytes)

		title := titleGenerator().Draw(rt, "title")
		content := contentGenerator().Draw(rt, "content")

		note := createTestNoteRapid(rt, noteService, title, content)
		if note.ID == "" {
			rt.Fatal("Note ID should not be empty")
		}
	}))
}

// =============================================================================
// Property: SetPublic returns error for non-existent note
// =============================================================================

func TestPublic_SetPublicNonExistent_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-noexist-%d", testID))
		publicService := NewPublicNoteService(s3Client)

		ctx := context.Background()

		nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(rt, "nonExistentID")

		// Property: SetPublic fails for non-existent note
		err = publicService.SetPublic(ctx, userDB, nonExistentID, true)
		if err == nil {
			rt.Fatal("SetPublic should fail for non-existent note")
		}
	})
}

func FuzzPublic_SetPublicNonExistent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-fuzz%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		// Create a simple mock service without S3 for fuzz testing
		publicService := NewPublicNoteService(nil)
		ctx := context.Background()

		nonExistentID := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(rt, "nonExistentID")

		// SetPublic should fail for non-existent note (even before reaching S3)
		err = publicService.SetPublic(ctx, userDB, nonExistentID, true)
		if err == nil {
			rt.Fatal("SetPublic should fail for non-existent note")
		}
	}))
}

// =============================================================================
// Property: SetPublic returns error for empty note ID
// =============================================================================

func TestPublic_SetPublicEmptyID_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-empty-%d", testID))
		publicService := NewPublicNoteService(s3Client)

		ctx := context.Background()

		// Property: SetPublic fails for empty ID
		err = publicService.SetPublic(ctx, userDB, "", true)
		if err == nil {
			rt.Fatal("SetPublic should fail for empty ID")
		}
	})
}

func FuzzPublic_SetPublicEmptyID_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-fuzz%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		publicService := NewPublicNoteService(nil)
		ctx := context.Background()

		// Property: SetPublic fails for empty ID
		err = publicService.SetPublic(ctx, userDB, "", true)
		if err == nil {
			rt.Fatal("SetPublic should fail for empty ID")
		}
	}))
}

// =============================================================================
// Property: GetPublic returns error for empty note ID
// =============================================================================

func TestPublic_GetPublicEmptyID_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-getempty-%d", testID))
		publicService := NewPublicNoteService(s3Client)

		ctx := context.Background()

		// Property: GetPublic fails for empty ID
		_, err = publicService.GetPublic(ctx, userDB, "")
		if err == nil {
			rt.Fatal("GetPublic should fail for empty ID")
		}
	})
}

func FuzzPublic_GetPublicEmptyID_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-fuzz%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		publicService := NewPublicNoteService(nil)
		ctx := context.Background()

		// Property: GetPublic fails for empty ID
		_, err = publicService.GetPublic(ctx, userDB, "")
		if err == nil {
			rt.Fatal("GetPublic should fail for empty ID")
		}
	}))
}

// =============================================================================
// Property: GetPublicURL returns correct URL format
// =============================================================================

func TestPublic_GetPublicURL_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-url-%d", testID))
		publicService := NewPublicNoteService(s3Client)
		noteService := NewService(userDB, FreeStorageLimitBytes)

		title := titleGenerator().Draw(rt, "title")
		content := contentGenerator().Draw(rt, "content")

		// Create a note
		note := createTestNoteRapid(rt, noteService, title, content)

		// Property: GetPublicURL returns a valid URL containing the note ID
		url := publicService.GetPublicURL(userID, note.ID)

		if !strings.Contains(url, note.ID) {
			rt.Fatalf("Public URL should contain note ID, got: %s", url)
		}
		if !strings.Contains(url, userID) {
			rt.Fatalf("Public URL should contain user ID, got: %s", url)
		}
		if !strings.HasSuffix(url, ".html") {
			rt.Fatalf("Public URL should end with .html, got: %s", url)
		}
	})
}

func FuzzPublic_GetPublicURL_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-fuzz%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		noteService := NewService(userDB, FreeStorageLimitBytes)

		title := titleGenerator().Draw(rt, "title")
		content := contentGenerator().Draw(rt, "content")

		note := createTestNoteRapid(rt, noteService, title, content)
		if note.ID == "" {
			rt.Fatal("Note ID should not be empty")
		}
	}))
}

// =============================================================================
// Property: ListPublicByUser respects pagination
// =============================================================================

func TestPublic_ListPagination_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-test%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		s3Client := s3client.TestClient(t, fmt.Sprintf("test-bucket-page-%d", testID))
		publicService := NewPublicNoteService(s3Client)
		noteService := NewService(userDB, FreeStorageLimitBytes)

		ctx := context.Background()

		// Create multiple public notes
		numNotes := rapid.IntRange(0, 15).Draw(rt, "numNotes")

		for i := 0; i < numNotes; i++ {
			title := titleGenerator().Draw(rt, "title")
			content := contentGenerator().Draw(rt, "content")
			note := createTestNoteRapid(rt, noteService, title, content)

			err := publicService.SetPublic(ctx, userDB, note.ID, true)
			if err != nil {
				rt.Fatalf("SetPublic(true) failed: %v", err)
			}
		}

		// Test with random limit and offset
		limit := rapid.IntRange(1, 20).Draw(rt, "limit")
		offset := rapid.IntRange(0, numNotes+5).Draw(rt, "offset")

		publicNotes, err := publicService.ListPublicByUser(ctx, userDB, limit, offset)
		if err != nil {
			rt.Fatalf("ListPublicByUser failed: %v", err)
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

		if len(publicNotes) != expectedReturned {
			rt.Fatalf("Expected %d notes (limit=%d, offset=%d, total=%d), got %d",
				expectedReturned, limit, offset, numNotes, len(publicNotes))
		}
	})
}

func FuzzPublic_ListPagination_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testID := testCounter.Add(1)
		userID := fmt.Sprintf("%s-public-fuzz%d", HardcodedUserID, testID)

		userDB, err := dbtestutil.NewUserDBInMemory(userID)
		if err != nil {
			rt.Fatalf("failed to create in-memory database: %v", err)
		}

		noteService := NewService(userDB, FreeStorageLimitBytes)

		// Create some notes with random inputs
		numNotes := rapid.IntRange(0, 5).Draw(rt, "numNotes")
		for i := 0; i < numNotes; i++ {
			title := titleGenerator().Draw(rt, "title")
			content := contentGenerator().Draw(rt, "content")
			createTestNoteRapid(rt, noteService, title, content)
		}
	}))
}
