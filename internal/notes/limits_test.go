package notes

import (
	"errors"
	"fmt"
	"testing"

	dbtestutil "github.com/kuitang/agent-notes/internal/testdb"
	"pgregory.net/rapid"
)

// =============================================================================
// Test Setup Helpers for Storage Limit Tests
// =============================================================================

func setupLimitsTestService(t interface {
	Fatalf(format string, args ...interface{})
}) *Service {
	testID := testCounter.Add(1)
	userID := fmt.Sprintf("limits-test-%d", testID)

	userDB, err := dbtestutil.NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("failed to create in-memory database: %v", err)
	}
	return NewService(userDB)
}

// =============================================================================
// Property: CheckStorageLimit correctly enforces limit
// =============================================================================

func testCheckStorageLimit_Properties(t *rapid.T) {
	currentSize := rapid.Int64Range(0, StorageLimitBytes).Draw(t, "currentSize")
	newContentSize := rapid.Int64Range(0, StorageLimitBytes).Draw(t, "newContentSize")

	err := CheckStorageLimit(currentSize, newContentSize)

	if currentSize+newContentSize > StorageLimitBytes {
		// Property: Should fail when exceeding limit
		if err == nil {
			t.Fatalf("Expected error when currentSize(%d) + newContentSize(%d) > limit(%d)",
				currentSize, newContentSize, StorageLimitBytes)
		}
		if !errors.Is(err, ErrStorageLimitExceeded) {
			t.Fatalf("Expected ErrStorageLimitExceeded, got: %v", err)
		}
	} else {
		// Property: Should succeed when within limit
		if err != nil {
			t.Fatalf("Expected no error when within limit, got: %v", err)
		}
	}
}

func TestCheckStorageLimit_Properties(t *testing.T) {
	rapid.Check(t, testCheckStorageLimit_Properties)
}

func FuzzCheckStorageLimit_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCheckStorageLimit_Properties))
}

// =============================================================================
// Property: CheckStorageLimitForUpdate allows shrinking content
// =============================================================================

func testCheckStorageLimitForUpdate_ShrinkAlways_Properties(t *rapid.T) {
	oldContentSize := rapid.Int64Range(100, 10000).Draw(t, "oldContentSize")
	newContentSize := rapid.Int64Range(0, oldContentSize).Draw(t, "newContentSize")
	currentTotalSize := rapid.Int64Range(oldContentSize, StorageLimitBytes+10000).Draw(t, "currentTotalSize")

	err := CheckStorageLimitForUpdate(currentTotalSize, oldContentSize, newContentSize)

	// Property: Shrinking content should always succeed
	if err != nil {
		t.Fatalf("Shrinking content should always succeed: old=%d, new=%d, total=%d, err=%v",
			oldContentSize, newContentSize, currentTotalSize, err)
	}
}

func TestCheckStorageLimitForUpdate_ShrinkAlways_Properties(t *testing.T) {
	rapid.Check(t, testCheckStorageLimitForUpdate_ShrinkAlways_Properties)
}

func FuzzCheckStorageLimitForUpdate_ShrinkAlways_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCheckStorageLimitForUpdate_ShrinkAlways_Properties))
}

// =============================================================================
// Property: CheckStorageLimitForUpdate enforces limit for growing content
// =============================================================================

func testCheckStorageLimitForUpdate_GrowEnforced_Properties(t *rapid.T) {
	oldContentSize := rapid.Int64Range(0, 10000).Draw(t, "oldContentSize")
	growAmount := rapid.Int64Range(1, 10000).Draw(t, "growAmount")
	newContentSize := oldContentSize + growAmount
	currentTotalSize := rapid.Int64Range(oldContentSize, StorageLimitBytes+10000).Draw(t, "currentTotalSize")

	err := CheckStorageLimitForUpdate(currentTotalSize, oldContentSize, newContentSize)

	delta := newContentSize - oldContentSize
	if currentTotalSize+delta > StorageLimitBytes {
		if err == nil {
			t.Fatalf("Expected error when growing content would exceed limit")
		}
		if !errors.Is(err, ErrStorageLimitExceeded) {
			t.Fatalf("Expected ErrStorageLimitExceeded, got: %v", err)
		}
	} else {
		if err != nil {
			t.Fatalf("Expected no error when growing stays within limit, got: %v", err)
		}
	}
}

func TestCheckStorageLimitForUpdate_GrowEnforced_Properties(t *testing.T) {
	rapid.Check(t, testCheckStorageLimitForUpdate_GrowEnforced_Properties)
}

func FuzzCheckStorageLimitForUpdate_GrowEnforced_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCheckStorageLimitForUpdate_GrowEnforced_Properties))
}

// =============================================================================
// Property: NewStorageUsageInfo produces valid output
// =============================================================================

func testNewStorageUsageInfo_Properties(t *rapid.T) {
	usedBytes := rapid.Int64Range(0, StorageLimitBytes*2).Draw(t, "usedBytes")

	info := NewStorageUsageInfo(usedBytes)

	// Property: UsedBytes matches input
	if info.UsedBytes != usedBytes {
		t.Fatalf("UsedBytes mismatch: expected %d, got %d", usedBytes, info.UsedBytes)
	}

	// Property: LimitBytes is always StorageLimitBytes
	if info.LimitBytes != StorageLimitBytes {
		t.Fatalf("LimitBytes mismatch: expected %d, got %d", StorageLimitBytes, info.LimitBytes)
	}

	// Property: Percentage is in [0, 100] range
	if info.Percentage < 0 || info.Percentage > 100 {
		t.Fatalf("Percentage out of range: %f", info.Percentage)
	}

	// Property: UsedMB is correct
	expectedMB := float64(usedBytes) / (1024 * 1024)
	diff := info.UsedMB - expectedMB
	if diff > 0.001 || diff < -0.001 {
		t.Fatalf("UsedMB mismatch: expected %f, got %f", expectedMB, info.UsedMB)
	}
}

func TestNewStorageUsageInfo_Properties(t *testing.T) {
	rapid.Check(t, testNewStorageUsageInfo_Properties)
}

func FuzzNewStorageUsageInfo_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNewStorageUsageInfo_Properties))
}

// =============================================================================
// Property: Storage limit constant is exactly 100MB
// =============================================================================

func testStorageLimitConstant_Properties(t *rapid.T) {
	expected := int64(100 * 1024 * 1024)
	if StorageLimitBytes != expected {
		t.Fatalf("StorageLimitBytes should be %d (100MB), got %d", expected, StorageLimitBytes)
	}
}

func TestStorageLimitConstant_Properties(t *testing.T) {
	rapid.Check(t, testStorageLimitConstant_Properties)
}

// =============================================================================
// Property: Empty database has zero storage usage
// =============================================================================

func testEmptyDB_ZeroUsage_Properties(t *rapid.T) {
	svc := setupLimitsTestService(t)

	usage, err := svc.GetStorageUsage()
	if err != nil {
		t.Fatalf("GetStorageUsage failed: %v", err)
	}

	if usage.UsedBytes != 0 {
		t.Fatalf("Empty database should have 0 bytes used, got %d", usage.UsedBytes)
	}

	if usage.Percentage != 0 {
		t.Fatalf("Empty database should have 0%% usage, got %.2f%%", usage.Percentage)
	}
}

func TestEmptyDB_ZeroUsage_Properties(t *testing.T) {
	rapid.Check(t, testEmptyDB_ZeroUsage_Properties)
}

func FuzzEmptyDB_ZeroUsage_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testEmptyDB_ZeroUsage_Properties))
}

// =============================================================================
// Property: Storage usage tracks correctly after create and delete
// =============================================================================

func testStorageUsageTracking_Properties(t *rapid.T) {
	svc := setupLimitsTestService(t)

	numNotes := rapid.IntRange(1, 5).Draw(t, "numNotes")
	var expectedSize int64
	var noteIDs []string

	for i := 0; i < numNotes; i++ {
		title := rapid.StringMatching(`[A-Za-z]{5,20}`).Draw(t, fmt.Sprintf("title%d", i))
		content := rapid.StringMatching(`[A-Za-z0-9 ]{10,100}`).Draw(t, fmt.Sprintf("content%d", i))

		note, err := svc.Create(CreateNoteParams{
			Title:   title,
			Content: content,
		})
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		expectedSize += int64(len(title) + len(content))
		noteIDs = append(noteIDs, note.ID)
	}

	// Property: Storage usage matches sum of all note sizes
	usage, err := svc.GetStorageUsage()
	if err != nil {
		t.Fatalf("GetStorageUsage failed: %v", err)
	}

	if usage.UsedBytes != expectedSize {
		t.Fatalf("Storage usage mismatch: expected %d bytes, got %d bytes", expectedSize, usage.UsedBytes)
	}

	// Delete a note and verify usage decreases
	if len(noteIDs) > 0 {
		deleteIdx := rapid.IntRange(0, len(noteIDs)-1).Draw(t, "deleteIdx")
		deletedNote, err := svc.Read(noteIDs[deleteIdx])
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		deletedSize := int64(len(deletedNote.Title) + len(deletedNote.Content))

		if err := svc.Delete(noteIDs[deleteIdx]); err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		expectedSize -= deletedSize

		usage, err = svc.GetStorageUsage()
		if err != nil {
			t.Fatalf("GetStorageUsage after delete failed: %v", err)
		}

		if usage.UsedBytes != expectedSize {
			t.Fatalf("Storage usage after delete mismatch: expected %d bytes, got %d bytes", expectedSize, usage.UsedBytes)
		}
	}
}

func TestStorageUsageTracking_Properties(t *testing.T) {
	rapid.Check(t, testStorageUsageTracking_Properties)
}

func FuzzStorageUsageTracking_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testStorageUsageTracking_Properties))
}

// =============================================================================
// Property: Creating notes within limit always succeeds
// =============================================================================

func testWithinLimit_CreateSucceeds_Properties(t *rapid.T) {
	svc := setupLimitsTestService(t)

	numNotes := rapid.IntRange(1, 10).Draw(t, "numNotes")

	for i := 0; i < numNotes; i++ {
		title := rapid.StringMatching(`[A-Za-z]{5,20}`).Draw(t, fmt.Sprintf("title%d", i))
		content := rapid.StringMatching(`[A-Za-z0-9 ]{0,200}`).Draw(t, fmt.Sprintf("content%d", i))

		_, err := svc.Create(CreateNoteParams{
			Title:   title,
			Content: content,
		})
		if err != nil {
			t.Fatalf("Create should succeed within limit: %v", err)
		}
	}

	usage, err := svc.GetStorageUsage()
	if err != nil {
		t.Fatalf("GetStorageUsage failed: %v", err)
	}

	if usage.UsedBytes > StorageLimitBytes {
		t.Fatalf("Usage should be within limit: %d > %d", usage.UsedBytes, StorageLimitBytes)
	}
}

func TestWithinLimit_CreateSucceeds_Properties(t *testing.T) {
	rapid.Check(t, testWithinLimit_CreateSucceeds_Properties)
}

func FuzzWithinLimit_CreateSucceeds_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testWithinLimit_CreateSucceeds_Properties))
}

// =============================================================================
// Property: Update that shrinks content always succeeds
// =============================================================================

func testUpdateShrink_AlwaysSucceeds_Properties(t *rapid.T) {
	svc := setupLimitsTestService(t)

	title := rapid.StringMatching(`[A-Za-z]{5,20}`).Draw(t, "title")
	content := rapid.StringMatching(`[A-Za-z0-9 ]{50,200}`).Draw(t, "content")

	note, err := svc.Create(CreateNoteParams{
		Title:   title,
		Content: content,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update with shorter content
	shorterContent := content[:len(content)/2]
	_, err = svc.Update(note.ID, UpdateNoteParams{
		Content: &shorterContent,
	})
	if err != nil {
		t.Fatalf("Update with shorter content should succeed: %v", err)
	}

	// Verify the content was updated
	updated, err := svc.Read(note.ID)
	if err != nil {
		t.Fatalf("Read after update failed: %v", err)
	}
	if updated.Content != shorterContent {
		t.Fatalf("Content not updated: expected %q, got %q", shorterContent, updated.Content)
	}
}

func TestUpdateShrink_AlwaysSucceeds_Properties(t *testing.T) {
	rapid.Check(t, testUpdateShrink_AlwaysSucceeds_Properties)
}

func FuzzUpdateShrink_AlwaysSucceeds_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUpdateShrink_AlwaysSucceeds_Properties))
}
