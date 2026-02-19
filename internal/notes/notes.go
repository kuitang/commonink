package notes

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/userdb"
)

const (
	// HardcodedUserID is the test user for Milestone 1 (unauthenticated CRUD)
	HardcodedUserID = "test-user-001"

	// DefaultLimit is the default number of notes to return in a list
	DefaultLimit = 50

	// MaxLimit is the maximum number of notes to return in a list
	MaxLimit = 1000
)

// Service handles note CRUD operations using the db layer
type Service struct {
	userDB       *db.UserDB
	storageLimit int64
}

// NewService creates a new notes service. storageLimit of 0 means unlimited (paid users).
func NewService(userDB *db.UserDB, storageLimit int64) *Service {
	return &Service{userDB: userDB, storageLimit: storageLimit}
}

// NewServiceForHardcodedUser creates a new notes service for the hardcoded test user
// This is a convenience function for Milestone 1
func NewServiceForHardcodedUser() (*Service, error) {
	userDB, err := db.OpenUserDB(HardcodedUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to open user database: %w", err)
	}
	return &Service{userDB: userDB, storageLimit: FreeStorageLimitBytes}, nil
}

// GetStorageUsage returns the current storage usage for this user
func (s *Service) GetStorageUsage() (StorageUsageInfo, error) {
	ctx := context.Background()
	totalSize, err := s.userDB.GetTotalNotesSize(ctx)
	if err != nil {
		return StorageUsageInfo{}, fmt.Errorf("failed to get storage usage: %w", err)
	}
	return NewStorageUsageInfo(totalSize, s.storageLimit), nil
}

// Create creates a new note
func (s *Service) Create(params CreateNoteParams) (*Note, error) {
	if params.Title == "" {
		return nil, fmt.Errorf("title is required")
	}

	ctx := context.Background()

	// Check storage limit before creating
	currentSize, err := s.userDB.GetTotalNotesSize(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check storage: %w", err)
	}
	newContentSize := int64(len(params.Title) + len(params.Content))
	if err := CheckStorageLimit(currentSize, newContentSize, s.storageLimit); err != nil {
		return nil, err
	}

	noteID := uuid.New().String()
	now := time.Now().UTC()
	nowUnix := now.Unix()

	err = s.userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        noteID,
		Title:     params.Title,
		Content:   params.Content,
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: nowUnix,
		UpdatedAt: nowUnix,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create note: %w", err)
	}

	return &Note{
		ID:         noteID,
		Title:      params.Title,
		Content:    params.Content,
		Visibility: VisibilityPrivate,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

// Read retrieves a note by ID
func (s *Service) Read(id string) (*Note, error) {
	if id == "" {
		return nil, fmt.Errorf("note ID is required")
	}

	ctx := context.Background()

	dbNote, err := s.userDB.Queries().GetNote(ctx, id)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("note not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read note: %w", err)
	}

	return &Note{
		ID:      dbNote.ID,
		Title:   dbNote.Title,
		Content: dbNote.Content,
		Visibility: func() NoteVisibility {
			if dbNote.IsPublic.Valid {
				return NoteVisibility(dbNote.IsPublic.Int64)
			}
			return VisibilityPrivate
		}(),
		CreatedAt: time.Unix(dbNote.CreatedAt, 0).UTC(),
		UpdatedAt: time.Unix(dbNote.UpdatedAt, 0).UTC(),
	}, nil
}

// Update updates an existing note
func (s *Service) Update(id string, params UpdateNoteParams) (*Note, error) {
	if id == "" {
		return nil, fmt.Errorf("note ID is required")
	}

	ctx := context.Background()

	// Check if note exists first
	existing, err := s.userDB.Queries().GetNote(ctx, id)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("note not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read note: %w", err)
	}

	// Apply updates
	newTitle := existing.Title
	newContent := existing.Content
	if params.Title != nil {
		newTitle = *params.Title
	}
	if params.Content != nil {
		newContent = *params.Content
	}

	// Check storage limit for the size delta
	oldSize := int64(len(existing.Title) + len(existing.Content))
	newSize := int64(len(newTitle) + len(newContent))
	if newSize > oldSize {
		currentTotalSize, err := s.userDB.GetTotalNotesSize(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to check storage: %w", err)
		}
		if err := CheckStorageLimitForUpdate(currentTotalSize, oldSize, newSize, s.storageLimit); err != nil {
			return nil, err
		}
	}

	nowUnix := time.Now().UTC().Unix()

	err = s.userDB.Queries().UpdateNote(ctx, userdb.UpdateNoteParams{
		ID:        id,
		Title:     newTitle,
		Content:   newContent,
		IsPublic:  existing.IsPublic,
		UpdatedAt: nowUnix,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update note: %w", err)
	}

	return &Note{
		ID:      id,
		Title:   newTitle,
		Content: newContent,
		Visibility: func() NoteVisibility {
			if existing.IsPublic.Valid {
				return NoteVisibility(existing.IsPublic.Int64)
			}
			return VisibilityPrivate
		}(),
		CreatedAt: time.Unix(existing.CreatedAt, 0).UTC(),
		UpdatedAt: time.Unix(nowUnix, 0).UTC(),
	}, nil
}

// Delete deletes a note by ID
func (s *Service) Delete(id string) error {
	if id == "" {
		return fmt.Errorf("note ID is required")
	}

	ctx := context.Background()

	// Check if note exists first
	exists, err := s.userDB.Queries().NoteExists(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to check note existence: %w", err)
	}
	if exists == 0 {
		return fmt.Errorf("note not found: %s", id)
	}

	err = s.userDB.Queries().DeleteNote(ctx, userdb.DeleteNoteParams{
		DeletedAt: sql.NullInt64{Int64: time.Now().UTC().Unix(), Valid: true},
		ID:        id,
	})
	if err != nil {
		return fmt.Errorf("failed to delete note: %w", err)
	}

	return nil
}

// Purge permanently removes notes that were soft-deleted more than the given duration ago.
func (s *Service) Purge(olderThan time.Duration) error {
	ctx := context.Background()
	cutoff := time.Now().UTC().Add(-olderThan).Unix()
	return s.userDB.Queries().PurgeDeletedNotes(ctx, sql.NullInt64{Int64: cutoff, Valid: true})
}

// StrReplace performs exact string replacement in a note's content.
// When replaceAll is false, old_string must match exactly one location; returns
// ErrNoMatch if not found, ErrAmbiguousMatch if found multiple times.
// When replaceAll is true, replaces every occurrence (still returns ErrNoMatch if zero).
// Returns the updated note, edit metadata (replacement count + first match byte offset), and error.
func (s *Service) StrReplace(id string, oldStr, newStr string, replaceAll bool) (*Note, *EditMetadata, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("note ID is required")
	}
	if oldStr == "" {
		return nil, nil, fmt.Errorf("old_string is required")
	}

	note, err := s.Read(id)
	if err != nil {
		return nil, nil, err
	}

	count := strings.Count(note.Content, oldStr)
	if count == 0 {
		return nil, nil, fmt.Errorf("%w. Use note_view to see the current content.", ErrNoMatch)
	}
	if count > 1 && !replaceAll {
		return nil, nil, fmt.Errorf("found %d matches of the string to replace, but replace_all is false: %w. To replace all occurrences, set replace_all to true. To replace only one occurrence, provide more surrounding context to uniquely identify the instance.", count, ErrAmbiguousMatch)
	}

	// Capture the byte offset of the first match before replacement
	firstMatchOffset := strings.Index(note.Content, oldStr)

	var newContent string
	replacementsMade := count
	if replaceAll {
		newContent = strings.ReplaceAll(note.Content, oldStr, newStr)
	} else {
		newContent = strings.Replace(note.Content, oldStr, newStr, 1)
		replacementsMade = 1
	}

	updated, err := s.Update(id, UpdateNoteParams{Content: &newContent})
	if err != nil {
		return nil, nil, err
	}

	meta := &EditMetadata{
		ReplacementsMade:     replacementsMade,
		FirstMatchByteOffset: firstMatchOffset,
	}
	return updated, meta, nil
}

// List retrieves a paginated list of notes
func (s *Service) List(limit, offset int) (*NoteListResult, error) {
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	if offset < 0 {
		offset = 0
	}

	ctx := context.Background()

	// Get total count
	totalCount, err := s.userDB.Queries().CountNotes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count notes: %w", err)
	}

	// Get paginated notes
	dbNotes, err := s.userDB.Queries().ListNotes(ctx, userdb.ListNotesParams{
		Limit:  int64(limit),
		Offset: int64(offset),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list notes: %w", err)
	}

	notes := make([]Note, 0, len(dbNotes))
	for _, dbNote := range dbNotes {
		notes = append(notes, Note{
			ID:      dbNote.ID,
			Title:   dbNote.Title,
			Content: dbNote.Content,
			Visibility: func() NoteVisibility {
				if dbNote.IsPublic.Valid {
					return NoteVisibility(dbNote.IsPublic.Int64)
				}
				return VisibilityPrivate
			}(),
			CreatedAt: time.Unix(dbNote.CreatedAt, 0).UTC(),
			UpdatedAt: time.Unix(dbNote.UpdatedAt, 0).UTC(),
		})
	}

	return &NoteListResult{
		Notes:      notes,
		TotalCount: int(totalCount),
		Limit:      limit,
		Offset:     offset,
	}, nil
}

// Search performs full-text search on notes using FTS5
func (s *Service) Search(query string) (*SearchResults, error) {
	if query == "" {
		return nil, fmt.Errorf("search query is required")
	}

	ctx := context.Background()

	// Use the db layer's SearchNotes which handles FTS5 properly
	dbResults, err := s.userDB.SearchNotes(ctx, query, MaxLimit, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to search notes: %w", err)
	}

	results := make([]SearchResult, 0, len(dbResults))
	for _, dbResult := range dbResults {
		results = append(results, SearchResult{
			Note: Note{
				ID:         dbResult.ID,
				Title:      dbResult.Title,
				Content:    dbResult.Content,
				Visibility: NoteVisibility(dbResult.IsPublic),
				CreatedAt:  time.Unix(dbResult.CreatedAt, 0).UTC(),
				UpdatedAt:  time.Unix(dbResult.UpdatedAt, 0).UTC(),
			},
			Rank: dbResult.Rank,
		})
	}

	return &SearchResults{
		Results:    results,
		Query:      query,
		TotalCount: len(results),
	}, nil
}

// SearchWithSnippets performs full-text search returning snippets instead of full content.
// Uses FTS5 snippet() for efficient extraction and supports raw FTS5 query syntax.
// When the raw query has a syntax error, falls back to an escaped version and includes
// fallback metadata (original error, corrected query) in the response.
func (s *Service) SearchWithSnippets(query string) (*SearchSnippetResults, error) {
	if query == "" {
		return nil, fmt.Errorf("search query is required")
	}

	ctx := context.Background()

	dbResult, err := s.userDB.SearchNotesWithSnippets(ctx, query, int64(MaxLimit), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to search notes: %w", err)
	}

	results := make([]SearchSnippetResult, 0, len(dbResult.Results))
	for _, r := range dbResult.Results {
		results = append(results, SearchSnippetResult{
			ID:        r.ID,
			Title:     r.Title,
			Snippet:   r.Snippet,
			IsPublic:  r.IsPublic,
			CreatedAt: time.Unix(r.CreatedAt, 0).UTC(),
			UpdatedAt: time.Unix(r.UpdatedAt, 0).UTC(),
			Rank:      r.Rank,
		})
	}

	return &SearchSnippetResults{
		Results:         results,
		Query:           query,
		TotalCount:      len(results),
		FallbackApplied: dbResult.FallbackApplied,
		OriginalError:   dbResult.OriginalError,
		CorrectedQuery:  dbResult.CorrectedQuery,
	}, nil
}
