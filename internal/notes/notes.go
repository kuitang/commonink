package notes

import (
	"context"
	"database/sql"
	"fmt"
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
	userDB *db.UserDB
}

// NewService creates a new notes service for the specified user
func NewService(userDB *db.UserDB) *Service {
	return &Service{userDB: userDB}
}

// NewServiceForHardcodedUser creates a new notes service for the hardcoded test user
// This is a convenience function for Milestone 1
func NewServiceForHardcodedUser() (*Service, error) {
	userDB, err := db.OpenUserDB(HardcodedUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to open user database: %w", err)
	}
	return &Service{userDB: userDB}, nil
}

// GetStorageUsage returns the current storage usage for this user
func (s *Service) GetStorageUsage() (StorageUsageInfo, error) {
	ctx := context.Background()
	totalSize, err := s.userDB.GetTotalNotesSize(ctx)
	if err != nil {
		return StorageUsageInfo{}, fmt.Errorf("failed to get storage usage: %w", err)
	}
	return NewStorageUsageInfo(totalSize), nil
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
	if err := CheckStorageLimit(currentSize, newContentSize); err != nil {
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
		ID:        noteID,
		Title:     params.Title,
		Content:   params.Content,
		IsPublic:  false,
		CreatedAt: now,
		UpdatedAt: now,
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
		ID:        dbNote.ID,
		Title:     dbNote.Title,
		Content:   dbNote.Content,
		IsPublic:  dbNote.IsPublic.Valid && dbNote.IsPublic.Int64 == 1,
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
		if err := CheckStorageLimitForUpdate(currentTotalSize, oldSize, newSize); err != nil {
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
		ID:        id,
		Title:     newTitle,
		Content:   newContent,
		IsPublic:  existing.IsPublic.Valid && existing.IsPublic.Int64 == 1,
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

	err = s.userDB.Queries().DeleteNote(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete note: %w", err)
	}

	return nil
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
			ID:        dbNote.ID,
			Title:     dbNote.Title,
			Content:   dbNote.Content,
			IsPublic:  dbNote.IsPublic.Valid && dbNote.IsPublic.Int64 == 1,
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
				ID:        dbResult.ID,
				Title:     dbResult.Title,
				Content:   dbResult.Content,
				IsPublic:  dbResult.IsPublic == 1,
				CreatedAt: time.Unix(dbResult.CreatedAt, 0).UTC(),
				UpdatedAt: time.Unix(dbResult.UpdatedAt, 0).UTC(),
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
