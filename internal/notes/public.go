package notes

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/userdb"
	"github.com/kuitang/agent-notes/internal/s3client"
	"github.com/kuitang/agent-notes/internal/shorturl"
	"github.com/kuitang/agent-notes/internal/urlutil"
)

// PublicNoteService handles public note operations including toggling visibility
// and uploading/deleting rendered HTML from S3 storage.
type PublicNoteService struct {
	s3          *s3client.Client
	shortURLSvc *shorturl.Service
	baseURL     string
}

// NewPublicNoteService creates a new public note service with the given S3 client.
func NewPublicNoteService(s3 *s3client.Client) *PublicNoteService {
	return &PublicNoteService{s3: s3}
}

// WithShortURLService sets the short URL service for generating short URLs.
func (s *PublicNoteService) WithShortURLService(svc *shorturl.Service, baseURL string) *PublicNoteService {
	s.shortURLSvc = svc
	s.baseURL = baseURL
	return s
}

// publicNoteKey returns the object storage key for a public note.
// Format: public/{user_id}/{note_id}.html
func publicNoteKey(userID, noteID string) string {
	return fmt.Sprintf("public/%s/%s.html", userID, noteID)
}

// SetPublic sets the visibility of a note.
// When vis >= VisibilityPublicAnonymous: renders HTML, uploads to S3, creates short URL.
//   - VisibilityPublicAttributed: looks up user email for author attribution.
//   - VisibilityPublicAnonymous: empty author string.
//
// When vis == VisibilityPrivate: deletes from S3 and short URL.
func (s *PublicNoteService) SetPublic(ctx context.Context, userDB *db.UserDB, noteID string, vis NoteVisibility) error {
	if noteID == "" {
		return fmt.Errorf("note ID is required")
	}

	// Get the note first to verify it exists and get content for rendering
	dbNote, err := userDB.Queries().GetNote(ctx, noteID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("note not found: %s", noteID)
	}
	if err != nil {
		return fmt.Errorf("failed to get note: %w", err)
	}

	nowUnix := time.Now().UTC().Unix()

	// Update the is_public value in the database
	err = userDB.Queries().UpdateNotePublic(ctx, userdb.UpdateNotePublicParams{
		ID:        noteID,
		IsPublic:  sql.NullInt64{Int64: int64(vis), Valid: true},
		UpdatedAt: nowUnix,
	})
	if err != nil {
		return fmt.Errorf("failed to update note public status: %w", err)
	}

	userID := userDB.UserID()
	key := publicNoteKey(userID, noteID)

	if vis.IsPublic() {
		// Determine author string for attribution
		author := ""
		if vis == VisibilityPublicAttributed {
			account, err := userDB.Queries().GetAccount(ctx, userID)
			if err == nil {
				author = account.Email
			}
		}

		// Render note to HTML and upload
		html, err := renderNoteHTML(dbNote.Title, dbNote.Content, userID, noteID, author)
		if err != nil {
			return fmt.Errorf("failed to render note HTML: %w", err)
		}

		err = s.s3.PutObject(ctx, key, html, "text/html; charset=utf-8")
		if err != nil {
			return fmt.Errorf("failed to upload public note: %w", err)
		}

		// Create short URL mapping if service is configured
		if s.shortURLSvc != nil {
			fullPath := fmt.Sprintf("/public/%s/%s", userID, noteID)
			_, err = s.shortURLSvc.Create(ctx, fullPath)
			if err != nil {
				// Log but don't fail - short URL is a convenience feature
			}
		}
	} else {
		// Delete from S3 storage (ignore not found errors)
		err = s.s3.DeleteObject(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to delete public note: %w", err)
		}

		// Delete short URL mapping if service is configured
		if s.shortURLSvc != nil {
			fullPath := fmt.Sprintf("/public/%s/%s", userID, noteID)
			_ = s.shortURLSvc.DeleteByFullPath(ctx, fullPath)
		}
	}

	return nil
}

// GetPublic retrieves a public note by ID without requiring authentication.
// Returns an error if the note is not found or is not public (is_public >= 1).
func (s *PublicNoteService) GetPublic(ctx context.Context, userDB *db.UserDB, noteID string) (*Note, error) {
	if noteID == "" {
		return nil, fmt.Errorf("note ID is required")
	}

	dbNote, err := userDB.Queries().GetNote(ctx, noteID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("note not found: %s", noteID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get note: %w", err)
	}

	// Check if note is public (is_public >= 1)
	vis := VisibilityPrivate
	if dbNote.IsPublic.Valid {
		vis = NoteVisibility(dbNote.IsPublic.Int64)
	}
	if !vis.IsPublic() {
		return nil, fmt.Errorf("note is not public: %s", noteID)
	}

	return &Note{
		ID:         dbNote.ID,
		Title:      dbNote.Title,
		Content:    dbNote.Content,
		Visibility: vis,
		CreatedAt:  time.Unix(dbNote.CreatedAt, 0).UTC(),
		UpdatedAt:  time.Unix(dbNote.UpdatedAt, 0).UTC(),
	}, nil
}

// ListPublicByUser returns all public notes for a given user.
func (s *PublicNoteService) ListPublicByUser(ctx context.Context, userDB *db.UserDB, limit, offset int) ([]*Note, error) {
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	if offset < 0 {
		offset = 0
	}

	dbNotes, err := userDB.Queries().ListPublicNotes(ctx, userdb.ListPublicNotesParams{
		Limit:  int64(limit),
		Offset: int64(offset),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list public notes: %w", err)
	}

	notes := make([]*Note, 0, len(dbNotes))
	for _, dbNote := range dbNotes {
		vis := VisibilityPublicAnonymous
		if dbNote.IsPublic.Valid {
			vis = NoteVisibility(dbNote.IsPublic.Int64)
		}
		notes = append(notes, &Note{
			ID:         dbNote.ID,
			Title:      dbNote.Title,
			Content:    dbNote.Content,
			Visibility: vis,
			CreatedAt:  time.Unix(dbNote.CreatedAt, 0).UTC(),
			UpdatedAt:  time.Unix(dbNote.UpdatedAt, 0).UTC(),
		})
	}

	return notes, nil
}

// GetPublicURL returns the public URL for a note.
func (s *PublicNoteService) GetPublicURL(userID, noteID string) string {
	key := publicNoteKey(userID, noteID)
	return s.s3.GetPublicURL(key)
}

// GetShortURL returns the short URL for a public note.
// Returns an empty string if no short URL exists or service is not configured.
func (s *PublicNoteService) GetShortURL(ctx context.Context, userID, noteID string, baseURLs ...string) string {
	if s.shortURLSvc == nil {
		return ""
	}

	fullPath := fmt.Sprintf("/public/%s/%s", userID, noteID)
	shortURL, err := s.shortURLSvc.GetByFullPath(ctx, fullPath)
	if err != nil {
		return ""
	}

	baseURL := s.baseURL
	if len(baseURLs) > 0 && strings.TrimSpace(baseURLs[0]) != "" {
		baseURL = baseURLs[0]
	}

	return urlutil.BuildAbsolute(baseURL, "/pub/"+shortURL.ShortID)
}

// renderNoteHTML renders a note's markdown content to a complete HTML document.
func renderNoteHTML(title, content, userID, noteID, author string) ([]byte, error) {
	description := content
	if len(description) > 160 {
		description = description[:160] + "..."
	}

	canonicalURL := fmt.Sprintf("/public/%s/%s", userID, noteID)

	return RenderMarkdownToHTML(content, title, description, canonicalURL, author), nil
}
