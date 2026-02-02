package notes

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/userdb"
	"github.com/kuitang/agent-notes/internal/s3client"
)

// PublicNoteService handles public note operations including toggling visibility
// and uploading/deleting rendered HTML from S3 storage.
type PublicNoteService struct {
	s3 *s3client.Client
}

// NewPublicNoteService creates a new public note service with the given S3 client.
func NewPublicNoteService(s3 *s3client.Client) *PublicNoteService {
	return &PublicNoteService{s3: s3}
}

// publicNoteKey returns the object storage key for a public note.
// Format: public/{user_id}/{note_id}.html
func publicNoteKey(userID, noteID string) string {
	return fmt.Sprintf("public/%s/%s.html", userID, noteID)
}

// SetPublic toggles the public visibility of a note.
// When isPublic is true, renders the note to HTML and uploads to object storage.
// When isPublic is false, deletes the rendered HTML from object storage.
func (s *PublicNoteService) SetPublic(ctx context.Context, userDB *db.UserDB, noteID string, isPublic bool) error {
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

	// Update the is_public flag in the database
	isPublicValue := int64(0)
	if isPublic {
		isPublicValue = 1
	}

	err = userDB.Queries().UpdateNotePublic(ctx, userdb.UpdateNotePublicParams{
		ID:        noteID,
		IsPublic:  sql.NullInt64{Int64: isPublicValue, Valid: true},
		UpdatedAt: nowUnix,
	})
	if err != nil {
		return fmt.Errorf("failed to update note public status: %w", err)
	}

	userID := userDB.UserID()
	key := publicNoteKey(userID, noteID)

	if isPublic {
		// Render note to HTML and upload
		html, err := renderNoteHTML(dbNote.Title, dbNote.Content, userID, noteID)
		if err != nil {
			return fmt.Errorf("failed to render note HTML: %w", err)
		}

		err = s.s3.PutObject(ctx, key, html, "text/html; charset=utf-8")
		if err != nil {
			return fmt.Errorf("failed to upload public note: %w", err)
		}
	} else {
		// Delete from S3 storage (ignore not found errors)
		err = s.s3.DeleteObject(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to delete public note: %w", err)
		}
	}

	return nil
}

// GetPublic retrieves a public note by ID without requiring authentication.
// Returns an error if the note is not found or is not public.
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

	// Check if note is public
	if !dbNote.IsPublic.Valid || dbNote.IsPublic.Int64 != 1 {
		return nil, fmt.Errorf("note is not public: %s", noteID)
	}

	return &Note{
		ID:        dbNote.ID,
		Title:     dbNote.Title,
		Content:   dbNote.Content,
		IsPublic:  true,
		CreatedAt: time.Unix(dbNote.CreatedAt, 0).UTC(),
		UpdatedAt: time.Unix(dbNote.UpdatedAt, 0).UTC(),
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
		notes = append(notes, &Note{
			ID:        dbNote.ID,
			Title:     dbNote.Title,
			Content:   dbNote.Content,
			IsPublic:  true, // All returned notes are public
			CreatedAt: time.Unix(dbNote.CreatedAt, 0).UTC(),
			UpdatedAt: time.Unix(dbNote.UpdatedAt, 0).UTC(),
		})
	}

	return notes, nil
}

// GetPublicURL returns the public URL for a note.
func (s *PublicNoteService) GetPublicURL(userID, noteID string) string {
	key := publicNoteKey(userID, noteID)
	return s.s3.GetPublicURL(key)
}

// publicNoteHTMLTemplate is the HTML template for rendering public notes.
// It includes basic SEO tags and responsive styling.
const publicNoteHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="index, follow">
    <meta property="og:title" content="{{.Title}}">
    <meta property="og:type" content="article">
    <meta property="og:url" content="{{.URL}}">
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="{{.Title}}">
    <title>{{.Title}}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            color: #333;
        }
        h1 {
            border-bottom: 1px solid #eee;
            padding-bottom: 0.5rem;
        }
        pre {
            background: #f4f4f4;
            padding: 1rem;
            overflow-x: auto;
            border-radius: 4px;
        }
        code {
            background: #f4f4f4;
            padding: 0.2rem 0.4rem;
            border-radius: 2px;
        }
        pre code {
            padding: 0;
        }
    </style>
</head>
<body>
    <article>
        <h1>{{.Title}}</h1>
        <div class="content"><pre>{{.Content}}</pre></div>
    </article>
</body>
</html>`

type publicNoteTemplateData struct {
	Title   string
	Content string // Plain text content - template will escape it
	URL     string
}

// renderNoteHTML renders a note's content to HTML.
// For now, content is treated as plain text and wrapped in a <pre> tag.
// In the future, this could support Markdown rendering.
func renderNoteHTML(title, content, userID, noteID string) ([]byte, error) {
	tmpl, err := template.New("public_note").Parse(publicNoteHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Pass content as plain text - template will escape it automatically
	data := publicNoteTemplateData{
		Title:   title,
		Content: content, // Template escapes this when rendering
		URL:     fmt.Sprintf("/public/%s/%s", userID, noteID),
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.Bytes(), nil
}
