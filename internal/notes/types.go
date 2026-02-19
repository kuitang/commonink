package notes

import "time"

// NoteVisibility represents the visibility level of a note.
// Stored as INTEGER in the DB (is_public column): 0=private, 1=public anonymous, 2=public attributed.
type NoteVisibility int

const (
	VisibilityPrivate          NoteVisibility = 0
	VisibilityPublicAnonymous  NoteVisibility = 1
	VisibilityPublicAttributed NoteVisibility = 2
)

// IsPublic returns true if the visibility is any public state (anonymous or attributed).
func (v NoteVisibility) IsPublic() bool {
	return v >= VisibilityPublicAnonymous
}

// IsAnonymous returns true if the visibility is public anonymous.
func (v NoteVisibility) IsAnonymous() bool {
	return v == VisibilityPublicAnonymous
}

// IsAttributed returns true if the visibility is public with author attribution.
func (v NoteVisibility) IsAttributed() bool {
	return v == VisibilityPublicAttributed
}

// Note represents a user's note with metadata
type Note struct {
	ID         string         `json:"id"`
	Title      string         `json:"title"`
	Content    string         `json:"content"`
	Visibility NoteVisibility `json:"visibility"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// NoteListResult represents a paginated list of notes
type NoteListResult struct {
	Notes      []Note `json:"notes"`
	TotalCount int    `json:"total_count"`
	Limit      int    `json:"limit"`
	Offset     int    `json:"offset"`
}

// SearchResult represents a single search result with ranking
type SearchResult struct {
	Note Note    `json:"note"`
	Rank float64 `json:"rank"` // FTS5 rank score
}

// SearchResults represents search results with metadata
type SearchResults struct {
	Results    []SearchResult `json:"results"`
	Query      string         `json:"query"`
	TotalCount int            `json:"total_count"`
}

// CreateNoteParams contains parameters for creating a note
type CreateNoteParams struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

// UpdateNoteParams contains parameters for updating a note
// Both Title and Content are optional (pointer to distinguish empty string from omitted)
type UpdateNoteParams struct {
	Title   *string `json:"title,omitempty"`
	Content *string `json:"content,omitempty"`
}
