package notes

import (
	"errors"
	"time"
)

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

// Error sentinels for str_replace operations
var (
	// ErrNoMatch is returned when old_string is not found in note content
	ErrNoMatch = errors.New("string to replace not found in note")

	// ErrAmbiguousMatch is returned when old_string matches multiple locations
	ErrAmbiguousMatch = errors.New("found multiple matches of the string to replace")

	// ErrRevisionConflict is returned when a prior_hash precondition fails.
	ErrRevisionConflict = errors.New("note revision conflict")

	// ErrInvalidPriorHash is returned when prior_hash is malformed.
	ErrInvalidPriorHash = errors.New("invalid prior_hash")

	// ErrPriorHashRequired is returned when a mutation is missing prior_hash.
	ErrPriorHashRequired = errors.New("prior_hash is required")
)

// Note represents a user's note with metadata
type Note struct {
	ID           string         `json:"id"`
	Title        string         `json:"title"`
	Content      string         `json:"content"`
	RevisionHash string         `json:"revision_hash,omitempty"`
	Visibility   NoteVisibility `json:"visibility"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
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
	Title     *string `json:"title,omitempty"`
	Content   *string `json:"content,omitempty"`
	PriorHash *string `json:"prior_hash,omitempty"`
}

// NoteViewResult represents a note formatted for viewing with line numbers
type NoteViewResult struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Content      string    `json:"content"`
	TotalLines   int       `json:"total_lines"`
	LineRange    [2]int    `json:"line_range,omitempty"`
	IsPublic     bool      `json:"is_public"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	RevisionHash string    `json:"revision_hash"`
}

// NoteListItem represents a note in a list with preview instead of full content
type NoteListItem struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Preview    string    `json:"preview"`
	TotalLines int       `json:"total_lines"`
	IsPublic   bool      `json:"is_public"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// FTSSnippetResult represents an FTS search result with snippet instead of full content
type FTSSnippetResult struct {
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	Snippet   string  `json:"snippet"`
	IsPublic  bool    `json:"is_public"`
	CreatedAt int64   `json:"created_at"`
	UpdatedAt int64   `json:"updated_at"`
	Rank      float64 `json:"rank"`
}

// SearchSnippetResult represents a search result with snippet for MCP
type SearchSnippetResult struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Snippet   string    `json:"snippet"`
	IsPublic  bool      `json:"is_public"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Rank      float64   `json:"rank"`
}

// NoteCreateResult is the minimal response for note_create (omits content the LLM already knows)
type NoteCreateResult struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	TotalLines   int       `json:"total_lines"`
	IsPublic     bool      `json:"is_public"`
	CreatedAt    time.Time `json:"created_at"`
	RevisionHash string    `json:"revision_hash"`
}

// NoteUpdateResult is the minimal response for note_update (omits content the LLM already knows)
type NoteUpdateResult struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	TotalLines   int       `json:"total_lines"`
	IsPublic     bool      `json:"is_public"`
	UpdatedAt    time.Time `json:"updated_at"`
	RevisionHash string    `json:"revision_hash"`
}

// NoteEditResult is the minimal response for note_edit with a snippet around the edit site
type NoteEditResult struct {
	ID               string    `json:"id"`
	Title            string    `json:"title"`
	TotalLines       int       `json:"total_lines"`
	Snippet          string    `json:"snippet"`
	SnippetLineRange [2]int    `json:"snippet_line_range"`
	ReplacementsMade int       `json:"replacements_made"`
	IsPublic         bool      `json:"is_public"`
	UpdatedAt        time.Time `json:"updated_at"`
	RevisionHash     string    `json:"revision_hash"`
}

// EditMetadata contains metadata about a str_replace operation
type EditMetadata struct {
	ReplacementsMade     int
	FirstMatchByteOffset int // byte offset of the first replacement in the NEW content
}

// SearchSnippetResults represents search results with snippets and optional fallback metadata
type SearchSnippetResults struct {
	Results         []SearchSnippetResult `json:"results"`
	Query           string                `json:"query"`
	TotalCount      int                   `json:"total_count"`
	FallbackApplied bool                  `json:"fallback_applied,omitempty"`
	OriginalError   string                `json:"original_error,omitempty"`
	CorrectedQuery  string                `json:"corrected_query,omitempty"`
}
