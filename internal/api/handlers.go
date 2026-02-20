package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/kuitang/agent-notes/internal/notes"
)

const (
	// HardcodedUserID is used for all requests in Milestone 1 (unauthenticated)
	HardcodedUserID = "test-user-001"
)

// Handler wraps the notes service and provides HTTP handlers
type Handler struct {
	notesService *notes.Service
}

// NewHandler creates a new API handler with the given notes service
func NewHandler(notesService *notes.Service) *Handler {
	return &Handler{notesService: notesService}
}

// RegisterRoutes registers all notes API routes on the given mux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Notes CRUD endpoints using Go 1.22+ routing patterns
	mux.HandleFunc("GET /notes", h.ListNotes)
	mux.HandleFunc("GET /notes/{id}", h.GetNote)
	mux.HandleFunc("POST /notes", h.CreateNote)
	mux.HandleFunc("PUT /notes/{id}", h.UpdateNote)
	mux.HandleFunc("DELETE /notes/{id}", h.DeleteNote)
	mux.HandleFunc("POST /notes/search", h.SearchNotes)
}

// ListNotes handles GET /notes - returns a paginated list of notes
func (h *Handler) ListNotes(w http.ResponseWriter, r *http.Request) {
	// Parse pagination parameters from query string
	limit := 50 // default
	offset := 0 // default

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	result, err := h.notesService.List(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list notes: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// GetNote handles GET /notes/{id} - returns a single note by ID
func (h *Handler) GetNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Note ID is required")
		return
	}

	note, err := h.notesService.Read(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Note not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get note: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, note)
}

// CreateNote handles POST /notes - creates a new note
func (h *Handler) CreateNote(w http.ResponseWriter, r *http.Request) {
	var params notes.CreateNoteParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if params.Title == "" {
		writeError(w, http.StatusBadRequest, "Title is required")
		return
	}

	note, err := h.notesService.Create(params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create note: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, note)
}

// UpdateNote handles PUT /notes/{id} - updates an existing note
func (h *Handler) UpdateNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Note ID is required")
		return
	}

	var params notes.UpdateNoteParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	note, err := h.notesService.Update(id, params)
	if err != nil {
		if errors.Is(err, notes.ErrPriorHashRequired) || errors.Is(err, notes.ErrInvalidPriorHash) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, notes.ErrRevisionConflict) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Note not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to update note: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, note)
}

// DeleteNote handles DELETE /notes/{id} - deletes a note
func (h *Handler) DeleteNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Note ID is required")
		return
	}

	err := h.notesService.Delete(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Note not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete note: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SearchRequest represents the request body for search endpoint
type SearchRequest struct {
	Query string `json:"query"`
}

// SearchNotes handles POST /notes/search - searches notes using FTS5
func (h *Handler) SearchNotes(w http.ResponseWriter, r *http.Request) {
	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "Search query is required")
		return
	}

	results, err := h.notesService.Search(req.Query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to search notes: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, results)
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// writeJSON writes a JSON response with the given status code
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes a JSON error response with the given status code
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, ErrorResponse{Error: message})
}
