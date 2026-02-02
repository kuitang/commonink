// Remote Notes MicroSaaS - Main Server Entry Point
// Milestone 2: Authentication, encryption, and per-user databases

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/mcp"
	"github.com/kuitang/agent-notes/internal/notes"
)

const (
	// DefaultAddr is the default listen address
	DefaultAddr = ":8080"

	// ShutdownTimeout is the graceful shutdown timeout
	ShutdownTimeout = 30 * time.Second
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Remote Notes MicroSaaS - Starting server (Milestone 2)...")

	// Get listen address from environment or use default
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = DefaultAddr
	}

	// Load master key from environment (REQUIRED for envelope encryption)
	masterKeyHex := os.Getenv("MASTER_KEY")
	if masterKeyHex == "" {
		// For development/testing, generate a random key
		log.Println("WARNING: MASTER_KEY not set, using random key (NOT FOR PRODUCTION)")
		randomKey, err := crypto.GenerateDEK()
		if err != nil {
			log.Fatalf("Failed to generate random master key: %v", err)
		}
		masterKeyHex = hex.EncodeToString(randomKey)
	}
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil || len(masterKey) != 32 {
		log.Fatalf("Invalid MASTER_KEY: must be 64 hex characters (32 bytes)")
	}
	log.Println("Master key loaded")

	// Initialize sessions database
	log.Println("Initializing sessions database...")
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		log.Fatalf("Failed to open sessions database: %v", err)
	}
	log.Println("Sessions database initialized")

	// Initialize key manager for envelope encryption
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)
	log.Println("Key manager initialized")

	// Initialize services (using mocks for M2)
	emailService := email.NewMockEmailService()
	oidcClient := auth.NewMockOIDCClient()

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost" + addr
	}

	userService := auth.NewUserService(sessionsDB, emailService, baseURL)
	sessionService := auth.NewSessionService(sessionsDB)

	// Initialize auth middleware and handlers
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)
	authHandler := auth.NewHandler(oidcClient, userService, sessionService)

	// Create HTTP mux
	mux := http.NewServeMux()

	// Health check endpoint (no auth required)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"remote-notes","milestone":2}`))
	})

	// Register auth routes (no auth required for these)
	authHandler.RegisterRoutes(mux)
	log.Println("Auth routes registered at /auth/*")

	// Create authenticated notes handler
	notesHandler := &AuthenticatedNotesHandler{}

	// Register protected notes API routes
	mux.Handle("GET /notes", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.ListNotes)))
	mux.Handle("POST /notes", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.CreateNote)))
	mux.Handle("GET /notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.GetNote)))
	mux.Handle("PUT /notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.UpdateNote)))
	mux.Handle("DELETE /notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.DeleteNote)))
	mux.Handle("POST /notes/search", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.SearchNotes)))
	log.Println("Protected notes API routes registered at /notes")

	// Create and mount MCP server (requires auth)
	mcpHandler := &AuthenticatedMCPHandler{}
	mux.Handle("/mcp", authMiddleware.RequireAuth(http.HandlerFunc(mcpHandler.ServeHTTP)))
	log.Println("MCP server mounted at /mcp (protected)")

	// Create HTTP server
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to receive server errors
	serverErr := make(chan error, 1)

	// Start server in goroutine
	go func() {
		log.Printf("Server listening on %s", addr)
		log.Println("Endpoints:")
		log.Println("  GET  /health                      - Health check (no auth)")
		log.Println("  GET  /auth/google                 - Google OIDC login")
		log.Println("  GET  /auth/google/callback        - Google OIDC callback")
		log.Println("  POST /auth/magic                  - Request magic link")
		log.Println("  GET  /auth/magic/verify           - Verify magic link")
		log.Println("  POST /auth/register               - Email/password registration")
		log.Println("  POST /auth/login                  - Email/password login")
		log.Println("  POST /auth/password/reset         - Request password reset")
		log.Println("  POST /auth/password/reset/confirm - Confirm password reset")
		log.Println("  POST /auth/logout                 - Logout")
		log.Println("  GET  /auth/whoami                 - Current user info")
		log.Println("  GET  /notes                       - List notes (protected)")
		log.Println("  POST /notes                       - Create note (protected)")
		log.Println("  GET  /notes/{id}                  - Get note (protected)")
		log.Println("  PUT  /notes/{id}                  - Update note (protected)")
		log.Println("  DELETE /notes/{id}                - Delete note (protected)")
		log.Println("  POST /notes/search                - Search notes (protected)")
		log.Println("  POST /mcp                         - MCP endpoint (protected)")
		log.Println("")
		log.Println("Server ready to accept connections")
		serverErr <- server.ListenAndServe()
	}()

	// Set up signal handling for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal or server error
	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	case sig := <-quit:
		log.Printf("Received signal %v, initiating graceful shutdown...", sig)
	}

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()

	// Shutdown HTTP server
	log.Println("Shutting down HTTP server...")
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	// Close all database connections
	log.Println("Closing database connections...")
	if err := db.CloseAll(); err != nil {
		log.Printf("Database close error: %v", err)
	}

	log.Println("Server shutdown complete")
}

// AuthenticatedNotesHandler wraps notes operations with auth context
type AuthenticatedNotesHandler struct{}

func (h *AuthenticatedNotesHandler) getService(r *http.Request) (*notes.Service, error) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		return nil, fmt.Errorf("no user database in context")
	}
	return notes.NewService(userDB), nil
}

// ListNotes handles GET /notes - returns a paginated list of notes
func (h *AuthenticatedNotesHandler) ListNotes(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

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

	result, err := svc.List(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list notes: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// GetNote handles GET /notes/{id} - returns a single note by ID
func (h *AuthenticatedNotesHandler) GetNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Note ID is required")
		return
	}

	note, err := svc.Read(id)
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
func (h *AuthenticatedNotesHandler) CreateNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	var params notes.CreateNoteParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if params.Title == "" {
		writeError(w, http.StatusBadRequest, "Title is required")
		return
	}

	note, err := svc.Create(params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create note: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, note)
}

// UpdateNote handles PUT /notes/{id} - updates an existing note
func (h *AuthenticatedNotesHandler) UpdateNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

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

	note, err := svc.Update(id, params)
	if err != nil {
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
func (h *AuthenticatedNotesHandler) DeleteNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Note ID is required")
		return
	}

	err = svc.Delete(id)
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
func (h *AuthenticatedNotesHandler) SearchNotes(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "Search query is required")
		return
	}

	results, err := svc.Search(req.Query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to search notes: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, results)
}

// AuthenticatedMCPHandler wraps MCP with auth context
type AuthenticatedMCPHandler struct{}

func (h *AuthenticatedMCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	notesSvc := notes.NewService(userDB)
	mcpServer := mcp.NewServer(notesSvc)
	mcpServer.ServeHTTP(w, r)
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
