// Remote Notes MicroSaaS - Main Server Entry Point
// Milestone 3: Web UI, rate limiting, and public notes

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/mcp"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/ratelimit"
	"github.com/kuitang/agent-notes/internal/s3client"
	"github.com/kuitang/agent-notes/internal/web"
)

const (
	// DefaultAddr is the default listen address
	DefaultAddr = ":8080"

	// ShutdownTimeout is the graceful shutdown timeout
	ShutdownTimeout = 30 * time.Second

	// DefaultBucketName is the default S3 bucket for mock storage
	DefaultBucketName = "remote-notes"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Remote Notes MicroSaaS - Starting server (Milestone 3)...")

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

	// Initialize rate limiter
	rateLimiter := ratelimit.NewRateLimiter(ratelimit.DefaultConfig)
	log.Println("Rate limiter initialized with default config")

	// Initialize S3 client
	s3Client, s3Cleanup := initS3Client()
	if s3Cleanup != nil {
		defer s3Cleanup()
	}
	log.Println("S3 client initialized")

	// Initialize template renderer
	templatesDir := os.Getenv("TEMPLATES_DIR")
	if templatesDir == "" {
		templatesDir = "./web/templates"
	}
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		log.Fatalf("Failed to initialize template renderer: %v", err)
	}
	log.Printf("Template renderer initialized with templates from %s", templatesDir)

	// Initialize services (using mocks for M2/M3)
	emailService := email.NewMockEmailService()
	oidcClient := auth.NewMockOIDCClient()

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost" + addr
	}

	publicNotesURL := os.Getenv("PUBLIC_NOTES_URL")
	if publicNotesURL == "" {
		publicNotesURL = baseURL + "/public"
	}

	userService := auth.NewUserService(sessionsDB, emailService, baseURL)
	sessionService := auth.NewSessionService(sessionsDB)
	consentService := auth.NewConsentService(sessionsDB)

	// Initialize public notes service
	publicNotes := notes.NewPublicNoteService(s3Client)

	// Initialize auth middleware and handlers
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)
	authHandler := auth.NewHandler(oidcClient, userService, sessionService)

	// Initialize web handler with all services
	webHandler := web.NewWebHandler(
		renderer,
		nil, // notesService is created per-request with user's DB
		publicNotes,
		userService,
		sessionService,
		consentService,
		s3Client,
		baseURL,
	)

	// Create HTTP mux
	mux := http.NewServeMux()

	// Health check endpoint (no auth required, no rate limiting)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"remote-notes","milestone":3}`))
	})

	// Register web UI routes (handles /, /login, /register, /notes/*, /public/*, /oauth/consent)
	webHandler.RegisterRoutes(mux, authMiddleware)
	log.Println("Web UI routes registered")

	// Register auth API routes (no auth required for these)
	authHandler.RegisterRoutes(mux)
	log.Println("Auth API routes registered at /auth/*")

	// Rate limiting middleware - extracts user ID and paid status from request
	getUserID := func(r *http.Request) string {
		return auth.GetUserID(r.Context())
	}
	getIsPaid := func(r *http.Request) bool {
		// TODO: Check subscription status from user record
		// For now, all users are free tier
		return false
	}
	rateLimitMW := ratelimit.RateLimitMiddleware(rateLimiter, getUserID, getIsPaid)

	// Create authenticated notes handler with rate limiting
	notesHandler := &AuthenticatedNotesHandler{}

	// Register protected notes API routes with rate limiting
	mux.Handle("GET /api/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.ListNotes))))
	mux.Handle("POST /api/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.CreateNote))))
	mux.Handle("GET /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.GetNote))))
	mux.Handle("PUT /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.UpdateNote))))
	mux.Handle("DELETE /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.DeleteNote))))
	mux.Handle("POST /api/notes/search", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.SearchNotes))))
	log.Println("Protected notes API routes registered at /api/notes with rate limiting")

	// Create and mount MCP server (requires auth + rate limiting)
	mcpHandler := &AuthenticatedMCPHandler{}
	mux.Handle("/mcp", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(mcpHandler.ServeHTTP))))
	log.Println("MCP server mounted at /mcp (protected with rate limiting)")

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
		log.Println("  Web UI:")
		log.Println("    GET  /                           - Landing (redirects)")
		log.Println("    GET  /login                      - Login page")
		log.Println("    GET  /register                   - Registration page")
		log.Println("    GET  /password-reset             - Password reset page")
		log.Println("    GET  /notes                      - Notes list (protected)")
		log.Println("    GET  /notes/new                  - New note form (protected)")
		log.Println("    GET  /notes/{id}                 - View note (protected)")
		log.Println("    GET  /notes/{id}/edit            - Edit note form (protected)")
		log.Println("    GET  /public/{user_id}/{note_id} - Public note view")
		log.Println("    GET  /oauth/consent              - OAuth consent page (protected)")
		log.Println("  Auth API:")
		log.Println("    GET  /auth/google                - Google OIDC login")
		log.Println("    GET  /auth/google/callback       - Google OIDC callback")
		log.Println("    POST /auth/magic                 - Request magic link")
		log.Println("    GET  /auth/magic/verify          - Verify magic link")
		log.Println("    POST /auth/register              - Email/password registration")
		log.Println("    POST /auth/login                 - Email/password login")
		log.Println("    POST /auth/password/reset        - Request password reset")
		log.Println("    POST /auth/password/reset/confirm - Confirm password reset")
		log.Println("    POST /auth/logout                - Logout")
		log.Println("    GET  /auth/whoami                - Current user info")
		log.Println("  Notes API (rate limited):")
		log.Println("    GET  /api/notes                  - List notes (protected)")
		log.Println("    POST /api/notes                  - Create note (protected)")
		log.Println("    GET  /api/notes/{id}             - Get note (protected)")
		log.Println("    PUT  /api/notes/{id}             - Update note (protected)")
		log.Println("    DELETE /api/notes/{id}           - Delete note (protected)")
		log.Println("    POST /api/notes/search           - Search notes (protected)")
		log.Println("  MCP (rate limited):")
		log.Println("    POST /mcp                        - MCP endpoint (protected)")
		log.Println("  Health:")
		log.Println("    GET  /health                     - Health check")
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

	// Stop rate limiter cleanup goroutine
	log.Println("Stopping rate limiter...")
	rateLimiter.Stop()

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

// initS3Client initializes the S3 client based on environment variables.
// If USE_MOCK_S3=true (default), creates an in-memory mock S3 server.
// Otherwise, creates a real S3 client with Tigris configuration.
func initS3Client() (*s3client.Client, func()) {
	useMockS3 := os.Getenv("USE_MOCK_S3")
	if useMockS3 == "" {
		useMockS3 = "true" // Default to mock for development
	}

	if useMockS3 == "true" {
		log.Println("Using mock S3 (gofakes3) for development")
		return createMockS3Client()
	}

	log.Println("Using real S3 client (Tigris)")
	return createRealS3Client(), nil
}

// createMockS3Client creates an in-memory S3 client using gofakes3.
func createMockS3Client() (*s3client.Client, func()) {
	// Create in-memory S3 backend
	backend := s3mem.New()
	faker := gofakes3.New(backend)

	// Create test HTTP server
	ts := httptest.NewServer(faker.Server())

	// Create S3 client configured for the mock server
	ctx := context.Background()
	sdkConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("test-key", "test-secret", ""),
		),
	)
	if err != nil {
		log.Fatalf("Failed to load AWS config for mock S3: %v", err)
	}

	s3Client := s3.NewFromConfig(sdkConfig, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(ts.URL)
		o.UsePathStyle = true // Required for gofakes3
	})

	// Create the bucket
	bucketName := os.Getenv("S3_BUCKET")
	if bucketName == "" {
		bucketName = DefaultBucketName
	}

	_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		log.Fatalf("Failed to create mock S3 bucket: %v", err)
	}

	publicURL := ts.URL + "/" + bucketName
	client := s3client.NewFromS3Client(s3Client, bucketName, publicURL)

	cleanup := func() {
		ts.Close()
	}

	return client, cleanup
}

// createRealS3Client creates a real S3 client for production use with Tigris.
func createRealS3Client() *s3client.Client {
	ctx := context.Background()

	cfg := s3client.Config{
		Endpoint:        os.Getenv("S3_ENDPOINT"),          // e.g., "https://fly.storage.tigris.dev"
		Region:          os.Getenv("S3_REGION"),            // e.g., "auto"
		AccessKeyID:     os.Getenv("S3_ACCESS_KEY_ID"),     // Tigris access key
		SecretAccessKey: os.Getenv("S3_SECRET_ACCESS_KEY"), // Tigris secret key
		BucketName:      os.Getenv("S3_BUCKET"),            // e.g., "remote-notes"
		PublicURL:       os.Getenv("S3_PUBLIC_URL"),        // e.g., "https://remote-notes.fly.storage.tigris.dev"
		UsePathStyle:    false,                             // Tigris uses virtual-hosted style
	}

	if cfg.BucketName == "" {
		cfg.BucketName = DefaultBucketName
	}

	client, err := s3client.New(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to create S3 client: %v", err)
	}

	return client
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

// ListNotes handles GET /api/notes - returns a paginated list of notes
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

// GetNote handles GET /api/notes/{id} - returns a single note by ID
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

// CreateNote handles POST /api/notes - creates a new note
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

// UpdateNote handles PUT /api/notes/{id} - updates an existing note
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

// DeleteNote handles DELETE /api/notes/{id} - deletes a note
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

// SearchNotes handles POST /api/notes/search - searches notes using FTS5
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
