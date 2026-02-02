// Remote Notes MicroSaaS - Main Server Entry Point
// Milestone 1: Unauthenticated CRUD with hardcoded test user

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kuitang/agent-notes/internal/api"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/mcp"
	"github.com/kuitang/agent-notes/internal/notes"
)

const (
	// HardcodedUserID is the test user for Milestone 1 (unauthenticated CRUD)
	HardcodedUserID = "test-user-001"

	// DefaultAddr is the default listen address
	DefaultAddr = ":8080"

	// ShutdownTimeout is the graceful shutdown timeout
	ShutdownTimeout = 30 * time.Second
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Remote Notes MicroSaaS - Starting server...")

	// Get listen address from environment or use default
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = DefaultAddr
	}

	// Initialize database layer
	log.Println("Initializing database layer...")
	if err := db.InitSchemas(HardcodedUserID); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	log.Println("Database initialized successfully")

	// Open user database for the hardcoded test user
	userDB, err := db.OpenUserDB(HardcodedUserID)
	if err != nil {
		log.Fatalf("Failed to open user database: %v", err)
	}
	log.Printf("Opened user database for user: %s", HardcodedUserID)

	// Create notes service
	notesSvc := notes.NewService(userDB)
	log.Println("Notes service created")

	// Create HTTP mux
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"remote-notes"}`))
	})

	// Register REST API handlers
	apiHandler := api.NewHandler(notesSvc)
	apiHandler.RegisterRoutes(mux)
	log.Println("REST API routes registered at /notes")

	// Create and mount MCP server
	mcpServer := mcp.NewServer(notesSvc)
	mux.Handle("/mcp", mcpServer)
	log.Println("MCP server mounted at /mcp (Streamable HTTP transport)")

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
		log.Println("  GET  /health         - Health check")
		log.Println("  GET  /notes          - List notes")
		log.Println("  POST /notes          - Create note")
		log.Println("  GET  /notes/{id}     - Get note")
		log.Println("  PUT  /notes/{id}     - Update note")
		log.Println("  DELETE /notes/{id}   - Delete note")
		log.Println("  POST /notes/search   - Search notes")
		log.Println("  POST /mcp            - MCP endpoint")
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
