// Remote Notes MicroSaaS - Main Server Entry Point
// Milestone 4+: OAuth 2.1 Provider, Google OIDC, Resend Email, Tigris S3

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-contrib/sse"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/kuitang/agent-notes/internal/apps"
	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/billing"
	"github.com/kuitang/agent-notes/internal/config"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/mcp"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/oauth"
	"github.com/kuitang/agent-notes/internal/ratelimit"
	"github.com/kuitang/agent-notes/internal/s3client"
	"github.com/kuitang/agent-notes/internal/shorturl"
	"github.com/kuitang/agent-notes/internal/web"
)

const (
	// ShutdownTimeout is the graceful shutdown timeout
	ShutdownTimeout = 30 * time.Second

	// DefaultBucketName is the default S3 bucket for mock storage
	DefaultBucketName = "commonink-public"
)

// =============================================================================
// OAuth Token Verifier Adapter
// =============================================================================

// OAuthProviderVerifier adapts oauth.Provider to implement auth.OAuthTokenVerifier.
type OAuthProviderVerifier struct {
	provider *oauth.Provider
}

// VerifyAccessToken verifies an OAuth JWT and returns the claims.
func (v *OAuthProviderVerifier) VerifyAccessToken(token string) (*auth.OAuthTokenClaims, error) {
	claims, err := v.provider.VerifyAccessToken(token)
	if err != nil {
		return nil, err
	}

	return &auth.OAuthTokenClaims{
		Subject:  claims.Subject,
		ClientID: claims.ClientID,
		Scope:    claims.Scope,
	}, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Step 1: Parse CLI flags
	noEmail, noS3, noOIDC, addr := config.ParseFlags()

	// Step 2: Load and validate configuration
	cfg, err := config.LoadConfig(noEmail, noS3, noOIDC, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	// Step 3: Print startup summary
	cfg.PrintStartupSummary()

	resolvedSpriteToken := cfg.SpriteToken

	// Wire DatabasePath to db package before any DB operations
	db.DataDirectory = cfg.DatabasePath

	masterKey, err := hex.DecodeString(cfg.MasterKey)
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
	rateLimiter := ratelimit.NewRateLimiter(cfg.RateLimitConfig)
	log.Println("Rate limiter initialized")

	// Initialize S3 client
	s3Client, s3Cleanup := initS3Client(cfg)
	if s3Cleanup != nil {
		defer s3Cleanup()
	}
	log.Println("S3 client initialized")

	// Initialize template renderer
	renderer, err := web.NewRenderer(cfg.TemplatesDir)
	if err != nil {
		log.Fatalf("Failed to initialize template renderer: %v", err)
	}
	log.Printf("Template renderer initialized with templates from %s", cfg.TemplatesDir)

	// Initialize services - use real or mock based on CLI flags
	var emailService email.EmailService
	if cfg.NoEmail {
		emailService = email.NewMockEmailService()
		log.Println("Using mock email service (--no-email)")
	} else {
		emailService = email.NewResendEmailService(cfg.ResendAPIKey, cfg.ResendFromEmail)
		log.Printf("Using real Resend email service (from: %s)", cfg.ResendFromEmail)
	}

	var oidcClient auth.OIDCClient
	var localMockOIDC *auth.LocalMockOIDCProvider
	if cfg.NoOIDC {
		localMockOIDC = auth.NewLocalMockOIDCProvider("")
		oidcClient = localMockOIDC
		log.Println("Using local mock OIDC provider (--no-oidc)")
	} else {
		realOIDC, err := auth.NewGoogleOIDCClient(cfg.GoogleClientID, cfg.GoogleClientSecret)
		if err != nil {
			log.Fatalf("Failed to initialize Google OIDC client: %v", err)
		}
		oidcClient = realOIDC
		log.Println("Using real Google OIDC client")
	}

	// Initialize billing service
	var billingService billing.BillingService
	if cfg.IsTestMode() {
		billingService = billing.NewMockService()
		log.Println("Using mock billing service (--test)")
	} else {
		billingCfg := billing.Config{
			SecretKey:      cfg.StripeSecretKey,
			PublishableKey: cfg.StripePublishableKey,
			WebhookSecret:  cfg.StripeWebhookSecret,
			PriceMonthly:   cfg.StripePriceMonthly,
			PriceAnnual:    cfg.StripePriceAnnual,
		}
		billingService = billing.NewService(billingCfg, sessionsDB, keyManager)
		log.Println("Using real Stripe billing service")
	}

	// Disable secure cookies for local development (HTTP)
	if !cfg.RequireSecureCookies() {
		auth.SetSecureCookies(false)
		log.Println("Secure cookies disabled for local development (HTTP)")
	}

	userService := auth.NewUserService(sessionsDB, keyManager, emailService, "", auth.Argon2Hasher{})
	sessionService := auth.NewSessionService(sessionsDB)
	consentService := auth.NewConsentService(sessionsDB)

	// Initialize OAuth 2.1 provider
	oauthHMACSecret := loadOAuthHMACSecret(cfg)
	oauthSigningKey := loadOAuthSigningKey(cfg)
	oauthCfg := oauth.Config{
		DB:         sessionsDB.DB(),
		Issuer:     "",
		Resource:   "",
		HMACSecret: oauthHMACSecret,
		SigningKey: oauthSigningKey,
	}
	oauthProvider, err := oauth.NewProvider(oauthCfg)
	if err != nil {
		log.Fatalf("Failed to create OAuth provider: %v", err)
	}
	log.Println("OAuth 2.1 provider initialized")

	// Initialize OAuth handler with consent service
	oauthHandler := oauth.NewHandler(oauthProvider, sessionService, consentService, renderer)

	// Initialize short URL service
	shortURLSvc := shorturl.NewService(sessionsDB.Queries())
	log.Println("Short URL service initialized")

	// Initialize public notes service with short URL support
	publicNotes := notes.NewPublicNoteService(s3Client).WithShortURLService(shortURLSvc, "")

	// Initialize auth middleware and handlers
	// Create an OAuth token verifier adapter that wraps the OAuth provider
	oauthTokenVerifier := &OAuthProviderVerifier{provider: oauthProvider}
	resourceMetadataURL := "/.well-known/oauth-protected-resource"

	authMiddleware := auth.NewMiddleware(sessionService, keyManager)
	authMiddleware.WithOAuthVerifier(oauthTokenVerifier, resourceMetadataURL)

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
		shortURLSvc,
		billingService,
		"",
		resolvedSpriteToken,
	)

	// Create HTTP mux
	mux := http.NewServeMux()

	// Health check endpoint (no auth required, no rate limiting)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"commonink","milestone":4}`))
	})

	// Register OAuth 2.1 provider routes
	oauthProvider.RegisterMetadataRoutes(mux)
	log.Println("OAuth metadata routes registered at /.well-known/*")

	// OAuth endpoints: DCR, authorize, token
	mux.HandleFunc("POST /oauth/register", oauthProvider.DCR)
	oauthHandler.RegisterRoutes(mux)
	log.Println("OAuth provider routes registered at /oauth/*")

	// Register web UI routes (handles /, /login, /register, /notes/*, /public/*, /oauth/consent)
	webHandler.RegisterRoutes(mux, authMiddleware)
	log.Println("Web UI routes registered")

	// Initialize and register static page handler (privacy, terms, about, api-docs, install)
	staticSrcDir := os.Getenv("STATIC_SRC_DIR")
	if staticSrcDir == "" {
		staticSrcDir = "./static/src"
	}
	staticHandler := web.NewStaticHandler(renderer, staticSrcDir, authMiddleware)
	staticHandler.RegisterRoutes(mux)
	log.Println("Static page routes registered at /privacy, /terms, /about, /docs/api, /docs/install")

	// Serve favicon.ico from static directory
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/favicon.ico")
	})

	// Register auth API routes (no auth required for these)
	authHandler.RegisterRoutes(mux)
	if localMockOIDC != nil {
		localMockOIDC.RegisterRoutes(mux)
		log.Println("Local mock OIDC routes registered at /auth/mock-oidc/*")
	}
	log.Println("Auth API routes registered at /auth/*")

	// Rate limiting middleware - extracts user ID and paid status from request
	getUserID := func(r *http.Request) string {
		return auth.GetUserID(r.Context())
	}
	getIsPaid := func(r *http.Request) bool {
		userDB := auth.GetUserDB(r.Context())
		if userDB == nil {
			return false
		}
		userID := auth.GetUserID(r.Context())
		account, err := userDB.Queries().GetAccount(r.Context(), userID)
		if err != nil {
			return false
		}
		return account.SubscriptionStatus.Valid && account.SubscriptionStatus.String == "active"
	}
	rateLimitMW := ratelimit.RateLimitMiddleware(rateLimiter, getUserID, getIsPaid)

	// Create authenticated notes handler with rate limiting
	notesHandler := &AuthenticatedNotesHandler{}
	appsHandler := &AuthenticatedAppsHandler{
		SpriteToken: resolvedSpriteToken,
		Renderer:    renderer,
	}

	// Register protected notes API routes with rate limiting
	mux.Handle("GET /api/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.ListNotes))))
	mux.Handle("POST /api/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.CreateNote))))
	mux.Handle("GET /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.GetNote))))
	mux.Handle("PUT /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.UpdateNote))))
	mux.Handle("DELETE /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.DeleteNote))))
	mux.Handle("POST /api/notes/search", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.SearchNotes))))
	mux.Handle("GET /api/storage", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.GetStorageUsage))))
	log.Println("Protected notes API routes registered at /api/notes with rate limiting")

	// Register protected apps management API routes with rate limiting
	mux.Handle("GET /api/apps", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.ListApps))))
	mux.Handle("GET /api/apps/{name}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.GetApp))))
	mux.Handle("DELETE /api/apps/{name}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.DeleteApp))))
	mux.Handle("GET /api/apps/{name}/files", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.ListFiles))))
	mux.Handle("GET /api/apps/{name}/files/{path...}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.GetFile))))
	mux.Handle("GET /api/apps/{name}/logs", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.GetLogs))))
	mux.Handle("GET /api/apps/{name}/stream", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.StreamApp))))
	mux.Handle("POST /api/apps/{name}/{action}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.HandleAction))))
	log.Println("Protected apps API routes registered at /api/apps with rate limiting")

	// Register API Key routes
	apiKeyHandler := auth.NewAPIKeyHandler(userService)
	mux.Handle("POST /api/keys", authMiddleware.RequireAuth(http.HandlerFunc(apiKeyHandler.CreateAPIKey)))
	mux.Handle("GET /api/keys", authMiddleware.RequireAuth(http.HandlerFunc(apiKeyHandler.ListAPIKeys)))
	mux.Handle("DELETE /api/keys/{id}", authMiddleware.RequireAuth(http.HandlerFunc(apiKeyHandler.RevokeAPIKey)))
	log.Println("API Key routes registered at /api/keys")

	// Create and mount MCP servers (requires auth + rate limiting)
	mcpAllHandler := &AuthenticatedMCPHandler{
		Toolset:     mcp.ToolsetAll,
		SpriteToken: resolvedSpriteToken,
	}
	mcpNotesHandler := &AuthenticatedMCPHandler{
		Toolset:     mcp.ToolsetNotes,
		SpriteToken: resolvedSpriteToken,
	}
	mcpAppsHandler := &AuthenticatedMCPHandler{
		Toolset:     mcp.ToolsetApps,
		SpriteToken: resolvedSpriteToken,
	}

	mux.Handle("POST /mcp", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(mcpAllHandler.ServeHTTP))))
	mux.Handle("POST /mcp/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(mcpNotesHandler.ServeHTTP))))
	mux.Handle("POST /mcp/apps", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(mcpAppsHandler.ServeHTTP))))

	registerStatelessMCPMethodGuards(mux, authMiddleware, "/mcp")
	registerStatelessMCPMethodGuards(mux, authMiddleware, "/mcp/notes")
	registerStatelessMCPMethodGuards(mux, authMiddleware, "/mcp/apps")
	log.Println("MCP server mounted at POST /mcp, /mcp/notes, /mcp/apps (protected with rate limiting)")

	// Wrap mux with request logging middleware
	loggedMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log every incoming request
		log.Printf("[REQ] %s %s %s (Host: %s, UA: %s)", r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.Header.Get("User-Agent"))

		// Capture response status code
		rw := &statusRecorder{ResponseWriter: w, statusCode: 200}
		mux.ServeHTTP(rw, r)

		log.Printf("[RES] %s %s -> %d", r.Method, r.URL.Path, rw.statusCode)
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      loggedMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Bind the listener BEFORE logging "ready" to avoid a race where the test
	// detects the log line but the socket isn't accepting connections yet.
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
	}

	log.Printf("Server listening on %s", listener.Addr())
	log.Println("Endpoints:")
	log.Println("  OAuth 2.1 Provider:")
	log.Println("    GET  /.well-known/oauth-protected-resource  - Protected resource metadata")
	log.Println("    GET  /.well-known/oauth-authorization-server - Auth server metadata")
	log.Println("    GET  /.well-known/jwks.json                  - JWKS for token verification")
	log.Println("    POST /oauth/register              - Dynamic Client Registration (DCR)")
	log.Println("    GET  /oauth/authorize             - Authorization endpoint")
	log.Println("    POST /oauth/consent               - Consent submission")
	log.Println("    POST /oauth/token                 - Token endpoint")
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
	log.Println("    GET  /pub/{short_id}             - Short URL redirect")
	log.Println("    GET  /oauth/consent              - OAuth consent page (protected)")
	log.Println("  Static Pages:")
	log.Println("    GET  /privacy                    - Privacy policy")
	log.Println("    GET  /terms                      - Terms of service")
	log.Println("    GET  /about                      - About page")
	log.Println("    GET  /docs/api                   - API documentation")
	log.Println("  Auth API:")
	log.Println("    GET  /auth/google                - Google OIDC login")
	log.Println("    GET  /auth/google/callback       - Google OIDC callback")
	log.Println("    POST /auth/magic                 - Request magic link")
	log.Println("    GET  /auth/magic/verify          - Verify magic link")
	log.Println("    POST /auth/register              - Email/password registration")
	log.Println("    POST /auth/login                 - Email/password login")
	log.Println("    POST /auth/password-reset         - Request password reset")
	log.Println("    POST /auth/password-reset-confirm - Confirm password reset")
	log.Println("    POST /auth/logout                - Logout")
	log.Println("    GET  /auth/whoami                - Current user info")
	log.Println("  Notes API (rate limited):")
	log.Println("    GET  /api/notes                  - List notes (protected)")
	log.Println("    POST /api/notes                  - Create note (protected)")
	log.Println("    GET  /api/notes/{id}             - Get note (protected)")
	log.Println("    PUT  /api/notes/{id}             - Update note (protected)")
	log.Println("    DELETE /api/notes/{id}           - Delete note (protected)")
	log.Println("    POST /api/notes/search           - Search notes (protected)")
	log.Println("  API Keys:")
	log.Println("    GET  /api/keys                   - List API keys (protected)")
	log.Println("    POST /api/keys                   - Create API key (protected)")
	log.Println("    DELETE /api/keys/{id}            - Revoke API key (protected)")
	log.Println("  Apps API (management, rate limited):")
	log.Println("    GET  /api/apps                   - List apps (protected)")
	log.Println("    GET  /api/apps/{name}            - Get app metadata (protected)")
	log.Println("    DELETE /api/apps/{name}          - Delete app + sprite (protected)")
	log.Println("    GET  /api/apps/{name}/files      - List app files on sprite (protected)")
	log.Println("    GET  /api/apps/{name}/files/{path...} - Read app file (protected)")
	log.Println("    GET  /api/apps/{name}/logs       - Tail app logs (protected)")
	log.Println("    GET  /api/apps/{name}/stream     - Stream app updates (SSE: ping/log/file, protected)")
	log.Println("  Billing:")
	log.Println("    GET  /pricing                    - Pricing page")
	log.Println("    POST /billing/checkout           - Create checkout session")
	log.Println("    GET  /billing/success            - Checkout success page")
	log.Println("    POST /billing/webhook            - Stripe webhook")
	log.Println("    POST /billing/portal             - Stripe customer portal (protected)")
	log.Println("    GET  /settings/billing           - Billing settings (protected)")
	log.Println("  MCP (rate limited):")
	log.Println("    POST /mcp                        - MCP endpoint (all tools, protected)")
	log.Println("    POST /mcp/notes                  - MCP endpoint (notes toolset, protected)")
	log.Println("    POST /mcp/apps                   - MCP endpoint (apps toolset, protected)")
	log.Println("  Health:")
	log.Println("    GET  /health                     - Health check")
	log.Println("")
	log.Println("Server ready to accept connections")

	// Channel to receive server errors
	serverErr := make(chan error, 1)

	// Start serving on the already-bound listener
	go func() {
		serverErr <- server.Serve(listener)
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

// initS3Client initializes the S3 client based on configuration.
// If --no-s3 flag is set, creates an in-memory mock S3 server.
// Otherwise, creates a real S3 client with Tigris configuration.
func initS3Client(cfg *config.Config) (*s3client.Client, func()) {
	if cfg.NoS3 {
		log.Println("Using mock S3 (gofakes3) (--no-s3)")
		return createMockS3Client(cfg)
	}

	log.Println("Using real S3 client (Tigris)")
	return createRealS3Client(cfg), nil
}

// createMockS3Client creates an in-memory S3 client using gofakes3.
func createMockS3Client(cfg *config.Config) (*s3client.Client, func()) {
	// Create in-memory S3 backend
	backend := s3mem.New()
	faker := gofakes3.New(backend)

	// Create test HTTP server
	ts := httptest.NewServer(faker.Server())

	// Create S3 client configured for the mock server
	ctx := context.Background()
	sdkConfig, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
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

	bucketName := cfg.AWSBucketName
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
func createRealS3Client(cfg *config.Config) *s3client.Client {
	ctx := context.Background()

	s3Cfg := s3client.Config{
		Endpoint:        cfg.AWSEndpointS3,
		Region:          cfg.AWSRegion,
		AccessKeyID:     cfg.AWSAccessKeyID,
		SecretAccessKey: cfg.AWSSecretAccessKey,
		BucketName:      cfg.AWSBucketName,
		PublicURL:       cfg.AWSPublicURL,
		UsePathStyle:    false, // Tigris uses virtual-hosted style
	}

	if s3Cfg.BucketName == "" {
		s3Cfg.BucketName = DefaultBucketName
	}

	client, err := s3client.New(ctx, s3Cfg)
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
	storageLimit := notes.FreeStorageLimitBytes
	userID := auth.GetUserID(r.Context())
	account, err := userDB.Queries().GetAccount(r.Context(), userID)
	if err == nil && account.SubscriptionStatus.Valid {
		storageLimit = notes.StorageLimitForStatus(account.SubscriptionStatus.String)
	}
	svc := notes.NewService(userDB, storageLimit)
	_ = svc.Purge(30 * 24 * time.Hour)
	return svc, nil
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
		if errors.Is(err, notes.ErrStorageLimitExceeded) {
			writeError(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
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
		if errors.Is(err, notes.ErrPriorHashRequired) || errors.Is(err, notes.ErrInvalidPriorHash) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, notes.ErrRevisionConflict) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		if errors.Is(err, notes.ErrStorageLimitExceeded) {
			writeError(w, http.StatusRequestEntityTooLarge, err.Error())
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

// GetStorageUsage handles GET /api/storage - returns current storage usage
func (h *AuthenticatedNotesHandler) GetStorageUsage(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	usage, err := svc.GetStorageUsage()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get storage usage: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, usage)
}

// AuthenticatedAppsHandler wraps apps management operations with auth context.
type AuthenticatedAppsHandler struct {
	SpriteToken string
	Renderer    *web.Renderer
}

func (h *AuthenticatedAppsHandler) getService(r *http.Request) (*apps.Service, error) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		return nil, fmt.Errorf("no user database in context")
	}
	userID := auth.GetUserID(r.Context())
	return apps.NewService(userDB, userID, h.SpriteToken), nil
}

func firstServiceName(servicesOutput string) string {
	output := strings.TrimSpace(servicesOutput)
	if output == "" {
		return ""
	}

	var list []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(output), &list); err == nil {
		for _, item := range list {
			name := strings.TrimSpace(item.Name)
			if name != "" {
				return name
			}
		}
	}

	var item struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(output), &item); err == nil {
		name := strings.TrimSpace(item.Name)
		if name != "" {
			return name
		}
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.Contains(strings.ToLower(trimmed), "no services") {
			continue
		}
		if idx := strings.Index(trimmed, "[name:"); idx >= 0 {
			rest := trimmed[idx+len("[name:"):]
			if end := strings.Index(rest, "]"); end > 0 {
				name := strings.TrimSpace(rest[:end])
				if name != "" {
					return name
				}
			}
		}
		fields := strings.Fields(trimmed)
		if len(fields) > 0 {
			token := strings.TrimSpace(fields[0])
			token = strings.TrimPrefix(token, "[name:")
			token = strings.TrimSuffix(token, "]")
			if token != "" {
				return token
			}
		}
	}
	return ""
}

func hashJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

func writeSSEEvent(w http.ResponseWriter, flusher http.Flusher, event string, payload any) bool {
	if err := sse.Encode(w, sse.Event{
		Event: event,
		Data:  payload,
	}); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func logStreamPayload(result *apps.AppLogsResult, err error) map[string]any {
	if err != nil {
		return map[string]any{
			"error": err.Error(),
		}
	}
	if result == nil {
		return map[string]any{
			"output":    "",
			"stderr":    "",
			"exit_code": 0,
		}
	}
	return map[string]any{
		"output":    result.Output,
		"stderr":    result.Stderr,
		"exit_code": result.ExitCode,
	}
}

func (h *AuthenticatedAppsHandler) renderFilesHTML(files []apps.AppFileEntry, filesErr string) (string, error) {
	if h.Renderer == nil {
		return "", errors.New("renderer is not configured")
	}
	return h.Renderer.RenderPartialToString(
		"apps/detail.html",
		"app-files-list",
		map[string]any{
			"Files":    files,
			"FilesErr": filesErr,
		},
	)
}

func appErrorStatus(err error) int {
	if err == nil {
		return http.StatusInternalServerError
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found"):
		return http.StatusNotFound
	case strings.Contains(msg, "path is required"),
		strings.Contains(msg, "must be relative"),
		strings.Contains(msg, "invalid lines parameter"):
		return http.StatusBadRequest
	case strings.Contains(msg, "not configured"):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func writeAppError(w http.ResponseWriter, action string, err error) {
	status := appErrorStatus(err)
	if status == http.StatusInternalServerError {
		writeError(w, status, "Failed to "+action+": "+err.Error())
		return
	}
	writeError(w, status, err.Error())
}

// ListApps handles GET /api/apps - returns all apps for current user.
func (h *AuthenticatedAppsHandler) ListApps(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	items, err := svc.List(r.Context())
	if err != nil {
		writeAppError(w, "list apps", err)
		return
	}

	response := struct {
		Apps []apps.AppMetadata `json:"apps"`
	}{
		Apps: items,
	}
	writeJSON(w, http.StatusOK, response)
}

// GetApp handles GET /api/apps/{name} - returns app metadata.
func (h *AuthenticatedAppsHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "App name is required")
		return
	}

	item, err := svc.Get(r.Context(), name)
	if err != nil {
		writeAppError(w, "get app", err)
		return
	}

	writeJSON(w, http.StatusOK, item)
}

// DeleteApp handles DELETE /api/apps/{name} - destroys sprite and deletes metadata.
func (h *AuthenticatedAppsHandler) DeleteApp(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "App name is required")
		return
	}

	result, err := svc.Delete(r.Context(), name)
	if err != nil {
		writeAppError(w, "delete app", err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// ListFiles handles GET /api/apps/{name}/files - lists app files on sprite.
func (h *AuthenticatedAppsHandler) ListFiles(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "App name is required")
		return
	}

	result, err := svc.ListFiles(r.Context(), name)
	if err != nil {
		writeAppError(w, "list app files", err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// GetFile handles GET /api/apps/{name}/files/{path...} - reads one app file.
func (h *AuthenticatedAppsHandler) GetFile(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "App name is required")
		return
	}

	filePath := strings.TrimSpace(r.PathValue("path"))
	if filePath == "" {
		writeError(w, http.StatusBadRequest, "File path is required")
		return
	}

	result, err := svc.ReadFile(r.Context(), name, filePath)
	if err != nil {
		writeAppError(w, "read app file", err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// GetLogs handles GET /api/apps/{name}/logs - tails recent app logs.
func (h *AuthenticatedAppsHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "App name is required")
		return
	}

	lines := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("lines")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "invalid lines parameter: must be a positive integer")
			return
		}
		lines = parsed
	}

	result, err := svc.TailLogs(r.Context(), name, lines)
	if err != nil {
		writeAppError(w, "tail app logs", err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// StreamApp handles GET /api/apps/{name}/stream - streams app updates over SSE.
// Events:
// - file: {"html":"..."}    (server-rendered file list partial)
// - log:  {"output":"...","stderr":"...","exit_code":0} or {"error":"..."}
// - ping: {"ts":"..."}
func (h *AuthenticatedAppsHandler) StreamApp(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "App name is required")
		return
	}

	lines := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("lines")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "invalid lines parameter: must be a positive integer")
			return
		}
		lines = parsed
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "Streaming not supported")
		return
	}

	initialFiles, err := svc.ListFiles(r.Context(), name)
	if err != nil {
		writeAppError(w, "list app files", err)
		return
	}
	initialLogs, err := svc.TailLogs(r.Context(), name, lines)
	if err != nil {
		writeAppError(w, "tail app logs", err)
		return
	}
	filesHTML, err := h.renderFilesHTML(initialFiles.Files, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to render file list stream")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	fileHash := hashJSON(map[string]string{"html": filesHTML})

	initialLogPayload := logStreamPayload(initialLogs, nil)
	logHash := hashJSON(initialLogPayload)

	if !writeSSEEvent(w, flusher, "file", map[string]any{"html": filesHTML}) {
		return
	}
	if !writeSSEEvent(w, flusher, "log", initialLogPayload) {
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			sentEvent := false

			nextFiles, nextFilesErr := svc.ListFiles(r.Context(), name)
			nextFilesList := []apps.AppFileEntry{}
			nextFilesErrText := ""
			if nextFilesErr != nil {
				nextFilesErrText = nextFilesErr.Error()
			} else {
				nextFilesList = nextFiles.Files
			}
			nextFilesHTML, renderErr := h.renderFilesHTML(nextFilesList, nextFilesErrText)
			if renderErr != nil {
				log.Printf("apps stream render failed for app=%s: %v", name, renderErr)
				return
			}
			nextFileHash := hashJSON(map[string]string{"html": nextFilesHTML})
			if nextFileHash != fileHash {
				fileHash = nextFileHash
				if !writeSSEEvent(w, flusher, "file", map[string]any{"html": nextFilesHTML}) {
					return
				}
				sentEvent = true
			}

			nextLogPayload := logStreamPayload(svc.TailLogs(r.Context(), name, lines))
			nextLogHash := hashJSON(nextLogPayload)
			if nextLogHash != logHash {
				logHash = nextLogHash
				if !writeSSEEvent(w, flusher, "log", nextLogPayload) {
					return
				}
				sentEvent = true
			}

			if sentEvent {
				continue
			}
			if !writeSSEEvent(w, flusher, "ping", map[string]any{
				"ts": time.Now().UTC().Format(time.RFC3339Nano),
			}) {
				return
			}
		}
	}
}

// HandleAction handles POST /api/apps/{name}/{action} - performs start/stop/restart.
func (h *AuthenticatedAppsHandler) HandleAction(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "App name is required")
		return
	}

	action := strings.TrimSpace(r.PathValue("action"))
	switch action {
	case "start", "stop", "restart":
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid action %q: must be start, stop, or restart", action))
		return
	}

	listResult, err := svc.RunBash(r.Context(), name, "sprite-env services list", 30)
	if err != nil {
		writeAppError(w, "discover service", err)
		return
	}

	svcName := firstServiceName(listResult.Stdout)
	if svcName == "" {
		writeError(w, http.StatusBadRequest, "No service registered. Use sprite-env services create first.")
		return
	}

	var cmd string
	switch action {
	case "start":
		cmd = fmt.Sprintf("sprite-env services start %q", svcName)
	case "stop":
		cmd = fmt.Sprintf("sprite-env services stop %q", svcName)
	case "restart":
		cmd = fmt.Sprintf("sprite-env services stop %q && sprite-env services start %q", svcName, svcName)
	}

	result, err := svc.RunBash(r.Context(), name, cmd, 30)
	if err != nil {
		writeAppError(w, action+" service", err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// AuthenticatedMCPHandler wraps MCP with auth context
type AuthenticatedMCPHandler struct {
	Toolset     mcp.Toolset
	SpriteToken string
}

func (h *AuthenticatedMCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID := auth.GetUserID(r.Context())

	var notesSvc *notes.Service
	if h.Toolset != mcp.ToolsetApps {
		storageLimit := notes.FreeStorageLimitBytes
		account, err := userDB.Queries().GetAccount(r.Context(), userID)
		if err == nil && account.SubscriptionStatus.Valid {
			storageLimit = notes.StorageLimitForStatus(account.SubscriptionStatus.String)
		}
		notesSvc = notes.NewService(userDB, storageLimit)
		_ = notesSvc.Purge(30 * 24 * time.Hour)
	}

	var appsSvc *apps.Service
	if h.Toolset != mcp.ToolsetNotes {
		appsSvc = apps.NewService(userDB, userID, h.SpriteToken)
	}

	mcpServer := mcp.NewServer(notesSvc, appsSvc, h.Toolset)
	mcpServer.ServeHTTP(w, r)
}

func registerStatelessMCPMethodGuards(mux *http.ServeMux, authMiddleware *auth.Middleware, route string) {
	mux.Handle("GET "+route, authMiddleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "POST")
		http.Error(w, "GET not supported in stateless MCP mode. Use POST.", http.StatusMethodNotAllowed)
	})))
	mux.Handle("DELETE "+route, authMiddleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "POST")
		http.Error(w, "DELETE not supported in stateless MCP mode. Use POST.", http.StatusMethodNotAllowed)
	})))
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
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

// =============================================================================
// OAuth Configuration Helpers
// =============================================================================

// loadOAuthHMACSecret decodes the HMAC secret from config. Fatal on invalid format.
func loadOAuthHMACSecret(cfg *config.Config) []byte {
	secret, err := hex.DecodeString(cfg.OAuthHMACSecret)
	if err != nil || len(secret) < 32 {
		log.Fatalf("OAUTH_HMAC_SECRET must be valid hex, at least 64 characters (32 bytes)")
	}
	return secret
}

// loadOAuthSigningKey decodes the Ed25519 signing key from config. Fatal on invalid format.
func loadOAuthSigningKey(cfg *config.Config) ed25519.PrivateKey {
	keyBytes, err := hex.DecodeString(cfg.OAuthSigningKey)
	if err != nil || len(keyBytes) != ed25519.SeedSize {
		log.Fatalf("OAUTH_SIGNING_KEY must be valid hex, exactly 64 characters (32 bytes ed25519 seed)")
	}
	return ed25519.NewKeyFromSeed(keyBytes)
}
