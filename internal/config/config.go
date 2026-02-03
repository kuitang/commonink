// Package config provides centralized configuration management for the common.ink application.
// It loads configuration from environment variables, validates required fields, and provides sensible defaults.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/ratelimit"
)

// Config holds all application configuration.
type Config struct {
	// Server settings
	ListenAddr   string
	BaseURL      string
	TemplatesDir string

	// Database and encryption
	MasterKey       string        // 64 hex characters (32 bytes)
	DatabasePath    string        // Path for per-user databases (e.g., /data/{user_id}/notes.db)
	SessionDuration time.Duration // How long sessions remain valid

	// Rate limiting
	RateLimitConfig ratelimit.Config

	// Mock service flags (for development/testing)
	UseMockOIDC  bool // If true, use mock OIDC provider
	UseMockEmail bool // If true, use mock email service
	UseMockS3    bool // If true, use in-memory S3

	// Google OIDC (real integration for M4)
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	// Resend Email (real integration for M4)
	ResendAPIKey    string
	ResendFromEmail string

	// OAuth 2.1 Provider
	OAuthHMACSecret string // 64 hex characters (32 bytes)
	OAuthSigningKey string // 64 hex characters (ed25519 seed)

	// S3/Tigris Storage
	S3Endpoint        string
	S3Region          string
	S3AccessKeyID     string
	S3SecretAccessKey string
	S3Bucket          string
	S3PublicURL       string
}

// ValidationError represents a configuration validation error with multiple issues.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("configuration validation failed: %s", strings.Join(e.Errors, "; "))
}

// LoadConfig loads configuration from environment variables.
// It validates required fields and returns an error if critical config is missing.
func LoadConfig() (*Config, error) {
	cfg := &Config{}

	// Server settings
	cfg.ListenAddr = getEnvOrDefault("LISTEN_ADDR", ":8080")
	cfg.BaseURL = os.Getenv("BASE_URL")
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost" + cfg.ListenAddr
	}
	cfg.TemplatesDir = getEnvOrDefault("TEMPLATES_DIR", "./web/templates")

	// Database and encryption
	cfg.MasterKey = os.Getenv("MASTER_KEY")
	cfg.DatabasePath = getEnvOrDefault("DATABASE_PATH", "/data")
	cfg.SessionDuration = parseDurationOrDefault("SESSION_DURATION", 24*time.Hour)

	// Rate limiting
	cfg.RateLimitConfig = ratelimit.Config{
		FreeRPS:         parseFloat64OrDefault("RATE_LIMIT_FREE_RPS", 10),
		FreeBurst:       parseIntOrDefault("RATE_LIMIT_FREE_BURST", 20),
		PaidRPS:         parseFloat64OrDefault("RATE_LIMIT_PAID_RPS", 1000),
		PaidBurst:       parseIntOrDefault("RATE_LIMIT_PAID_BURST", 2000),
		CleanupInterval: parseDurationOrDefault("RATE_LIMIT_CLEANUP_INTERVAL", time.Hour),
	}

	// Mock service flags (default to true for development)
	cfg.UseMockOIDC = parseBoolOrDefault("USE_MOCK_OIDC", true)
	cfg.UseMockEmail = parseBoolOrDefault("USE_MOCK_EMAIL", true)
	cfg.UseMockS3 = parseBoolOrDefault("USE_MOCK_S3", true)

	// Google OIDC
	cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	cfg.GoogleRedirectURL = os.Getenv("GOOGLE_REDIRECT_URL")
	if cfg.GoogleRedirectURL == "" && cfg.GoogleClientID != "" {
		cfg.GoogleRedirectURL = cfg.BaseURL + "/auth/google/callback"
	}

	// Resend Email
	cfg.ResendAPIKey = os.Getenv("RESEND_API_KEY")
	cfg.ResendFromEmail = getEnvOrDefault("RESEND_FROM_EMAIL", "noreply@remotenotes.app")

	// OAuth 2.1 Provider
	cfg.OAuthHMACSecret = os.Getenv("OAUTH_HMAC_SECRET")
	cfg.OAuthSigningKey = os.Getenv("OAUTH_SIGNING_KEY")

	// S3/Tigris Storage
	cfg.S3Endpoint = os.Getenv("S3_ENDPOINT")
	cfg.S3Region = getEnvOrDefault("S3_REGION", "auto")
	cfg.S3AccessKeyID = os.Getenv("S3_ACCESS_KEY_ID")
	cfg.S3SecretAccessKey = os.Getenv("S3_SECRET_ACCESS_KEY")
	cfg.S3Bucket = getEnvOrDefault("S3_BUCKET", "remote-notes")
	cfg.S3PublicURL = os.Getenv("S3_PUBLIC_URL")

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks that all required configuration is present and valid.
// Returns a ValidationError if any issues are found.
func (c *Config) Validate() error {
	var errs []string

	// In production mode (mocks disabled), require real service credentials
	if !c.UseMockOIDC {
		if c.GoogleClientID == "" {
			errs = append(errs, "GOOGLE_CLIENT_ID is required when USE_MOCK_OIDC=false")
		}
		if c.GoogleClientSecret == "" {
			errs = append(errs, "GOOGLE_CLIENT_SECRET is required when USE_MOCK_OIDC=false")
		}
	}

	if !c.UseMockEmail {
		if c.ResendAPIKey == "" {
			errs = append(errs, "RESEND_API_KEY is required when USE_MOCK_EMAIL=false")
		}
	}

	if !c.UseMockS3 {
		if c.S3Endpoint == "" {
			errs = append(errs, "S3_ENDPOINT is required when USE_MOCK_S3=false")
		}
		if c.S3AccessKeyID == "" {
			errs = append(errs, "S3_ACCESS_KEY_ID is required when USE_MOCK_S3=false")
		}
		if c.S3SecretAccessKey == "" {
			errs = append(errs, "S3_SECRET_ACCESS_KEY is required when USE_MOCK_S3=false")
		}
	}

	// Validate MasterKey format if provided
	if c.MasterKey != "" && len(c.MasterKey) != 64 {
		errs = append(errs, "MASTER_KEY must be 64 hex characters (32 bytes)")
	}

	// Validate OAuth secrets format if provided
	if c.OAuthHMACSecret != "" && len(c.OAuthHMACSecret) < 64 {
		errs = append(errs, "OAUTH_HMAC_SECRET must be at least 64 hex characters (32 bytes)")
	}

	if c.OAuthSigningKey != "" && len(c.OAuthSigningKey) != 64 {
		errs = append(errs, "OAUTH_SIGNING_KEY must be 64 hex characters (ed25519 seed)")
	}

	// Validate rate limit config
	if c.RateLimitConfig.FreeRPS <= 0 {
		errs = append(errs, "RATE_LIMIT_FREE_RPS must be positive")
	}
	if c.RateLimitConfig.FreeBurst <= 0 {
		errs = append(errs, "RATE_LIMIT_FREE_BURST must be positive")
	}

	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}

	return nil
}

// IsProduction returns true if all mock services are disabled.
func (c *Config) IsProduction() bool {
	return !c.UseMockOIDC && !c.UseMockEmail && !c.UseMockS3
}

// IsDevelopment returns true if any mock services are enabled.
func (c *Config) IsDevelopment() bool {
	return c.UseMockOIDC || c.UseMockEmail || c.UseMockS3
}

// RequireSecureCookies returns true if secure cookies should be required.
// Returns false for localhost development URLs.
func (c *Config) RequireSecureCookies() bool {
	return !strings.HasPrefix(c.BaseURL, "http://localhost") &&
		!strings.HasPrefix(c.BaseURL, "http://127.0.0.1")
}

// Helper functions for parsing environment variables

func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func parseBoolOrDefault(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	value = strings.ToLower(value)
	return value == "true" || value == "1" || value == "yes"
}

func parseIntOrDefault(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func parseFloat64OrDefault(key string, defaultValue float64) float64 {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func parseDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}

// MustLoadConfig loads configuration and panics if validation fails.
// Use this in main() when you want the application to fail fast on bad config.
func MustLoadConfig() *Config {
	cfg, err := LoadConfig()
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			panic(fmt.Sprintf("Configuration validation failed:\n  - %s", strings.Join(validationErr.Errors, "\n  - ")))
		}
		panic(fmt.Sprintf("Failed to load configuration: %v", err))
	}
	return cfg
}
