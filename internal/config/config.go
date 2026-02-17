// Package config provides centralized configuration management for the common.ink application.
// It loads configuration from CLI flags and environment variables, validates required fields,
// and provides sensible defaults.
//
// CLI flags control which services are mocked (--no-email, --no-s3, --no-oidc, --test).
// Environment variables provide secrets and service configuration.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/ratelimit"
)

const (
	defaultTigrisRegion = "auto"
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

	// Mock service flags (controlled by CLI flags, not env vars)
	NoOIDC  bool // If true, use mock OIDC provider (--no-oidc)
	NoEmail bool // If true, use mock email service (--no-email)
	NoS3    bool // If true, use in-memory S3 (--no-s3)

	// Google OIDC
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	// Resend Email
	ResendAPIKey    string
	ResendFromEmail string

	// OAuth 2.1 Provider
	OAuthHMACSecret string // 64 hex characters (32 bytes)
	OAuthSigningKey string // 64 hex characters (ed25519 seed)

	// S3/Tigris Storage (uses AWS_ env vars, set automatically by `fly storage create`)
	AWSEndpointS3      string // AWS_ENDPOINT_URL_S3
	AWSRegion          string // AWS_REGION
	AWSAccessKeyID     string // AWS_ACCESS_KEY_ID
	AWSSecretAccessKey string // AWS_SECRET_ACCESS_KEY
	AWSBucketName      string // BUCKET_NAME
	AWSPublicURL       string // S3_PUBLIC_URL (custom, not set by Tigris)
}

// ValidationError represents a configuration validation error with multiple issues.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("configuration validation failed:\n  - %s", strings.Join(e.Errors, "\n  - "))
}

// ParseFlags parses CLI flags and returns them. Call before LoadConfig.
// This registers and parses --no-email, --no-s3, --no-oidc, --test, and --addr flags.
func ParseFlags() (noEmail, noS3, noOIDC bool, addr string) {
	var testMode bool
	flag.BoolVar(&noEmail, "no-email", false, "Use mock email service (logs emails to console)")
	flag.BoolVar(&noS3, "no-s3", false, "Use mock S3 storage (in-memory)")
	flag.BoolVar(&noOIDC, "no-oidc", false, "Use mock Google OIDC provider")
	flag.BoolVar(&testMode, "test", false, "Shorthand for --no-email --no-s3 --no-oidc")
	flag.StringVar(&addr, "addr", "", "Listen address (default :8080, overrides LISTEN_ADDR env var)")
	flag.Parse()

	if testMode {
		noEmail = true
		noS3 = true
		noOIDC = true
	}

	return noEmail, noS3, noOIDC, addr
}

// LoadConfig loads configuration from environment variables and CLI flag values.
// The noEmail, noS3, noOIDC flags control which services use mocks.
// The addr flag overrides the LISTEN_ADDR env var if non-empty.
func LoadConfig(noEmail, noS3, noOIDC bool, addr string) (*Config, error) {
	cfg := &Config{}

	// CLI flag values
	cfg.NoEmail = noEmail
	cfg.NoS3 = noS3
	cfg.NoOIDC = noOIDC

	// Server settings
	cfg.ListenAddr = getEnvOrDefault("LISTEN_ADDR", ":8080")
	if addr != "" {
		cfg.ListenAddr = addr
	}
	cfg.BaseURL = strings.TrimSpace(os.Getenv("BASE_URL"))
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

	// Google OIDC
	cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	cfg.GoogleRedirectURL = os.Getenv("GOOGLE_REDIRECT_URL")
	if cfg.GoogleRedirectURL == "" && cfg.GoogleClientID != "" {
		cfg.GoogleRedirectURL = cfg.BaseURL + "/auth/google/callback"
	}

	// Resend Email
	cfg.ResendAPIKey = os.Getenv("RESEND_API_KEY")
	cfg.ResendFromEmail = getEnvOrDefault("RESEND_FROM_EMAIL", "noreply@common.ink")

	// OAuth 2.1 Provider
	cfg.OAuthHMACSecret = os.Getenv("OAUTH_HMAC_SECRET")
	cfg.OAuthSigningKey = os.Getenv("OAUTH_SIGNING_KEY")

	// S3/Tigris Storage (AWS_ env vars set automatically by `fly storage create`)
	cfg.AWSEndpointS3 = strings.TrimSpace(os.Getenv("AWS_ENDPOINT_URL_S3"))
	cfg.AWSRegion = getEnvOrDefault("AWS_REGION", defaultTigrisRegion)
	cfg.AWSAccessKeyID = strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID"))
	cfg.AWSSecretAccessKey = strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY"))
	cfg.AWSBucketName = strings.TrimSpace(os.Getenv("BUCKET_NAME"))
	cfg.AWSPublicURL = strings.TrimSpace(os.Getenv("S3_PUBLIC_URL"))
	if cfg.AWSPublicURL == "" && cfg.AWSEndpointS3 != "" && cfg.AWSBucketName != "" {
		cfg.AWSPublicURL = strings.TrimRight(cfg.AWSEndpointS3, "/") + "/" + cfg.AWSBucketName
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks that all required configuration is present and valid.
// When mocks are NOT active for a service, the corresponding secrets are required.
func (c *Config) Validate() error {
	var errs []string

	// OIDC: require Google credentials unless --no-oidc
	if !c.NoOIDC {
		if c.GoogleClientID == "" {
			errs = append(errs, "GOOGLE_CLIENT_ID is required (set env var or use --no-oidc)")
		}
		if c.GoogleClientSecret == "" {
			errs = append(errs, "GOOGLE_CLIENT_SECRET is required (set env var or use --no-oidc)")
		}
	}

	// Email: require Resend API key unless --no-email
	if !c.NoEmail {
		if c.ResendAPIKey == "" {
			errs = append(errs, "RESEND_API_KEY is required (set env var or use --no-email)")
		}
	}

	// S3/Tigris: require AWS credentials unless --no-s3
	if !c.NoS3 {
		if c.AWSEndpointS3 == "" {
			errs = append(errs, "AWS_ENDPOINT_URL_S3 is required (set env var or use --no-s3)")
		}
		if c.AWSBucketName == "" {
			errs = append(errs, "BUCKET_NAME is required (set env var or use --no-s3)")
		}
		if c.AWSAccessKeyID == "" {
			errs = append(errs, "AWS_ACCESS_KEY_ID is required (set env var or use --no-s3)")
		}
		if c.AWSSecretAccessKey == "" {
			errs = append(errs, "AWS_SECRET_ACCESS_KEY is required (set env var or use --no-s3)")
		}
	}

	// MasterKey: always required (losing it = all user DBs unreadable)
	if c.MasterKey == "" {
		errs = append(errs, "MASTER_KEY is required (generate with: openssl rand -hex 32)")
	} else if len(c.MasterKey) != 64 {
		errs = append(errs, "MASTER_KEY must be 64 hex characters (32 bytes)")
	}

	// OAuth secrets: always required (no mock for OAuth provider)
	if c.OAuthHMACSecret == "" {
		errs = append(errs, "OAUTH_HMAC_SECRET is required (generate with: openssl rand -hex 32)")
	} else if len(c.OAuthHMACSecret) < 64 {
		errs = append(errs, "OAUTH_HMAC_SECRET must be at least 64 hex characters (32 bytes)")
	}

	if c.OAuthSigningKey == "" {
		errs = append(errs, "OAUTH_SIGNING_KEY is required (generate with: openssl rand -hex 32)")
	} else if len(c.OAuthSigningKey) != 64 {
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
	return !c.NoOIDC && !c.NoEmail && !c.NoS3
}

// IsDevelopment returns true if any mock services are enabled.
func (c *Config) IsDevelopment() bool {
	return c.NoOIDC || c.NoEmail || c.NoS3
}

// RequireSecureCookies returns true if secure cookies should be required.
// Returns false for localhost development URLs.
func (c *Config) RequireSecureCookies() bool {
	return !strings.HasPrefix(c.BaseURL, "http://localhost") &&
		!strings.HasPrefix(c.BaseURL, "http://127.0.0.1")
}

// PrintStartupSummary prints a human-readable summary of the configuration to stderr.
func (c *Config) PrintStartupSummary() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "commonink server starting...")

	// Auth
	if c.NoOIDC {
		fmt.Fprintln(os.Stderr, "  Auth:    Mock OIDC (--no-oidc)")
	} else {
		fmt.Fprintln(os.Stderr, "  Auth:    Google OIDC (real)")
	}

	// Email
	if c.NoEmail {
		fmt.Fprintln(os.Stderr, "  Email:   Mock (--no-email)")
	} else {
		fmt.Fprintf(os.Stderr, "  Email:   Resend (real, from: %s)\n", c.ResendFromEmail)
	}

	// Storage
	if c.NoS3 {
		fmt.Fprintln(os.Stderr, "  Storage: Mock S3 (--no-s3)")
	} else {
		fmt.Fprintf(os.Stderr, "  Storage: Tigris S3 (real, endpoint: %s)\n", c.AWSEndpointS3)
	}

	// Master key
	fmt.Fprintln(os.Stderr, "  Master:  From MASTER_KEY env var")

	// Listen address
	fmt.Fprintf(os.Stderr, "  Listen:  %s\n", c.ListenAddr)
	fmt.Fprintf(os.Stderr, "  Base:    %s\n", c.BaseURL)
	fmt.Fprintln(os.Stderr, "")
}

// Helper functions for parsing environment variables

func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
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
func MustLoadConfig(noEmail, noS3, noOIDC bool, addr string) *Config {
	cfg, err := LoadConfig(noEmail, noS3, noOIDC, addr)
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			panic(fmt.Sprintf("Configuration validation failed:\n  - %s", strings.Join(validationErr.Errors, "\n  - ")))
		}
		panic(fmt.Sprintf("Failed to load configuration: %v", err))
	}
	return cfg
}
