package config

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/internal/ratelimit"
	"pgregory.net/rapid"
)

func validTestConfig() Config {
	return Config{
		NoOIDC:               true,
		NoEmail:              true,
		NoS3:                 true,
		MasterKey:            strings.Repeat("a", 64),
		OAuthHMACSecret:      strings.Repeat("b", 64),
		OAuthSigningKey:      strings.Repeat("c", 64),
		SpriteToken:          "test-sprite-token",
		RateLimitConfig:      defaultRateLimitConfig(),
		StripeSecretKey:      "",
		StripePublishableKey: "",
		StripeWebhookSecret:  "",
		StripePriceMonthly:   "",
		StripePriceAnnual:    "",
	}
}

func defaultRateLimitConfig() ratelimit.Config {
	return ratelimit.Config{
		FreeRPS:         10,
		FreeBurst:       20,
		PaidRPS:         1000,
		PaidBurst:       2000,
		CleanupInterval: time.Hour,
	}
}

func TestValidate_TestModeMinimalConfigPasses(t *testing.T) {
	t.Parallel()
	cfg := validTestConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid test-mode config, got error: %v", err)
	}
}

func TestValidate_RequiresServiceSecretsWhenNotMocked(t *testing.T) {
	t.Parallel()
	cfg := validTestConfig()
	cfg.NoOIDC = false
	cfg.NoEmail = false
	cfg.NoS3 = false
	cfg.StripeSecretKey = ""
	cfg.StripePublishableKey = ""
	cfg.StripeWebhookSecret = ""
	cfg.StripePriceMonthly = ""
	cfg.StripePriceAnnual = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error when real services are enabled without secrets")
	}
	msg := err.Error()
	for _, expected := range []string{
		"GOOGLE_CLIENT_ID",
		"GOOGLE_CLIENT_SECRET",
		"RESEND_API_KEY",
		"STRIPE_SECRET_KEY",
		"AWS_ENDPOINT_URL_S3",
	} {
		if !strings.Contains(msg, expected) {
			t.Fatalf("expected validation error to mention %q, got: %v", expected, err)
		}
	}
}

func testValidate_RejectsInvalidCoreKeyLengths(t *rapid.T) {
	cfg := validTestConfig()

	cfg.MasterKey = strings.Repeat("a", rapid.IntRange(1, 63).Draw(t, "master_key_len"))
	cfg.OAuthHMACSecret = strings.Repeat("b", rapid.IntRange(1, 63).Draw(t, "hmac_len"))
	cfg.OAuthSigningKey = strings.Repeat("c", rapid.IntRange(1, 63).Draw(t, "signing_len"))

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for short core keys")
	}
	msg := err.Error()
	for _, token := range []string{"MASTER_KEY", "OAUTH_HMAC_SECRET", "OAUTH_SIGNING_KEY"} {
		if !strings.Contains(msg, token) {
			t.Fatalf("expected key-length error mentioning %q, got: %v", token, err)
		}
	}
}

func TestValidate_RejectsInvalidCoreKeyLengths(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testValidate_RejectsInvalidCoreKeyLengths)
}

func TestHelperParsers_DefaultOnBadInput(t *testing.T) {
	t.Setenv("CFG_TEST_INT", "not-an-int")
	t.Setenv("CFG_TEST_FLOAT", "not-a-float")
	t.Setenv("CFG_TEST_DUR", "not-a-duration")
	if got := parseIntOrDefault("CFG_TEST_INT", 7); got != 7 {
		t.Fatalf("parseIntOrDefault fallback mismatch: got=%d want=7", got)
	}
	if got := parseFloat64OrDefault("CFG_TEST_FLOAT", 3.5); got != 3.5 {
		t.Fatalf("parseFloat64OrDefault fallback mismatch: got=%v want=3.5", got)
	}
	if got := parseDurationOrDefault("CFG_TEST_DUR", 2*time.Minute); got != 2*time.Minute {
		t.Fatalf("parseDurationOrDefault fallback mismatch: got=%v want=%v", got, 2*time.Minute)
	}
}

func TestGetEnvOrDefault_TrimsWhitespace(t *testing.T) {
	key := "CFG_TEST_STR_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := os.Setenv(key, "   value   "); err != nil {
		t.Fatalf("Setenv failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv(key) })

	if got := getEnvOrDefault(key, "fallback"); got != "value" {
		t.Fatalf("getEnvOrDefault trim mismatch: got=%q want=%q", got, "value")
	}
}
