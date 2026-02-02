// Package e2e provides end-to-end tests for rate limiting.
// These tests verify rate limiting behavior via HTTP observable effects.
package e2e

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/internal/ratelimit"
)

// =============================================================================
// Rate Limiting HTTP Tests - Observable Behavior (Deterministic)
// =============================================================================

// rateLimitTestServer holds the server for rate limit testing.
type rateLimitTestServer struct {
	server  *httptest.Server
	limiter *ratelimit.RateLimiter
}

var rateLimitTestMutex sync.Mutex

// setupRateLimitTestServer creates a test server with rate limiting middleware.
func setupRateLimitTestServer(config ratelimit.Config) *rateLimitTestServer {
	rateLimitTestMutex.Lock()

	limiter := ratelimit.NewRateLimiter(config)

	// Simple handler that returns 200 OK
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with rate limit middleware
	wrapped := ratelimit.RateLimitMiddleware(limiter,
		func(r *http.Request) string {
			return r.Header.Get("X-User-ID")
		},
		func(r *http.Request) bool {
			return r.Header.Get("X-Is-Paid") == "true"
		},
	)(handler)

	server := httptest.NewServer(wrapped)

	return &rateLimitTestServer{
		server:  server,
		limiter: limiter,
	}
}

func (s *rateLimitTestServer) cleanup() {
	s.server.Close()
	s.limiter.Stop()
	rateLimitTestMutex.Unlock()
}

// makeRequest makes a request with the given user ID and paid status.
func (s *rateLimitTestServer) makeRequest(userID string, isPaid bool) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, s.server.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-User-ID", userID)
	if isPaid {
		req.Header.Set("X-Is-Paid", "true")
	}
	return http.DefaultClient.Do(req)
}

// =============================================================================
// Test: Requests within burst limit return 200
// =============================================================================

func TestRateLimitAPI_WithinBurst_Returns200(t *testing.T) {
	config := ratelimit.Config{
		FreeRPS:         100.0,
		FreeBurst:       50,
		PaidRPS:         1000.0,
		PaidBurst:       500,
		CleanupInterval: time.Hour,
	}

	srv := setupRateLimitTestServer(config)
	defer srv.cleanup()

	// Make 10 requests within burst limit
	for i := 0; i < 10; i++ {
		resp, err := srv.makeRequest("test-user", false)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Request %d: expected 200, got %d", i, resp.StatusCode)
		}

		// X-RateLimit-Remaining header should be present
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		if remaining == "" {
			t.Fatalf("Request %d: missing X-RateLimit-Remaining header", i)
		}
	}
}

// =============================================================================
// Test: Requests exceeding burst return 429 with Retry-After
// =============================================================================

func TestRateLimitAPI_ExceedBurst_Returns429(t *testing.T) {
	config := ratelimit.Config{
		FreeRPS:         0.001, // Very low - almost no refill
		FreeBurst:       3,
		PaidRPS:         0.001,
		PaidBurst:       5,
		CleanupInterval: time.Hour,
	}

	srv := setupRateLimitTestServer(config)
	defer srv.cleanup()

	// Exhaust the burst
	for i := 0; i < config.FreeBurst; i++ {
		resp, _ := srv.makeRequest("burst-test-user", false)
		resp.Body.Close()
	}

	// Next request should be rate limited
	resp, err := srv.makeRequest("burst-test-user", false)
	if err != nil {
		t.Fatalf("Rate limited request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("Expected 429, got %d", resp.StatusCode)
	}

	// Retry-After header should be present
	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("Missing Retry-After header on 429 response")
	}

	// Retry-After should be a valid number
	_, err = strconv.Atoi(retryAfter)
	if err != nil {
		t.Fatalf("Retry-After header is not a valid number: %s", retryAfter)
	}

	// X-RateLimit-Remaining should be 0
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	if remaining != "0" {
		t.Fatalf("Expected X-RateLimit-Remaining=0, got %s", remaining)
	}
}

// =============================================================================
// Test: Different users have independent rate limits
// =============================================================================

func TestRateLimitAPI_UserIndependence(t *testing.T) {
	config := ratelimit.Config{
		FreeRPS:         0.001,
		FreeBurst:       3,
		PaidRPS:         0.001,
		PaidBurst:       5,
		CleanupInterval: time.Hour,
	}

	srv := setupRateLimitTestServer(config)
	defer srv.cleanup()

	// Exhaust user1's limit
	for i := 0; i < config.FreeBurst; i++ {
		resp, _ := srv.makeRequest("user1", false)
		resp.Body.Close()
	}

	// Verify user1 is rate limited
	resp1, _ := srv.makeRequest("user1", false)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("User1 should be rate limited, got %d", resp1.StatusCode)
	}

	// User2 should NOT be affected
	resp2, err := srv.makeRequest("user2", false)
	if err != nil {
		t.Fatalf("User2 request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("User2 should get 200, got %d (user independence violated)", resp2.StatusCode)
	}
}

// =============================================================================
// Test: Paid users have higher limits than free users
// =============================================================================

func TestRateLimitAPI_PaidVsFree(t *testing.T) {
	config := ratelimit.Config{
		FreeRPS:         0.001,
		FreeBurst:       3,
		PaidRPS:         0.001,
		PaidBurst:       10,
		CleanupInterval: time.Hour,
	}

	srv := setupRateLimitTestServer(config)
	defer srv.cleanup()

	// Make FreeBurst+1 requests for free user - should get rate limited
	var freeLastStatus int
	for i := 0; i <= config.FreeBurst; i++ {
		resp, _ := srv.makeRequest("free-user", false)
		freeLastStatus = resp.StatusCode
		resp.Body.Close()
	}

	if freeLastStatus != http.StatusTooManyRequests {
		t.Fatalf("Free user should be rate limited after %d requests, got %d", config.FreeBurst, freeLastStatus)
	}

	// Make FreeBurst+1 requests for paid user - should NOT be rate limited yet
	var paidLastStatus int
	for i := 0; i <= config.FreeBurst; i++ {
		resp, _ := srv.makeRequest("paid-user", true)
		paidLastStatus = resp.StatusCode
		resp.Body.Close()
	}

	if paidLastStatus != http.StatusOK {
		t.Fatalf("Paid user should NOT be rate limited after %d requests, got %d", config.FreeBurst+1, paidLastStatus)
	}
}

// =============================================================================
// Test: Unauthenticated requests bypass rate limiting
// =============================================================================

func TestRateLimitAPI_UnauthenticatedBypass(t *testing.T) {
	config := ratelimit.Config{
		FreeRPS:         0.001,
		FreeBurst:       2,
		PaidRPS:         0.001,
		PaidBurst:       2,
		CleanupInterval: time.Hour,
	}

	srv := setupRateLimitTestServer(config)
	defer srv.cleanup()

	// Make many requests without user ID - should all succeed
	for i := 0; i < 10; i++ {
		resp, err := srv.makeRequest("", false) // Empty user ID
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Request %d: unauthenticated request should return 200, got %d", i, resp.StatusCode)
		}
	}
}
