// Package ratelimit provides per-user and per-IP rate limiting functionality.
package ratelimit

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPConfig defines the rate limiting configuration for unauthenticated
// (IP-based) requests.
type IPConfig struct {
	RPS             float64       // Requests per second per IP
	Burst           int           // Burst size per IP
	CleanupInterval time.Duration // How often to clean up idle limiters
}

// DefaultIPConfig provides sensible defaults for IP-based rate limiting.
// Tighter than authenticated rate limits since these protect login/register/DCR/token.
var DefaultIPConfig = IPConfig{
	RPS:             2,               // 2 requests/second per IP
	Burst:           5,               // Allow burst of 5
	CleanupInterval: 5 * time.Minute, // Shorter cleanup for IPs
}

// ipLimiterEntry holds a rate limiter and tracks its last usage.
type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

// IPRateLimiter manages per-IP rate limiting for unauthenticated endpoints.
type IPRateLimiter struct {
	limiters map[string]*ipLimiterEntry
	mu       sync.RWMutex
	config   IPConfig

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewIPRateLimiter creates a new IP-based rate limiter with the given configuration.
// It starts a background goroutine for cleanup.
func NewIPRateLimiter(config IPConfig) *IPRateLimiter {
	rl := &IPRateLimiter{
		limiters: make(map[string]*ipLimiterEntry),
		config:   config,
		stopCh:   make(chan struct{}),
	}

	rl.wg.Add(1)
	go rl.cleanupLoop()

	return rl
}

// GetLimiter returns the rate limiter for the given IP, creating one if necessary.
func (rl *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	// Fast path: check if limiter exists with read lock
	rl.mu.RLock()
	entry, exists := rl.limiters[ip]
	if exists {
		entry.lastUsed = time.Now()
		rl.mu.RUnlock()
		return entry.limiter
	}
	rl.mu.RUnlock()

	// Slow path: create limiter with write lock
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	entry, exists = rl.limiters[ip]
	if exists {
		entry.lastUsed = time.Now()
		return entry.limiter
	}

	limiter := rate.NewLimiter(rate.Limit(rl.config.RPS), rl.config.Burst)
	rl.limiters[ip] = &ipLimiterEntry{
		limiter:  limiter,
		lastUsed: time.Now(),
	}

	return limiter
}

// Allow checks if a request from the given IP is allowed.
func (rl *IPRateLimiter) Allow(ip string) bool {
	return rl.GetLimiter(ip).Allow()
}

// Cleanup removes rate limiters that have been idle for longer than the cleanup interval.
func (rl *IPRateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.config.CleanupInterval)
	for ip, entry := range rl.limiters {
		if entry.lastUsed.Before(cutoff) {
			delete(rl.limiters, ip)
		}
	}
}

func (rl *IPRateLimiter) cleanupLoop() {
	defer rl.wg.Done()

	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.Cleanup()
		case <-rl.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine and waits for it to finish.
func (rl *IPRateLimiter) Stop() {
	close(rl.stopCh)
	rl.wg.Wait()
}

// Len returns the number of active IP rate limiters.
func (rl *IPRateLimiter) Len() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return len(rl.limiters)
}

// IPRateLimitMiddleware creates HTTP middleware that enforces IP-based rate limits
// for unauthenticated endpoints (login, register, DCR, token exchange).
func IPRateLimitMiddleware(limiter *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractClientIP(r)

			if !limiter.Allow(ip) {
				w.Header().Set("Retry-After", strconv.Itoa(DefaultRetryAfterSeconds))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte("Too Many Requests"))
				return
			}

			remaining := int(limiter.GetLimiter(ip).Tokens())
			if remaining < 0 {
				remaining = 0
			}
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

			next.ServeHTTP(w, r)
		})
	}
}

// extractClientIP extracts the client IP from the request.
// Checks X-Forwarded-For and X-Real-IP headers first, then falls back to RemoteAddr.
func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (may contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Use the first IP (client IP)
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
