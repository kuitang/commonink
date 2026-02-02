// Package ratelimit provides per-user rate limiting functionality.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Config defines the rate limiting configuration.
type Config struct {
	FreeRPS         float64       // Requests per second for free tier
	FreeBurst       int           // Burst size for free tier
	PaidRPS         float64       // Requests per second for paid tier
	PaidBurst       int           // Burst size for paid tier
	CleanupInterval time.Duration // How often to clean up idle limiters
}

// DefaultConfig provides sensible defaults for rate limiting.
var DefaultConfig = Config{
	FreeRPS:         10,        // 10 requests/second
	FreeBurst:       20,        // Allow burst of 20
	PaidRPS:         1000,      // Effectively unlimited for paid
	PaidBurst:       2000,      // Large burst for paid
	CleanupInterval: time.Hour, // Clean up idle limiters every hour
}

// rateLimiterEntry holds a rate limiter and tracks its last usage.
type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastUsed time.Time
	isPaid   bool // Track tier to detect tier changes
}

// RateLimiter manages per-user rate limiting.
type RateLimiter struct {
	limiters map[string]*rateLimiterEntry
	mu       sync.RWMutex
	config   Config

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewRateLimiter creates a new rate limiter with the given configuration.
// It starts a background goroutine for cleanup.
func NewRateLimiter(config Config) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
		config:   config,
		stopCh:   make(chan struct{}),
	}

	// Start the cleanup goroutine
	rl.wg.Add(1)
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from the given user is allowed.
// It returns true if the request is within rate limits, false otherwise.
func (rl *RateLimiter) Allow(userID string, isPaid bool) bool {
	limiter := rl.GetLimiter(userID, isPaid)
	return limiter.Allow()
}

// GetLimiter returns the rate limiter for the given user, creating one if necessary.
// If the user's tier has changed (isPaid status), a new limiter with appropriate limits is created.
func (rl *RateLimiter) GetLimiter(userID string, isPaid bool) *rate.Limiter {
	// Fast path: check if limiter exists with read lock
	rl.mu.RLock()
	entry, exists := rl.limiters[userID]
	if exists && entry.isPaid == isPaid {
		entry.lastUsed = time.Now()
		rl.mu.RUnlock()
		return entry.limiter
	}
	rl.mu.RUnlock()

	// Slow path: create or update limiter with write lock
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	entry, exists = rl.limiters[userID]
	if exists && entry.isPaid == isPaid {
		entry.lastUsed = time.Now()
		return entry.limiter
	}

	// Create new limiter with appropriate rate based on tier
	var rps float64
	var burst int
	if isPaid {
		rps = rl.config.PaidRPS
		burst = rl.config.PaidBurst
	} else {
		rps = rl.config.FreeRPS
		burst = rl.config.FreeBurst
	}

	limiter := rate.NewLimiter(rate.Limit(rps), burst)
	rl.limiters[userID] = &rateLimiterEntry{
		limiter:  limiter,
		lastUsed: time.Now(),
		isPaid:   isPaid,
	}

	return limiter
}

// Cleanup removes rate limiters that have been idle for longer than the cleanup interval.
// This is called periodically by the background goroutine.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.config.CleanupInterval)
	for userID, entry := range rl.limiters {
		if entry.lastUsed.Before(cutoff) {
			delete(rl.limiters, userID)
		}
	}
}

// cleanupLoop runs the periodic cleanup in the background.
func (rl *RateLimiter) cleanupLoop() {
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
// This should be called when shutting down the application.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
	rl.wg.Wait()
}

// Len returns the number of active rate limiters.
// This is primarily useful for testing and monitoring.
func (rl *RateLimiter) Len() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return len(rl.limiters)
}
