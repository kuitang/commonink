// Package ratelimit provides per-user rate limiting functionality.
package ratelimit

import (
	"net/http"
	"strconv"
)

// DefaultRetryAfterSeconds is the default value for the Retry-After header
// when a rate limit is exceeded.
const DefaultRetryAfterSeconds = 1

// RateLimitMiddleware creates HTTP middleware that enforces rate limits.
//
// Parameters:
//   - limiter: The rate limiter instance to use
//   - getUserID: Function to extract user ID from the request (e.g., from auth token)
//   - getIsPaid: Function to determine if the user has a paid subscription
//
// The middleware returns 429 Too Many Requests when the rate limit is exceeded,
// including:
//   - Retry-After header with the recommended wait time in seconds
//   - X-RateLimit-Remaining header with the approximate remaining requests
func RateLimitMiddleware(limiter *RateLimiter, getUserID func(r *http.Request) string, getIsPaid func(r *http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := getUserID(r)

			// If no user ID, skip rate limiting (unauthenticated requests)
			// They will be handled by auth middleware
			if userID == "" {
				next.ServeHTTP(w, r)
				return
			}

			isPaid := getIsPaid(r)

			// Get the limiter for this user to check tokens before allowing
			rateLimiter := limiter.GetLimiter(userID, isPaid)

			// Check if request is allowed
			if !rateLimiter.Allow() {
				// Rate limit exceeded
				w.Header().Set("Retry-After", strconv.Itoa(DefaultRetryAfterSeconds))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte("Too Many Requests"))
				return
			}

			// Request allowed - add remaining tokens header
			// Tokens() returns the current number of available tokens
			remaining := int(rateLimiter.Tokens())
			if remaining < 0 {
				remaining = 0
			}
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

			next.ServeHTTP(w, r)
		})
	}
}
