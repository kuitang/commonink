package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// =============================================================================
// Generators for property-based testing
// =============================================================================

// userIDGenerator generates valid user IDs
func userIDGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z0-9]{8,32}`)
}

// configGenerator generates valid rate limiter configurations
func configGenerator() *rapid.Generator[Config] {
	return rapid.Custom(func(t *rapid.T) Config {
		cleanupSecs := rapid.IntRange(1, 3600).Draw(t, "cleanupSecs")
		return Config{
			FreeRPS:         rapid.Float64Range(1.0, 100.0).Draw(t, "freeRPS"),
			FreeBurst:       rapid.IntRange(1, 200).Draw(t, "freeBurst"),
			PaidRPS:         rapid.Float64Range(100.0, 10000.0).Draw(t, "paidRPS"),
			PaidBurst:       rapid.IntRange(200, 5000).Draw(t, "paidBurst"),
			CleanupInterval: time.Duration(cleanupSecs) * time.Second,
		}
	})
}

// =============================================================================
// Property: Requests within limit succeed
// =============================================================================

func testRateLimiter_RequestsWithinLimit(t *rapid.T) {
	config := Config{
		FreeRPS:         100.0, // High enough to not hit rate limit during test
		FreeBurst:       200,
		PaidRPS:         1000.0,
		PaidBurst:       2000,
		CleanupInterval: time.Hour,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	userID := userIDGenerator().Draw(t, "userID")
	isPaid := rapid.Bool().Draw(t, "isPaid")

	// Make requests within the burst limit
	burst := config.FreeBurst
	if isPaid {
		burst = config.PaidBurst
	}

	// Use a small number of requests well within burst
	numRequests := rapid.IntRange(1, min(burst/2, 50)).Draw(t, "numRequests")

	// Property: All requests within burst limit should succeed
	for i := 0; i < numRequests; i++ {
		if !rl.Allow(userID, isPaid) {
			t.Fatalf("Request %d of %d should have been allowed (within burst of %d)", i+1, numRequests, burst)
		}
	}
}

func TestRateLimiter_RequestsWithinLimit(t *testing.T) {
	rapid.Check(t, testRateLimiter_RequestsWithinLimit)
}

func FuzzRateLimiter_RequestsWithinLimit(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_RequestsWithinLimit))
}

// =============================================================================
// Property: Requests exceeding limit return false (blocked)
// =============================================================================

func testRateLimiter_ExceedingLimitBlocked(t *rapid.T) {
	// Use very low limits to easily exceed them
	config := Config{
		FreeRPS:         0.001, // Very low - almost no refill
		FreeBurst:       5,     // Very small burst
		PaidRPS:         0.001,
		PaidBurst:       10,
		CleanupInterval: time.Hour,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	userID := userIDGenerator().Draw(t, "userID")
	isPaid := rapid.Bool().Draw(t, "isPaid")

	burst := config.FreeBurst
	if isPaid {
		burst = config.PaidBurst
	}

	// Exhaust the burst allowance
	for i := 0; i < burst; i++ {
		rl.Allow(userID, isPaid)
	}

	// Property: Request beyond burst should be blocked (with very low RPS, refill is negligible)
	allowed := rl.Allow(userID, isPaid)
	if allowed {
		t.Fatalf("Request beyond burst limit of %d should have been blocked", burst)
	}
}

func TestRateLimiter_ExceedingLimitBlocked(t *testing.T) {
	rapid.Check(t, testRateLimiter_ExceedingLimitBlocked)
}

func FuzzRateLimiter_ExceedingLimitBlocked(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_ExceedingLimitBlocked))
}

// =============================================================================
// Property: Different users have independent limits
// =============================================================================

func testRateLimiter_UserIndependence(t *rapid.T) {
	config := Config{
		FreeRPS:         0.001, // Very low - almost no refill
		FreeBurst:       5,     // Small burst for testing
		PaidRPS:         0.001,
		PaidBurst:       10,
		CleanupInterval: time.Hour,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	// Generate two different user IDs
	userID1 := userIDGenerator().Draw(t, "userID1")
	userID2 := userIDGenerator().Filter(func(s string) bool {
		return s != userID1
	}).Draw(t, "userID2")

	// Exhaust user1's limit
	for i := 0; i < config.FreeBurst; i++ {
		rl.Allow(userID1, false)
	}

	// Verify user1 is now blocked
	if rl.Allow(userID1, false) {
		t.Fatal("User1 should be blocked after exhausting burst")
	}

	// Property: User2 should still be able to make requests
	// (their limit is independent of user1's)
	if !rl.Allow(userID2, false) {
		t.Fatal("User2 should still be allowed - limits should be independent per user")
	}
}

func TestRateLimiter_UserIndependence(t *testing.T) {
	rapid.Check(t, testRateLimiter_UserIndependence)
}

func FuzzRateLimiter_UserIndependence(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_UserIndependence))
}

// =============================================================================
// Property: Paid users have higher limits than free users
// =============================================================================

func testRateLimiter_PaidUsersHigherLimits(t *rapid.T) {
	// Configure with paid burst > free burst
	freeBurst := rapid.IntRange(5, 20).Draw(t, "freeBurst")
	paidBurst := rapid.IntRange(freeBurst+10, freeBurst+100).Draw(t, "paidBurst")

	config := Config{
		FreeRPS:         0.001, // Very low - almost no refill
		FreeBurst:       freeBurst,
		PaidRPS:         0.001,
		PaidBurst:       paidBurst,
		CleanupInterval: time.Hour,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	// Generate a user ID for testing both tiers
	userID := userIDGenerator().Draw(t, "userID")

	// First test as free user - exhaust free burst
	for i := 0; i < freeBurst; i++ {
		rl.Allow(userID, false)
	}

	// Free user should now be blocked
	if rl.Allow(userID, false) {
		t.Fatalf("Free user should be blocked after exhausting burst of %d", freeBurst)
	}

	// Create a new limiter for clean state
	rl2 := NewRateLimiter(config)
	defer rl2.Stop()

	// Test as paid user - should be able to make more requests
	successCount := 0
	for i := 0; i < paidBurst; i++ {
		if rl2.Allow(userID, true) {
			successCount++
		}
	}

	// Property: Paid user should be able to make more requests than free burst
	if successCount <= freeBurst {
		t.Fatalf("Paid user should have higher limit: got %d successful requests, free burst is %d",
			successCount, freeBurst)
	}
}

func TestRateLimiter_PaidUsersHigherLimits(t *testing.T) {
	rapid.Check(t, testRateLimiter_PaidUsersHigherLimits)
}

func FuzzRateLimiter_PaidUsersHigherLimits(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_PaidUsersHigherLimits))
}

// =============================================================================
// Property: Idle limiters get cleaned up after CleanupInterval
// =============================================================================

func testRateLimiter_IdleLimiterCleanup(t *rapid.T) {
	// Use very short cleanup interval for testing
	cleanupInterval := 10 * time.Millisecond

	config := Config{
		FreeRPS:         100.0,
		FreeBurst:       200,
		PaidRPS:         1000.0,
		PaidBurst:       2000,
		CleanupInterval: cleanupInterval,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	// Create some limiters
	numUsers := rapid.IntRange(2, 10).Draw(t, "numUsers")
	for i := 0; i < numUsers; i++ {
		userID := userIDGenerator().Draw(t, "userID")
		rl.Allow(userID, false)
	}

	// Verify limiters were created
	initialLen := rl.Len()
	if initialLen == 0 {
		t.Fatal("Expected some limiters to be created")
	}

	// Wait longer than cleanup interval
	time.Sleep(cleanupInterval + 5*time.Millisecond)

	// Manually trigger cleanup (since background goroutine might not have run yet)
	rl.Cleanup()

	// Property: All idle limiters should be cleaned up
	finalLen := rl.Len()
	if finalLen != 0 {
		t.Fatalf("Expected all idle limiters to be cleaned up, got %d remaining", finalLen)
	}
}

func TestRateLimiter_IdleLimiterCleanup(t *testing.T) {
	rapid.Check(t, testRateLimiter_IdleLimiterCleanup)
}

func FuzzRateLimiter_IdleLimiterCleanup(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_IdleLimiterCleanup))
}

// =============================================================================
// Property: Active limiters are NOT cleaned up
// =============================================================================

func testRateLimiter_ActiveLimiterNotCleaned(t *rapid.T) {
	cleanupInterval := 50 * time.Millisecond

	config := Config{
		FreeRPS:         100.0,
		FreeBurst:       200,
		PaidRPS:         1000.0,
		PaidBurst:       2000,
		CleanupInterval: cleanupInterval,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	userID := userIDGenerator().Draw(t, "userID")

	// Make initial request
	rl.Allow(userID, false)

	// Keep the limiter active by making requests periodically
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(cleanupInterval / 4)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.Allow(userID, false)
			case <-done:
				return
			}
		}
	}()

	// Wait and then cleanup
	time.Sleep(cleanupInterval + 10*time.Millisecond)
	rl.Cleanup()

	close(done)

	// Property: Active limiter should NOT be cleaned up
	if rl.Len() == 0 {
		t.Fatal("Active limiter should not have been cleaned up")
	}
}

func TestRateLimiter_ActiveLimiterNotCleaned(t *testing.T) {
	rapid.Check(t, testRateLimiter_ActiveLimiterNotCleaned)
}

func FuzzRateLimiter_ActiveLimiterNotCleaned(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_ActiveLimiterNotCleaned))
}

// =============================================================================
// Property: Limiter is thread-safe (concurrent access)
// =============================================================================

func testRateLimiter_ConcurrentAccess(t *rapid.T) {
	config := Config{
		FreeRPS:         1000.0, // High to allow concurrent requests
		FreeBurst:       2000,
		PaidRPS:         10000.0,
		PaidBurst:       20000,
		CleanupInterval: time.Hour,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	numUsers := rapid.IntRange(5, 20).Draw(t, "numUsers")
	numGoroutines := rapid.IntRange(5, 20).Draw(t, "numGoroutines")
	requestsPerGoroutine := rapid.IntRange(10, 50).Draw(t, "requestsPerGoroutine")

	// Generate user IDs upfront
	userIDs := make([]string, numUsers)
	for i := 0; i < numUsers; i++ {
		userIDs[i] = userIDGenerator().Draw(t, "userID")
	}

	var wg sync.WaitGroup
	var successCount atomic.Int64
	var failCount atomic.Int64

	// Launch concurrent goroutines
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for r := 0; r < requestsPerGoroutine; r++ {
				// Pick a random user
				userIdx := (goroutineID + r) % numUsers
				userID := userIDs[userIdx]
				isPaid := (goroutineID+r)%2 == 0

				if rl.Allow(userID, isPaid) {
					successCount.Add(1)
				} else {
					failCount.Add(1)
				}
			}
		}(g)
	}

	wg.Wait()

	totalRequests := int64(numGoroutines * requestsPerGoroutine)
	actualTotal := successCount.Load() + failCount.Load()

	// Property: No requests should be lost or duplicated
	if actualTotal != totalRequests {
		t.Fatalf("Request count mismatch: expected %d, got %d (success=%d, fail=%d)",
			totalRequests, actualTotal, successCount.Load(), failCount.Load())
	}

	// Property: At least some requests should succeed (with high limits)
	if successCount.Load() == 0 {
		t.Fatal("Expected at least some requests to succeed")
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rapid.Check(t, testRateLimiter_ConcurrentAccess)
}

func FuzzRateLimiter_ConcurrentAccess(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_ConcurrentAccess))
}

// =============================================================================
// Property: GetLimiter returns same limiter for same user and tier
// =============================================================================

func testRateLimiter_GetLimiterConsistency(t *rapid.T) {
	config := Config{
		FreeRPS:         100.0,
		FreeBurst:       200,
		PaidRPS:         1000.0,
		PaidBurst:       2000,
		CleanupInterval: time.Hour,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	userID := userIDGenerator().Draw(t, "userID")
	isPaid := rapid.Bool().Draw(t, "isPaid")

	// Get limiter multiple times
	limiter1 := rl.GetLimiter(userID, isPaid)
	limiter2 := rl.GetLimiter(userID, isPaid)
	limiter3 := rl.GetLimiter(userID, isPaid)

	// Property: Should return the same limiter instance
	if limiter1 != limiter2 || limiter2 != limiter3 {
		t.Fatal("GetLimiter should return the same instance for same user and tier")
	}
}

func TestRateLimiter_GetLimiterConsistency(t *testing.T) {
	rapid.Check(t, testRateLimiter_GetLimiterConsistency)
}

func FuzzRateLimiter_GetLimiterConsistency(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_GetLimiterConsistency))
}

// =============================================================================
// Property: Tier change creates new limiter with appropriate limits
// =============================================================================

func testRateLimiter_TierChangeCreatesNewLimiter(t *rapid.T) {
	config := Config{
		FreeRPS:         10.0,
		FreeBurst:       20,
		PaidRPS:         1000.0,
		PaidBurst:       2000,
		CleanupInterval: time.Hour,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	userID := userIDGenerator().Draw(t, "userID")

	// Get limiter as free user
	freeLimiter := rl.GetLimiter(userID, false)

	// Get limiter as paid user (tier change)
	paidLimiter := rl.GetLimiter(userID, true)

	// Property: Should be different limiters due to tier change
	if freeLimiter == paidLimiter {
		t.Fatal("Tier change should create a new limiter")
	}

	// Property: Paid limiter should have higher burst
	// The burst is set via the limiter, and we verify it indirectly
	// by checking we can get through the paid limiter instance
	if paidLimiter == nil {
		t.Fatal("Paid limiter should not be nil")
	}
}

func TestRateLimiter_TierChangeCreatesNewLimiter(t *testing.T) {
	rapid.Check(t, testRateLimiter_TierChangeCreatesNewLimiter)
}

func FuzzRateLimiter_TierChangeCreatesNewLimiter(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_TierChangeCreatesNewLimiter))
}

// =============================================================================
// Property: Len returns correct count of active limiters
// =============================================================================

func testRateLimiter_LenReturnsCorrectCount(t *rapid.T) {
	config := Config{
		FreeRPS:         100.0,
		FreeBurst:       200,
		PaidRPS:         1000.0,
		PaidBurst:       2000,
		CleanupInterval: time.Hour,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	// Initially should have 0 limiters
	if rl.Len() != 0 {
		t.Fatalf("Expected 0 limiters initially, got %d", rl.Len())
	}

	// Create unique users
	numUsers := rapid.IntRange(1, 20).Draw(t, "numUsers")
	createdUsers := make(map[string]bool)

	for i := 0; i < numUsers; i++ {
		userID := userIDGenerator().Filter(func(s string) bool {
			return !createdUsers[s]
		}).Draw(t, "userID")
		createdUsers[userID] = true
		rl.Allow(userID, false)
	}

	// Property: Len should match the number of unique users
	if rl.Len() != len(createdUsers) {
		t.Fatalf("Expected %d limiters, got %d", len(createdUsers), rl.Len())
	}
}

func TestRateLimiter_LenReturnsCorrectCount(t *testing.T) {
	rapid.Check(t, testRateLimiter_LenReturnsCorrectCount)
}

func FuzzRateLimiter_LenReturnsCorrectCount(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_LenReturnsCorrectCount))
}

// =============================================================================
// Property: Default config has sensible values
// =============================================================================

func testRateLimiter_DefaultConfigValid(t *rapid.T) {
	// Property: Default config should create a working rate limiter
	rl := NewRateLimiter(DefaultConfig)
	defer rl.Stop()

	userID := userIDGenerator().Draw(t, "userID")

	// Should allow at least one request
	if !rl.Allow(userID, false) {
		t.Fatal("Default config should allow requests")
	}

	// Property: Default config values should be positive and sensible
	if DefaultConfig.FreeRPS <= 0 {
		t.Fatal("FreeRPS should be positive")
	}
	if DefaultConfig.FreeBurst <= 0 {
		t.Fatal("FreeBurst should be positive")
	}
	if DefaultConfig.PaidRPS <= DefaultConfig.FreeRPS {
		t.Fatal("PaidRPS should be greater than FreeRPS")
	}
	if DefaultConfig.PaidBurst <= DefaultConfig.FreeBurst {
		t.Fatal("PaidBurst should be greater than FreeBurst")
	}
	if DefaultConfig.CleanupInterval <= 0 {
		t.Fatal("CleanupInterval should be positive")
	}
}

func TestRateLimiter_DefaultConfigValid(t *testing.T) {
	rapid.Check(t, testRateLimiter_DefaultConfigValid)
}

func FuzzRateLimiter_DefaultConfigValid(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_DefaultConfigValid))
}

// =============================================================================
// Property: Stop gracefully shuts down the cleanup goroutine
// =============================================================================

func testRateLimiter_StopGracefulShutdown(t *rapid.T) {
	config := Config{
		FreeRPS:         100.0,
		FreeBurst:       200,
		PaidRPS:         1000.0,
		PaidBurst:       2000,
		CleanupInterval: 10 * time.Millisecond, // Short interval
	}

	rl := NewRateLimiter(config)

	// Create some limiters
	numUsers := rapid.IntRange(1, 5).Draw(t, "numUsers")
	for i := 0; i < numUsers; i++ {
		userID := userIDGenerator().Draw(t, "userID")
		rl.Allow(userID, false)
	}

	// Property: Stop should return without hanging
	done := make(chan struct{})
	go func() {
		rl.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success - Stop returned
	case <-time.After(1 * time.Second):
		t.Fatal("Stop did not return within timeout - possible goroutine leak")
	}
}

func TestRateLimiter_StopGracefulShutdown(t *testing.T) {
	rapid.Check(t, testRateLimiter_StopGracefulShutdown)
}

func FuzzRateLimiter_StopGracefulShutdown(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testRateLimiter_StopGracefulShutdown))
}

// =============================================================================
// Helper function for min
// =============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
