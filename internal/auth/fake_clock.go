package auth

import (
	"sync"
	stdtime "time"
)

// FakeClock is a controllable Clock for testing time-dependent behavior.
// Thread-safe for use across goroutines (e.g., test client + HTTP server).
type FakeClock struct {
	mu  sync.Mutex
	now stdtime.Time
}

// NewFakeClock creates a FakeClock frozen at the given time.
func NewFakeClock(t stdtime.Time) *FakeClock {
	return &FakeClock{now: t}
}

// Now returns the current fake time.
func (c *FakeClock) Now() stdtime.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *FakeClock) Advance(d stdtime.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
