package e2e

import (
	"os"
	"testing"

	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// TestMain ensures prompt process exit after all tests complete.
// Shared test fixtures create background goroutines (RateLimiter.cleanupLoop,
// httptest.Server accept loops, sql.DB.connectionOpener) that would otherwise
// prevent the process from exiting. We close all shared fixtures, then call
// os.Exit to terminate any stragglers.
func TestMain(m *testing.M) {
	code := m.Run()

	// Stop the subprocess server (apps_api_test.go uses testutil.GetServer).
	testutil.Cleanup()

	// Close all shared httptest fixtures. Each closeSharedResources() stops
	// the httptest.Server, mock S3 server, RateLimiter, sessionsDB, mockOIDC,
	// and removes the temp directory — eliminating all background goroutines.
	if staticPageSharedFixture != nil {
		staticPageSharedFixture.closeSharedResources()
	}
	if webFormSharedFixture != nil {
		webFormSharedFixture.closeSharedResources()
	}
	if shortURLWebSharedFixture != nil {
		shortURLWebSharedFixture.closeSharedResources()
	}
	if integrationSharedFixture != nil {
		integrationSharedFixture.closeSharedResources()
	}
	if oauthSharedFixture != nil {
		oauthSharedFixture.closeSharedResources()
	}
	if apiKeySharedFixture != nil {
		apiKeySharedFixture.closeSharedResources()
	}
	if oidcSharedFixture != nil {
		oidcSharedFixture.closeSharedResources()
	}

	os.Exit(code)
}
