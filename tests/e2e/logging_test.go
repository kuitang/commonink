package e2e

import (
	"io"
	"log"
	"os"
)

// Keep e2e output quiet by default for speed; opt in with E2E_TEST_DEBUG_LOGS=1.
func init() {
	if os.Getenv("E2E_TEST_DEBUG_LOGS") == "" {
		log.SetOutput(io.Discard)
	}
}
