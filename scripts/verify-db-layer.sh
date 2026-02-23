#!/bin/bash
# Verification script for the database layer implementation

set -e

echo "=================================="
echo "Database Layer Verification Script"
echo "=================================="
echo ""

# Set up Go environment
export PATH=/usr/local/go/bin:$PATH
export CGO_ENABLED=1
export CGO_CFLAGS="-DSQLITE_ENABLE_FTS5"
export CGO_LDFLAGS="-lm"

echo "✓ Environment configured"
echo "  - Go: $(go version)"
echo "  - CGO_ENABLED: $CGO_ENABLED"
echo "  - CGO_CFLAGS: $CGO_CFLAGS"
echo "  - CGO_LDFLAGS: $CGO_LDFLAGS"
echo ""

# Check for required files
echo "Checking implementation files..."
REQUIRED_FILES=(
    "internal/db/db.go"
    "internal/db/schema.go"
    "internal/db/db_test.go"
    "internal/db/integration_test.go"
    "internal/db/example_test.go"
    "Makefile"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file"
    else
        echo "  ✗ $file - MISSING!"
        exit 1
    fi
done
echo ""

# Run tests
echo "Running database layer tests..."
make test-db

echo ""
echo "=================================="
echo "✓ All verification checks passed!"
echo "=================================="
echo ""
echo "Database layer is ready for Milestone 1."
echo ""
echo "Next steps:"
echo "  1. Implement Notes CRUD logic (internal/notes/)"
echo "  2. Implement MCP server (internal/mcp/)"
echo "  3. Update main.go"
echo "  5. Run E2E tests"
