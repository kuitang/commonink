#!/bin/bash
# Run server with real Google OIDC credentials loaded from google_secret.json
# Usage: ./scripts/run-with-google.sh

set -e

# Initialize goenv
export GOENV_ROOT="$HOME/.goenv"
export PATH="$GOENV_ROOT/bin:$PATH"
eval "$(goenv init -)"

# CGO flags for SQLCipher + FTS5
export CGO_ENABLED=1
export CGO_CFLAGS="-DSQLITE_ENABLE_FTS5"
export CGO_LDFLAGS="-lm"

# Load Google credentials from JSON file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SECRETS_FILE="${PROJECT_DIR}/google_secret.json"

if [ ! -f "$SECRETS_FILE" ]; then
    echo "Error: google_secret.json not found at $SECRETS_FILE"
    echo "Please create google_secret.json with your Google OAuth credentials"
    exit 1
fi

# Parse JSON and export environment variables
export GOOGLE_CLIENT_ID=$(cat "$SECRETS_FILE" | grep -o '"client_id":"[^"]*"' | cut -d'"' -f4)
export GOOGLE_CLIENT_SECRET=$(cat "$SECRETS_FILE" | grep -o '"client_secret":"[^"]*"' | cut -d'"' -f4)
export GOOGLE_REDIRECT_URL=$(cat "$SECRETS_FILE" | grep -o '"redirect_uris":\["[^"]*"' | cut -d'"' -f4)

# Disable mocks for real testing
export USE_MOCK_OIDC=false
export USE_MOCK_EMAIL=false

# Load Resend API key
RESEND_KEY_FILE="${PROJECT_DIR}/resend_api_key.txt"
if [ -f "$RESEND_KEY_FILE" ]; then
    export RESEND_API_KEY=$(cat "$RESEND_KEY_FILE" | tr -d '\n')
    export RESEND_FROM_EMAIL="onboarding@resend.dev"  # Use Resend test sender (no domain verification needed)
    echo "Resend API key loaded"
else
    echo "Warning: resend_api_key.txt not found, using mock email"
    export USE_MOCK_EMAIL=true
fi

# Load or generate persistent master key
MASTER_KEY_FILE="${PROJECT_DIR}/.master_key"
if [ -f "$MASTER_KEY_FILE" ]; then
    export MASTER_KEY=$(cat "$MASTER_KEY_FILE" | tr -d '\n')
    echo "Master key loaded from .master_key"
else
    export MASTER_KEY=$(openssl rand -hex 32)
    echo "$MASTER_KEY" > "$MASTER_KEY_FILE"
    chmod 600 "$MASTER_KEY_FILE"
    echo "Generated new master key and saved to .master_key"
fi

# Server config
export LISTEN_ADDR=:8080
export BASE_URL=http://localhost:8080

echo "=== Configuration ==="
echo "Google Client ID: ${GOOGLE_CLIENT_ID:0:20}..."
echo "Google Redirect URL: $GOOGLE_REDIRECT_URL"
echo "USE_MOCK_OIDC: $USE_MOCK_OIDC"
echo "USE_MOCK_EMAIL: $USE_MOCK_EMAIL"
echo "Resend From: $RESEND_FROM_EMAIL"
echo ""
echo "Starting server on http://localhost:8080"
echo "Open http://localhost:8080/login to test Google login"
echo ""

cd "$PROJECT_DIR"

# Log file for debugging
LOG_FILE="${PROJECT_DIR}/server.log"
echo "Logging to $LOG_FILE"
echo ""

go run ./cmd/server 2>&1 | tee "$LOG_FILE"
