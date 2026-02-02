#!/bin/bash
# HTTP API E2E Test Script for Milestone 1
# Tests all CRUD endpoints with curl
#
# Usage: ./test.sh [--keep-server] [--base-url URL]
#   --keep-server: Don't start/stop server (use existing instance)
#   --base-url: Override the base URL (default: http://localhost:8080)

set -e  # Exit on first error

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
# Use port 18080 to avoid conflicts with common services on 8080
DEFAULT_PORT="${TEST_PORT:-18080}"
BASE_URL="${BASE_URL:-http://localhost:${DEFAULT_PORT}}"
SERVER_PID=""
KEEP_SERVER=false
HEALTH_CHECK_TIMEOUT=30
HEALTH_CHECK_INTERVAL=1

# =============================================================================
# Colors for output
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# =============================================================================
# Test counters
# =============================================================================

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# =============================================================================
# Helper functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_test() {
    echo -e "${CYAN}[TEST]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BOLD}========================================${NC}"
    echo -e "${BOLD}$1${NC}"
    echo -e "${BOLD}========================================${NC}"
    echo ""
}

# Run a test and track pass/fail
# Usage: run_test "Test name" expected_status actual_status [response_body] [expected_content]
run_test() {
    local test_name="$1"
    local expected_status="$2"
    local actual_status="$3"
    local response_body="${4:-}"
    local expected_content="${5:-}"

    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    log_test "$test_name"

    # Check HTTP status
    if [[ "$actual_status" != "$expected_status" ]]; then
        log_error "Expected HTTP $expected_status, got HTTP $actual_status"
        if [[ -n "$response_body" ]]; then
            echo "  Response: $response_body"
        fi
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi

    # Check response content if specified
    if [[ -n "$expected_content" ]]; then
        if ! echo "$response_body" | grep -q "$expected_content"; then
            log_error "Response does not contain expected content: $expected_content"
            echo "  Response: $response_body"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi
    fi

    log_success "$test_name (HTTP $actual_status)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    return 0
}

# Make HTTP request and capture both status and body
# Usage: http_request METHOD URL [DATA]
# Sets: HTTP_STATUS, HTTP_BODY
http_request() {
    local method="$1"
    local url="$2"
    local data="${3:-}"

    local curl_args=("-s" "-w" "\n%{http_code}" "-X" "$method")
    curl_args+=("-H" "Content-Type: application/json")
    curl_args+=("-H" "Accept: application/json")

    if [[ -n "$data" ]]; then
        curl_args+=("-d" "$data")
    fi

    local response
    response=$(curl "${curl_args[@]}" "$url")

    # Split response into body and status code
    HTTP_STATUS=$(echo "$response" | tail -n1)
    HTTP_BODY=$(echo "$response" | sed '$d')
}

# Extract JSON field using jq (or grep fallback)
json_field() {
    local json="$1"
    local field="$2"

    if command -v jq &> /dev/null; then
        echo "$json" | jq -r ".$field // empty"
    else
        # Fallback: basic grep extraction (works for simple cases)
        echo "$json" | grep -o "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | sed 's/.*: *"\([^"]*\)".*/\1/'
    fi
}

# =============================================================================
# Server management
# =============================================================================

start_server() {
    log_info "Building server..."

    # Initialize goenv for Go 1.25+
    export GOENV_ROOT="$HOME/.goenv"
    export PATH="$GOENV_ROOT/bin:$PATH"
    eval "$(goenv init -)"

    cd "$PROJECT_ROOT"
    # CGO_ENABLED=1 required for SQLite FTS5 support
    CGO_ENABLED=1 go build -o bin/server ./cmd/server

    log_info "Starting server..."

    # Create temp directory for test data
    export DATA_DIR=$(mktemp -d)

    # Set listen address to use our test port
    export LISTEN_ADDR=":${DEFAULT_PORT}"

    # Start server in background
    ./bin/server &
    SERVER_PID=$!

    log_info "Server started with PID $SERVER_PID"
    log_info "Data directory: $DATA_DIR"
}

stop_server() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log_info "Stopping server (PID $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        log_info "Server stopped"
    fi

    # Clean up temp data directory
    if [[ -n "${DATA_DIR:-}" ]] && [[ -d "$DATA_DIR" ]]; then
        rm -rf "$DATA_DIR"
        log_info "Cleaned up data directory"
    fi
}

wait_for_health() {
    log_info "Waiting for server to be healthy..."

    local elapsed=0
    while [[ $elapsed -lt $HEALTH_CHECK_TIMEOUT ]]; do
        if curl -s "${BASE_URL}/health" | grep -q "healthy"; then
            log_success "Server is healthy"
            return 0
        fi
        sleep $HEALTH_CHECK_INTERVAL
        elapsed=$((elapsed + HEALTH_CHECK_INTERVAL))
    done

    log_error "Server did not become healthy within ${HEALTH_CHECK_TIMEOUT}s"
    return 1
}

# =============================================================================
# Cleanup trap
# =============================================================================

cleanup() {
    local exit_code=$?

    if [[ "$KEEP_SERVER" == "false" ]]; then
        stop_server
    fi

    # Print summary
    log_section "Test Summary"
    echo -e "Total:  ${BOLD}$TESTS_TOTAL${NC}"
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}${BOLD}TESTS FAILED${NC}"
        exit 1
    elif [[ $TESTS_TOTAL -eq 0 ]]; then
        echo -e "${YELLOW}${BOLD}NO TESTS RUN${NC}"
        exit 1
    else
        echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
        exit 0
    fi
}

trap cleanup EXIT

# =============================================================================
# Parse command line arguments
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-server)
            KEEP_SERVER=true
            shift
            ;;
        --base-url)
            BASE_URL="$2"
            shift 2
            ;;
        --base-url=*)
            BASE_URL="${1#*=}"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--keep-server] [--base-url URL]"
            echo ""
            echo "Options:"
            echo "  --keep-server    Don't start/stop server (use existing instance)"
            echo "  --base-url URL   Override the base URL (default: http://localhost:8080)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# =============================================================================
# Main test execution
# =============================================================================

log_section "HTTP API E2E Tests"
log_info "Base URL: $BASE_URL"
log_info "Keep server: $KEEP_SERVER"

# Start server if needed
if [[ "$KEEP_SERVER" == "false" ]]; then
    start_server
fi

# Wait for server to be ready
wait_for_health

# =============================================================================
# Test: Health Check
# =============================================================================

log_section "Health Check"

http_request GET "${BASE_URL}/health"
run_test "GET /health returns 200" "200" "$HTTP_STATUS" "$HTTP_BODY" "healthy"

# =============================================================================
# Test: List Notes (empty)
# =============================================================================

log_section "List Notes (Empty Database)"

http_request GET "${BASE_URL}/notes"
run_test "GET /notes returns 200 for empty list" "200" "$HTTP_STATUS" "$HTTP_BODY" "notes"

# Verify empty notes array
NOTES_COUNT=$(echo "$HTTP_BODY" | jq -r '.notes | length' 2>/dev/null || echo "0")
if [[ "$NOTES_COUNT" == "0" ]] || [[ "$NOTES_COUNT" == "null" ]]; then
    log_success "Notes list is empty as expected"
else
    log_warn "Notes list may not be empty: $NOTES_COUNT notes found"
fi

# =============================================================================
# Test: Create Note
# =============================================================================

log_section "Create Note"

# Create a note
CREATE_DATA='{"title":"Test Note","content":"This is a test note created by curl E2E test."}'
http_request POST "${BASE_URL}/notes" "$CREATE_DATA"
run_test "POST /notes creates note (201)" "201" "$HTTP_STATUS" "$HTTP_BODY" "Test Note"

# Extract note ID for later tests
NOTE_ID=$(json_field "$HTTP_BODY" "id")
if [[ -z "$NOTE_ID" ]]; then
    log_error "Failed to extract note ID from create response"
    exit 1
fi
log_info "Created note with ID: $NOTE_ID"

# Verify response contains expected fields
run_test "Create response contains title" "201" "$HTTP_STATUS" "$HTTP_BODY" "Test Note"
run_test "Create response contains content" "201" "$HTTP_STATUS" "$HTTP_BODY" "test note created"
run_test "Create response contains created_at" "201" "$HTTP_STATUS" "$HTTP_BODY" "created_at"
run_test "Create response contains updated_at" "201" "$HTTP_STATUS" "$HTTP_BODY" "updated_at"

# =============================================================================
# Test: Create Note - Validation Errors
# =============================================================================

log_section "Create Note - Validation"

# Missing title
http_request POST "${BASE_URL}/notes" '{"content":"No title"}'
run_test "POST /notes without title returns 400" "400" "$HTTP_STATUS" "$HTTP_BODY" "Title is required"

# Invalid JSON
http_request POST "${BASE_URL}/notes" 'not valid json'
run_test "POST /notes with invalid JSON returns 400" "400" "$HTTP_STATUS" "$HTTP_BODY" "Invalid JSON"

# Empty body
http_request POST "${BASE_URL}/notes" '{}'
run_test "POST /notes with empty object returns 400" "400" "$HTTP_STATUS" "$HTTP_BODY" "Title is required"

# =============================================================================
# Test: Read Note
# =============================================================================

log_section "Read Note"

http_request GET "${BASE_URL}/notes/${NOTE_ID}"
run_test "GET /notes/{id} returns 200" "200" "$HTTP_STATUS" "$HTTP_BODY" "$NOTE_ID"
run_test "Get response contains title" "200" "$HTTP_STATUS" "$HTTP_BODY" "Test Note"
run_test "Get response contains content" "200" "$HTTP_STATUS" "$HTTP_BODY" "test note created"

# =============================================================================
# Test: Read Note - Not Found
# =============================================================================

log_section "Read Note - Not Found"

http_request GET "${BASE_URL}/notes/nonexistent-id-12345"
run_test "GET /notes/{id} for nonexistent returns 404" "404" "$HTTP_STATUS" "$HTTP_BODY" "not found"

# =============================================================================
# Test: List Notes (with data)
# =============================================================================

log_section "List Notes (With Data)"

http_request GET "${BASE_URL}/notes"
run_test "GET /notes returns 200 with notes" "200" "$HTTP_STATUS" "$HTTP_BODY" "notes"
run_test "List contains our created note" "200" "$HTTP_STATUS" "$HTTP_BODY" "$NOTE_ID"

# Test pagination parameters
http_request GET "${BASE_URL}/notes?limit=10&offset=0"
run_test "GET /notes with pagination returns 200" "200" "$HTTP_STATUS" "$HTTP_BODY" "notes"

# =============================================================================
# Test: Update Note
# =============================================================================

log_section "Update Note"

UPDATE_DATA='{"title":"Updated Title","content":"Updated content from curl test."}'
http_request PUT "${BASE_URL}/notes/${NOTE_ID}" "$UPDATE_DATA"
run_test "PUT /notes/{id} updates note (200)" "200" "$HTTP_STATUS" "$HTTP_BODY" "Updated Title"
run_test "Update response contains new content" "200" "$HTTP_STATUS" "$HTTP_BODY" "Updated content"

# Verify update persisted by reading again
http_request GET "${BASE_URL}/notes/${NOTE_ID}"
run_test "Updated note has new title" "200" "$HTTP_STATUS" "$HTTP_BODY" "Updated Title"
run_test "Updated note has new content" "200" "$HTTP_STATUS" "$HTTP_BODY" "Updated content"

# Test partial update (title only)
PARTIAL_UPDATE='{"title":"Partial Update Title"}'
http_request PUT "${BASE_URL}/notes/${NOTE_ID}" "$PARTIAL_UPDATE"
run_test "PUT /notes/{id} with partial data (200)" "200" "$HTTP_STATUS" "$HTTP_BODY" "Partial Update Title"

# Verify content was preserved
http_request GET "${BASE_URL}/notes/${NOTE_ID}"
run_test "Partial update preserved content" "200" "$HTTP_STATUS" "$HTTP_BODY" "Updated content"

# =============================================================================
# Test: Update Note - Not Found
# =============================================================================

log_section "Update Note - Not Found"

http_request PUT "${BASE_URL}/notes/nonexistent-id-12345" '{"title":"New Title"}'
run_test "PUT /notes/{id} for nonexistent returns 404" "404" "$HTTP_STATUS" "$HTTP_BODY" "not found"

# =============================================================================
# Test: Search Notes
# =============================================================================

log_section "Search Notes"

# Create additional notes for search testing
CREATE_DATA2='{"title":"Search Test Note","content":"This note contains the keyword findme123 for testing."}'
http_request POST "${BASE_URL}/notes" "$CREATE_DATA2"
run_test "Create second note for search (201)" "201" "$HTTP_STATUS" "$HTTP_BODY" "Search Test Note"
NOTE_ID2=$(json_field "$HTTP_BODY" "id")
log_info "Created second note with ID: $NOTE_ID2"

CREATE_DATA3='{"title":"Another Note","content":"This is completely different content with banana."}'
http_request POST "${BASE_URL}/notes" "$CREATE_DATA3"
run_test "Create third note for search (201)" "201" "$HTTP_STATUS" "$HTTP_BODY" "Another Note"
NOTE_ID3=$(json_field "$HTTP_BODY" "id")
log_info "Created third note with ID: $NOTE_ID3"

# Search for specific keyword
http_request POST "${BASE_URL}/notes/search" '{"query":"findme123"}'
run_test "POST /notes/search returns 200" "200" "$HTTP_STATUS" "$HTTP_BODY" "results"
run_test "Search finds note with keyword" "200" "$HTTP_STATUS" "$HTTP_BODY" "findme123"

# Search for title
http_request POST "${BASE_URL}/notes/search" '{"query":"Search Test"}'
run_test "Search by title works" "200" "$HTTP_STATUS" "$HTTP_BODY" "Search Test"

# Search for partial word
http_request POST "${BASE_URL}/notes/search" '{"query":"banana"}'
run_test "Search for banana returns result" "200" "$HTTP_STATUS" "$HTTP_BODY" "banana"

# Search with no results
http_request POST "${BASE_URL}/notes/search" '{"query":"zzzznonexistentwordzzz"}'
run_test "Search with no matches returns 200" "200" "$HTTP_STATUS" "$HTTP_BODY" "results"

# =============================================================================
# Test: Search Notes - Validation
# =============================================================================

log_section "Search Notes - Validation"

# Empty query
http_request POST "${BASE_URL}/notes/search" '{"query":""}'
run_test "POST /notes/search with empty query returns 400" "400" "$HTTP_STATUS" "$HTTP_BODY" "query is required"

# Missing query field
http_request POST "${BASE_URL}/notes/search" '{}'
run_test "POST /notes/search without query returns 400" "400" "$HTTP_STATUS" "$HTTP_BODY" "query is required"

# Invalid JSON
http_request POST "${BASE_URL}/notes/search" 'not json'
run_test "POST /notes/search with invalid JSON returns 400" "400" "$HTTP_STATUS" "$HTTP_BODY" "Invalid JSON"

# =============================================================================
# Test: Delete Note
# =============================================================================

log_section "Delete Note"

# Delete one of the test notes
http_request DELETE "${BASE_URL}/notes/${NOTE_ID3}"
run_test "DELETE /notes/{id} returns 204" "204" "$HTTP_STATUS"

# Verify note is deleted
http_request GET "${BASE_URL}/notes/${NOTE_ID3}"
run_test "Deleted note returns 404" "404" "$HTTP_STATUS" "$HTTP_BODY" "not found"

# Delete second test note
http_request DELETE "${BASE_URL}/notes/${NOTE_ID2}"
run_test "DELETE second note returns 204" "204" "$HTTP_STATUS"

# Delete original note
http_request DELETE "${BASE_URL}/notes/${NOTE_ID}"
run_test "DELETE original note returns 204" "204" "$HTTP_STATUS"

# Verify original note is deleted
http_request GET "${BASE_URL}/notes/${NOTE_ID}"
run_test "Original deleted note returns 404" "404" "$HTTP_STATUS" "$HTTP_BODY" "not found"

# =============================================================================
# Test: Delete Note - Not Found
# =============================================================================

log_section "Delete Note - Not Found"

http_request DELETE "${BASE_URL}/notes/nonexistent-id-12345"
run_test "DELETE /notes/{id} for nonexistent returns 404" "404" "$HTTP_STATUS" "$HTTP_BODY" "not found"

# =============================================================================
# Test: Delete Already Deleted (Idempotence check - should be 404)
# =============================================================================

log_section "Delete Already Deleted Note"

http_request DELETE "${BASE_URL}/notes/${NOTE_ID}"
run_test "DELETE already deleted note returns 404" "404" "$HTTP_STATUS" "$HTTP_BODY" "not found"

# =============================================================================
# Test: List Notes (verify cleanup)
# =============================================================================

log_section "List Notes (After Cleanup)"

http_request GET "${BASE_URL}/notes"
run_test "GET /notes after cleanup returns 200" "200" "$HTTP_STATUS" "$HTTP_BODY" "notes"

# Verify all test notes are deleted
if echo "$HTTP_BODY" | grep -q "Test Note\|Search Test\|Another Note"; then
    log_warn "Some test notes may still exist in the database"
fi

# =============================================================================
# Test Complete
# =============================================================================

log_section "Test Execution Complete"
log_info "All endpoint tests finished"
