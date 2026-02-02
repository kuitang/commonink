#!/bin/bash
# Claude Code Conformance Test for Milestone 1
# Tests MCP endpoint with all 6 note tools
#
# Usage:
#   ./test.sh                    - Run automated tests (starts server automatically)
#   ./test.sh --manual           - Show manual test instructions only
#   TEST_PORT=8081 ./test.sh     - Use custom port (default: 18080)
#
# Requirements:
#   - Go 1.25+ via goenv
#   - jq for JSON parsing
#   - curl for HTTP requests

# Note: We don't use -e because individual test failures shouldn't stop the script
# We track pass/fail counts instead and exit with appropriate status at the end
set -uo pipefail

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Use TEST_PORT env var or default to 18080 (avoid common port conflicts)
TEST_PORT="${TEST_PORT:-18080}"
SERVER_URL="http://localhost:${TEST_PORT}"
MCP_ENDPOINT="${SERVER_URL}/mcp"
HEALTH_ENDPOINT="${SERVER_URL}/health"
SERVER_PID=""
TEST_PASSED=0
TEST_FAILED=0
CREATED_NOTE_ID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ==============================================================================
# Helper Functions
# ==============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TEST_PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TEST_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

cleanup() {
    if [[ -n "${SERVER_PID}" ]]; then
        log_info "Stopping server (PID: ${SERVER_PID})..."
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Initialize goenv for Go 1.25+
init_goenv() {
    export GOENV_ROOT="$HOME/.goenv"
    export PATH="$GOENV_ROOT/bin:$PATH"
    eval "$(goenv init -)"
}

# Build the server
build_server() {
    log_info "Building server..."
    cd "${PROJECT_ROOT}"
    init_goenv
    # CGO flags required for SQLCipher FTS5 support
    export CGO_ENABLED=1
    export CGO_CFLAGS="-DSQLITE_ENABLE_FTS5"
    export CGO_LDFLAGS="-lm"
    go build -o bin/server ./cmd/server
    log_info "Server built successfully"
}

# Check if port is available
check_port_available() {
    if curl -sf "http://localhost:${TEST_PORT}/health" > /dev/null 2>&1; then
        log_error "Port ${TEST_PORT} is already in use!"
        log_error "Set TEST_PORT env var to use a different port, e.g.: TEST_PORT=18081 ./test.sh"
        return 1
    fi
    return 0
}

# Start the server in background
start_server() {
    log_info "Starting server on port ${TEST_PORT}..."
    cd "${PROJECT_ROOT}"
    LISTEN_ADDR=":${TEST_PORT}" ./bin/server &
    SERVER_PID=$!
    log_info "Server started with PID: ${SERVER_PID}"
}

# Wait for server to be ready
wait_for_server() {
    log_info "Waiting for server to be ready..."
    local max_attempts=60
    local attempt=0

    # Give the server a moment to start
    sleep 1

    while [[ ${attempt} -lt ${max_attempts} ]]; do
        # Check if server process is still running
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            log_error "Server process (PID: ${SERVER_PID}) died unexpectedly"
            return 1
        fi

        if curl -sf "${HEALTH_ENDPOINT}" > /dev/null 2>&1; then
            log_info "Server is ready!"
            return 0
        fi
        ((attempt++))
        sleep 0.5
    done

    log_error "Server failed to start within ${max_attempts} attempts"
    return 1
}

# Global session ID for MCP communication
MCP_SESSION_ID=""

# Parse SSE response to extract JSON data
# SSE format: "event: message\ndata: {...}\n\n"
parse_sse_response() {
    local response="$1"
    # Extract just the JSON data line(s), removing "data: " prefix
    echo "${response}" | grep "^data:" | sed 's/^data: //' | head -1
}

# Make MCP request and return response (JSON only, SSE format parsed)
mcp_request() {
    local method="$1"
    local params="${2:-\{\}}"
    local request_id="${3:-1}"

    # Build the JSON payload manually to avoid jq escaping issues
    local payload="{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":${request_id}}"

    local raw_response
    if [[ -n "${MCP_SESSION_ID}" ]]; then
        raw_response=$(curl -sf -X POST "${MCP_ENDPOINT}" \
            -H "Content-Type: application/json" \
            -H "Accept: application/json, text/event-stream" \
            -H "Mcp-Session-Id: ${MCP_SESSION_ID}" \
            -d "${payload}")
    else
        raw_response=$(curl -sf -X POST "${MCP_ENDPOINT}" \
            -H "Content-Type: application/json" \
            -H "Accept: application/json, text/event-stream" \
            -d "${payload}")
    fi

    # Parse SSE response to get clean JSON
    parse_sse_response "${raw_response}"
}

# Initialize MCP session (required before any other commands)
mcp_initialize() {
    log_info "Initializing MCP session..."

    local init_params='{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"conformance-test","version":"1.0.0"}}'

    local response
    # Use -i to capture headers for session ID
    response=$(curl -si -X POST "${MCP_ENDPOINT}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":${init_params},\"id\":0}")

    # Extract session ID from response headers (if present)
    MCP_SESSION_ID=$(echo "${response}" | grep -i "Mcp-Session-Id:" | cut -d: -f2 | tr -d ' \r\n')

    # Check if initialization was successful by looking for result in the response body
    if echo "${response}" | grep -q '"result"'; then
        if [[ -n "${MCP_SESSION_ID}" ]]; then
            log_success "MCP session initialized (session ID: ${MCP_SESSION_ID:0:8}...)"
        else
            log_success "MCP session initialized (no session ID returned)"
        fi
        return 0
    else
        log_error "MCP initialization failed"
        echo "Response: ${response}"
        return 1
    fi
}

# Make tools/call request
mcp_tool_call() {
    local tool_name="$1"
    local arguments="${2:-\{\}}"
    local request_id="${3:-1}"

    # Build params JSON for tools/call
    local params="{\"name\":\"${tool_name}\",\"arguments\":${arguments}}"

    mcp_request "tools/call" "${params}" "${request_id}"
}

# ==============================================================================
# Test Functions
# ==============================================================================

test_health_endpoint() {
    log_info "Testing health endpoint..."

    local response
    if response=$(curl -sf "${HEALTH_ENDPOINT}"); then
        local status
        status=$(echo "${response}" | jq -r '.status')
        if [[ "${status}" == "healthy" ]]; then
            log_success "Health endpoint returns healthy status"
        else
            log_error "Health endpoint returned unexpected status: ${status}"
        fi
    else
        log_error "Health endpoint request failed"
    fi
}

test_tools_list() {
    log_info "Testing tools/list..."

    local response
    if response=$(mcp_request "tools/list" "{}" 1); then
        # Check if we got a valid JSON response
        if echo "${response}" | jq -e '.result.tools' > /dev/null 2>&1; then
            local tool_count
            tool_count=$(echo "${response}" | jq '.result.tools | length')

            if [[ "${tool_count}" -eq 6 ]]; then
                log_success "tools/list returns exactly 6 tools"

                # Verify all expected tools are present
                local expected_tools=("note_view" "note_create" "note_update" "note_search" "note_list" "note_delete")
                local all_present=true

                for tool in "${expected_tools[@]}"; do
                    if ! echo "${response}" | jq -e ".result.tools[] | select(.name == \"${tool}\")" > /dev/null 2>&1; then
                        log_error "Missing expected tool: ${tool}"
                        all_present=false
                    fi
                done

                if [[ "${all_present}" == true ]]; then
                    log_success "All 6 expected tools are present"
                fi
            else
                log_error "Expected 6 tools, got ${tool_count}"
            fi
        else
            log_error "tools/list response missing result.tools"
            echo "Response: ${response}"
        fi
    else
        log_error "tools/list request failed"
    fi
}

test_note_create() {
    log_info "Testing note_create tool..."

    local args='{"title": "Test Note from Conformance", "content": "This is test content created by the conformance test."}'
    local response

    if response=$(mcp_tool_call "note_create" "${args}" 2); then
        # Check for success
        if echo "${response}" | jq -e '.result.content[0].text' > /dev/null 2>&1; then
            local note_text
            note_text=$(echo "${response}" | jq -r '.result.content[0].text')

            # Parse the note JSON from the text content
            CREATED_NOTE_ID=$(echo "${note_text}" | jq -r '.id')

            if [[ -n "${CREATED_NOTE_ID}" && "${CREATED_NOTE_ID}" != "null" ]]; then
                log_success "note_create succeeded, note ID: ${CREATED_NOTE_ID}"
            else
                log_error "note_create did not return a note ID"
                echo "Response: ${note_text}"
            fi
        else
            log_error "note_create response malformed"
            echo "Response: ${response}"
        fi
    else
        log_error "note_create request failed"
    fi
}

test_note_view() {
    log_info "Testing note_view tool..."

    if [[ -z "${CREATED_NOTE_ID}" ]]; then
        log_warning "Skipping note_view test - no note created"
        return
    fi

    local args
    args=$(jq -n --arg id "${CREATED_NOTE_ID}" '{id: $id}')
    local response

    if response=$(mcp_tool_call "note_view" "${args}" 3); then
        if echo "${response}" | jq -e '.result.content[0].text' > /dev/null 2>&1; then
            local note_text
            note_text=$(echo "${response}" | jq -r '.result.content[0].text')
            local retrieved_id
            retrieved_id=$(echo "${note_text}" | jq -r '.id')

            if [[ "${retrieved_id}" == "${CREATED_NOTE_ID}" ]]; then
                log_success "note_view succeeded, retrieved note matches created ID"
            else
                log_error "note_view returned wrong note ID: ${retrieved_id}"
            fi
        else
            log_error "note_view response malformed"
            echo "Response: ${response}"
        fi
    else
        log_error "note_view request failed"
    fi
}

test_note_update() {
    log_info "Testing note_update tool..."

    if [[ -z "${CREATED_NOTE_ID}" ]]; then
        log_warning "Skipping note_update test - no note created"
        return
    fi

    local new_title="Updated Test Note"
    local new_content="This content was updated by the conformance test."
    local args
    args=$(jq -n --arg id "${CREATED_NOTE_ID}" --arg title "${new_title}" --arg content "${new_content}" \
        '{id: $id, title: $title, content: $content}')
    local response

    if response=$(mcp_tool_call "note_update" "${args}" 4); then
        if echo "${response}" | jq -e '.result.content[0].text' > /dev/null 2>&1; then
            local note_text
            note_text=$(echo "${response}" | jq -r '.result.content[0].text')
            local updated_title
            updated_title=$(echo "${note_text}" | jq -r '.title')

            if [[ "${updated_title}" == "${new_title}" ]]; then
                log_success "note_update succeeded, title updated correctly"
            else
                log_error "note_update did not update title: got '${updated_title}', expected '${new_title}'"
            fi
        else
            log_error "note_update response malformed"
            echo "Response: ${response}"
        fi
    else
        log_error "note_update request failed"
    fi
}

test_note_list() {
    log_info "Testing note_list tool..."

    local args='{"limit": 10, "offset": 0}'
    local response

    if response=$(mcp_tool_call "note_list" "${args}" 5); then
        if echo "${response}" | jq -e '.result.content[0].text' > /dev/null 2>&1; then
            local notes_text
            notes_text=$(echo "${response}" | jq -r '.result.content[0].text')

            # The response should be an array (or object with notes)
            if echo "${notes_text}" | jq -e 'type' > /dev/null 2>&1; then
                log_success "note_list succeeded, returned valid JSON"
            else
                log_error "note_list returned invalid JSON"
            fi
        else
            log_error "note_list response malformed"
            echo "Response: ${response}"
        fi
    else
        log_error "note_list request failed"
    fi
}

test_note_search() {
    log_info "Testing note_search tool..."

    local args='{"query": "conformance"}'
    local response

    if response=$(mcp_tool_call "note_search" "${args}" 6); then
        if echo "${response}" | jq -e '.result.content[0].text' > /dev/null 2>&1; then
            local search_text
            search_text=$(echo "${response}" | jq -r '.result.content[0].text')

            # The response should be valid JSON
            if echo "${search_text}" | jq -e 'type' > /dev/null 2>&1; then
                log_success "note_search succeeded, returned valid JSON"
            else
                log_error "note_search returned invalid JSON"
            fi
        else
            log_error "note_search response malformed"
            echo "Response: ${response}"
        fi
    else
        log_error "note_search request failed"
    fi
}

test_note_delete() {
    log_info "Testing note_delete tool..."

    if [[ -z "${CREATED_NOTE_ID}" ]]; then
        log_warning "Skipping note_delete test - no note created"
        return
    fi

    local args
    args=$(jq -n --arg id "${CREATED_NOTE_ID}" '{id: $id}')
    local response

    if response=$(mcp_tool_call "note_delete" "${args}" 7); then
        if echo "${response}" | jq -e '.result.content[0].text' > /dev/null 2>&1; then
            local delete_text
            delete_text=$(echo "${response}" | jq -r '.result.content[0].text')

            if [[ "${delete_text}" == *"deleted successfully"* ]]; then
                log_success "note_delete succeeded"
            else
                log_error "note_delete unexpected response: ${delete_text}"
            fi
        else
            log_error "note_delete response malformed"
            echo "Response: ${response}"
        fi
    else
        log_error "note_delete request failed"
    fi
}

test_note_view_deleted() {
    log_info "Testing note_view for deleted note (should fail)..."

    if [[ -z "${CREATED_NOTE_ID}" ]]; then
        log_warning "Skipping deleted note test - no note was created"
        return
    fi

    local args
    args=$(jq -n --arg id "${CREATED_NOTE_ID}" '{id: $id}')
    local response

    if response=$(mcp_tool_call "note_view" "${args}" 8); then
        if echo "${response}" | jq -e '.result.isError' > /dev/null 2>&1; then
            local is_error
            is_error=$(echo "${response}" | jq -r '.result.isError')

            if [[ "${is_error}" == "true" ]]; then
                log_success "note_view correctly returns error for deleted note"
            else
                log_error "note_view should return error for deleted note"
            fi
        else
            # Check if content contains error message
            local content
            content=$(echo "${response}" | jq -r '.result.content[0].text // ""')
            if [[ "${content}" == *"not found"* || "${content}" == *"failed"* ]]; then
                log_success "note_view correctly returns error for deleted note"
            else
                log_error "note_view should return error for deleted note, got: ${content}"
            fi
        fi
    else
        log_error "note_view request failed unexpectedly"
    fi
}

# ==============================================================================
# Manual Test Instructions
# ==============================================================================

show_manual_instructions() {
    cat << EOF
================================================================================
MANUAL CLAUDE CODE TESTING INSTRUCTIONS
================================================================================

To test the MCP server with Claude Code manually:

1. Start the server (using port ${TEST_PORT}):
   cd /home/kuitang/git/agent-notes
   export GOENV_ROOT="\$HOME/.goenv" && export PATH="\$GOENV_ROOT/bin:\$PATH" && eval "\$(goenv init -)"
   export CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5" CGO_LDFLAGS="-lm"
   go build -o bin/server ./cmd/server && LISTEN_ADDR=":${TEST_PORT}" ./bin/server

2. Configure Claude Code MCP:
   Copy the .mcp.json file to your Claude Code config directory:

   # For project-local config (recommended):
   cp tests/e2e/claude/.mcp.json .mcp.json

   # Or for user-global config:
   mkdir -p ~/.config/claude-code
   cp tests/e2e/claude/.mcp.json ~/.config/claude-code/.mcp.json

3. Start Claude Code in a new terminal (in the project directory):
   claude-code

4. Test each tool with prompts like:

   a) List notes:
      "Use the note_list tool to show me all notes"

   b) Create a note:
      "Use note_create to create a note titled 'Meeting Notes' with content 'Discussed project timeline'"

   c) View a note (use ID from create):
      "Use note_view to show me the note with ID <note-id>"

   d) Update a note:
      "Use note_update to change the title of note <note-id> to 'Updated Meeting Notes'"

   e) Search notes:
      "Use note_search to find notes containing 'meeting'"

   f) Delete a note:
      "Use note_delete to delete note <note-id>"

5. Expected behavior:
   - Claude Code should discover all 6 tools automatically
   - Each tool call should succeed and return JSON data
   - The notes should persist between operations

================================================================================
MCP CONFIG FORMAT (for reference)
================================================================================

The .mcp.json file uses Streamable HTTP transport (MCP Spec 2025-03-26):

{
  "mcpServers": {
    "agent-notes": {
      "type": "streamableHttp",
      "url": "http://localhost:${TEST_PORT}/mcp"
    }
  }
}

Note: Update the port in .mcp.json if using a custom TEST_PORT.

================================================================================
EOF
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    echo "================================================================================"
    echo "Claude Code Conformance Test - Milestone 1"
    echo "================================================================================"
    echo ""

    # Check for --manual flag
    if [[ "${1:-}" == "--manual" ]]; then
        show_manual_instructions
        exit 0
    fi

    # Check dependencies
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed. Install with: sudo apt-get install jq"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed. Install with: sudo apt-get install curl"
        exit 1
    fi

    # Check port availability first
    check_port_available

    # Build and start server
    build_server
    start_server
    wait_for_server

    echo ""
    echo "================================================================================"
    echo "Running MCP Conformance Tests"
    echo "================================================================================"
    echo ""

    # Run all tests
    test_health_endpoint
    echo ""

    # Initialize MCP session (required before tools/list or tools/call)
    mcp_initialize
    echo ""

    test_tools_list
    echo ""

    test_note_create
    echo ""

    test_note_view
    echo ""

    test_note_update
    echo ""

    test_note_list
    echo ""

    test_note_search
    echo ""

    test_note_delete
    echo ""

    test_note_view_deleted
    echo ""

    # Summary
    echo "================================================================================"
    echo "Test Summary"
    echo "================================================================================"
    echo ""
    echo -e "Passed: ${GREEN}${TEST_PASSED}${NC}"
    echo -e "Failed: ${RED}${TEST_FAILED}${NC}"
    echo ""

    if [[ ${TEST_FAILED} -gt 0 ]]; then
        log_error "Some tests failed!"
        exit 1
    else
        log_success "All tests passed!"
        exit 0
    fi
}

main "$@"
