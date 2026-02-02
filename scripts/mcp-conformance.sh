#!/bin/bash
set -e

# MCP Conformance Test Script
# Tests MCP protocol implementation against official conformance suite

MCP_URL="${MCP_URL:-http://localhost:8080/mcp}"
OUTPUT_DIR="${OUTPUT_DIR:-./test-results/mcp-conformance}"

echo "Running MCP conformance tests..."
echo "Target URL: $MCP_URL"
echo ""

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Run conformance tests
npx @modelcontextprotocol/conformance server \
    --url "$MCP_URL" \
    --output-dir "$OUTPUT_DIR" \
    || {
        echo "MCP conformance tests failed"
        exit 1
    }

echo "MCP conformance tests passed"
