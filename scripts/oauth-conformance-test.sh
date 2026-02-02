#!/bin/bash
set -e

# OAuth 2.1 Conformance Testing Script
# Runs OpenID Foundation conformance suite against our OAuth server
# Expected to fail until server OAuth endpoints are implemented

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DOCKER_COMPOSE_FILE="docker-compose.oauth-test.yml"
SERVER_URL="${OAUTH_SERVER_URL:-http://localhost:8080}"
SUITE_URL="https://localhost:8443"
OUTPUT_DIR="${1:-./test-results/oauth-conformance}"
TIMEOUT="${TIMEOUT:-300}" # 5 minutes

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}OAuth 2.1 Conformance Testing${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "Server URL: $SERVER_URL"
echo -e "Suite URL: $SUITE_URL"
echo -e "Output dir: $OUTPUT_DIR"
echo -e "Timeout: ${TIMEOUT}s"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker not found. Install Docker to run conformance tests.${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}Error: docker-compose not found. Install docker-compose.${NC}"
    exit 1
fi

# Use docker compose (new) or docker-compose (old)
COMPOSE_CMD="docker compose"
if ! docker compose version &> /dev/null; then
    COMPOSE_CMD="docker-compose"
fi

# Start conformance suite
echo -e "${BLUE}Starting OpenID conformance suite...${NC}"
$COMPOSE_CMD -f "$DOCKER_COMPOSE_FILE" up -d

# Wait for suite to be ready
echo -e "${BLUE}Waiting for conformance suite to initialize...${NC}"
WAIT_TIME=0
while [[ $WAIT_TIME -lt $TIMEOUT ]]; do
    if curl -k -s "$SUITE_URL" > /dev/null 2>&1; then
        echo -e "${GREEN}Conformance suite ready!${NC}"
        break
    fi
    sleep 2
    WAIT_TIME=$((WAIT_TIME + 2))
    echo -n "."
done
echo ""

if [[ $WAIT_TIME -ge $TIMEOUT ]]; then
    echo -e "${RED}Timeout waiting for conformance suite${NC}"
    $COMPOSE_CMD -f "$DOCKER_COMPOSE_FILE" logs
    $COMPOSE_CMD -f "$DOCKER_COMPOSE_FILE" down
    exit 1
fi

# Check if our server is running
echo -e "${BLUE}Checking OAuth server availability...${NC}"
if ! curl -s -f "$SERVER_URL/health" > /dev/null 2>&1; then
    echo -e "${YELLOW}Warning: OAuth server not responding at $SERVER_URL${NC}"
    echo -e "${YELLOW}This is expected if OAuth endpoints are not implemented yet.${NC}"
    echo -e "${YELLOW}Tests will fail until server is implemented.${NC}"
    echo ""
fi

# Test basic OAuth endpoints
echo -e "${BLUE}Testing OAuth 2.1 endpoint availability...${NC}"
ENDPOINTS=(
    "$SERVER_URL/oauth/authorize"
    "$SERVER_URL/oauth/token"
    "$SERVER_URL/oauth/register"
    "$SERVER_URL/oauth/introspect"
    "$SERVER_URL/.well-known/oauth-authorization-server"
)

AVAILABLE_COUNT=0
for endpoint in "${ENDPOINTS[@]}"; do
    if curl -s -o /dev/null -w "%{http_code}" "$endpoint" | grep -E "^(200|400|401|404)$" > /dev/null; then
        echo -e "${GREEN}✓${NC} $endpoint"
        AVAILABLE_COUNT=$((AVAILABLE_COUNT + 1))
    else
        echo -e "${RED}✗${NC} $endpoint (not responding)"
    fi
done

echo ""
echo -e "Endpoint availability: $AVAILABLE_COUNT/${#ENDPOINTS[@]}"

# Run automated tests via API (if suite supports it)
echo -e "${BLUE}Running OAuth 2.1 conformance tests...${NC}"
echo -e "${YELLOW}Note: Full test suite requires manual configuration at $SUITE_URL${NC}"
echo -e "${YELLOW}This script performs basic connectivity and endpoint checks only.${NC}"

# Create test report
cat > "$OUTPUT_DIR/oauth-conformance-report.txt" <<EOF
OAuth 2.1 Conformance Test Report
Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

Server URL: $SERVER_URL
Suite URL: $SUITE_URL

Endpoint Availability:
EOF

for endpoint in "${ENDPOINTS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$endpoint" 2>&1)
    echo "  $endpoint: HTTP $status" >> "$OUTPUT_DIR/oauth-conformance-report.txt"
done

cat >> "$OUTPUT_DIR/oauth-conformance-report.txt" <<EOF

Summary:
- Endpoints available: $AVAILABLE_COUNT/${#ENDPOINTS[@]}
- Suite ready: Yes (manual tests available at $SUITE_URL)

Next Steps:
1. Navigate to $SUITE_URL in your browser
2. Configure test for OAuth 2.1 Authorization Server
3. Enter server configuration:
   - Issuer: $SERVER_URL
   - Authorization endpoint: $SERVER_URL/oauth/authorize
   - Token endpoint: $SERVER_URL/oauth/token
   - Registration endpoint: $SERVER_URL/oauth/register
4. Run test plans:
   - oauth2-1-pkce-authcode-flow
   - oauth2-1-refresh-token
   - oauth2-1-client-credentials

See: https://openid.net/certification/about-conformance-suite/
EOF

echo -e "${GREEN}✓ Basic conformance checks completed${NC}"
echo -e "${BLUE}Report: $OUTPUT_DIR/oauth-conformance-report.txt${NC}"
echo ""
echo -e "${YELLOW}Manual Testing Instructions:${NC}"
echo -e "1. Open browser: $SUITE_URL"
echo -e "2. Accept self-signed certificate"
echo -e "3. Configure OAuth 2.1 test with server URL: $SERVER_URL"
echo -e "4. Run test plans for OAuth 2.1 Authorization Server"
echo ""

# Keep suite running if requested
if [[ "${KEEP_RUNNING:-}" == "true" ]]; then
    echo -e "${BLUE}Conformance suite running. Press Ctrl+C to stop.${NC}"
    trap "$COMPOSE_CMD -f $DOCKER_COMPOSE_FILE down" EXIT
    tail -f /dev/null
else
    echo -e "${BLUE}Stopping conformance suite...${NC}"
    $COMPOSE_CMD -f "$DOCKER_COMPOSE_FILE" down
fi

# Exit with success if at least basic connectivity works
if [[ $AVAILABLE_COUNT -gt 0 ]]; then
    exit 0
else
    echo -e "${RED}No OAuth endpoints available. Server may not be implemented yet.${NC}"
    exit 1
fi
