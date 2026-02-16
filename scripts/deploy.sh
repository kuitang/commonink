#!/usr/bin/env bash
set -euo pipefail

# Fly.io deployment helper for commonink

# Check flyctl is installed
if ! command -v flyctl &> /dev/null; then
    echo "ERROR: flyctl is not installed."
    echo "Install it: curl -L https://fly.io/install.sh | sh"
    exit 1
fi

echo "=== commonink Fly.io Deploy ==="
echo ""
echo "Required secrets (set via 'fly secrets set KEY=VALUE'):"
echo "  MASTER_KEY           - Database encryption master key (64 hex chars)"
echo "  OAUTH_HMAC_SECRET    - OAuth HMAC secret (64+ hex chars)"
echo "  OAUTH_SIGNING_KEY    - OAuth Ed25519 signing key seed (64 hex chars)"
echo "  GOOGLE_CLIENT_ID     - Google OAuth client ID"
echo "  GOOGLE_CLIENT_SECRET - Google OAuth client secret"
echo "  RESEND_API_KEY       - Resend email API key"
echo ""
echo "Auto-set by Tigris (fly storage create):"
echo "  AWS_ACCESS_KEY_ID    - Tigris access key"
echo "  AWS_SECRET_ACCESS_KEY - Tigris secret key"
echo "  AWS_ENDPOINT_URL_S3  - Tigris endpoint URL"
echo "  BUCKET_NAME          - Tigris bucket name"
echo ""
echo "Optional:"
echo "  BASE_URL             - Public URL (default: https://common.ink)"
echo "  RESEND_FROM_EMAIL    - Sender email (default: noreply@common.ink)"
echo ""

# Check that required secrets are configured
MISSING=0
for SECRET in MASTER_KEY OAUTH_HMAC_SECRET OAUTH_SIGNING_KEY GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET RESEND_API_KEY; do
    if ! flyctl secrets list 2>/dev/null | grep -q "$SECRET"; then
        echo "WARNING: Secret $SECRET may not be set."
        MISSING=1
    fi
done

if [ "$MISSING" -eq 1 ]; then
    echo ""
    read -rp "Some secrets may be missing. Continue deployment? [y/N] " REPLY
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

echo ""
echo "Deploying..."
flyctl deploy
