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
echo "  GOOGLE_CLIENT_ID     - Google OAuth client ID"
echo "  GOOGLE_CLIENT_SECRET - Google OAuth client secret"
echo "  RESEND_API_KEY       - Resend email API key"
echo "  RESEND_FROM_EMAIL    - Sender email address for Resend"
echo "  S3_ENDPOINT          - S3/Tigris endpoint URL"
echo "  S3_ACCESS_KEY_ID     - S3/Tigris access key"
echo "  S3_SECRET_ACCESS_KEY - S3/Tigris secret key"
echo ""
echo "Optional secrets:"
echo "  OAUTH_HMAC_SECRET    - OAuth HMAC secret (64+ hex chars, auto-generated if missing)"
echo "  OAUTH_SIGNING_KEY    - OAuth Ed25519 signing key seed (64 hex chars, auto-generated if missing)"
echo "  BASE_URL             - Public URL (default: https://commonink.fly.dev)"
echo ""
echo "NOTE: In production, NO mock flags are used. All services must have real credentials."
echo ""

# Check that secrets are configured
MISSING=0
for SECRET in MASTER_KEY GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET RESEND_API_KEY RESEND_FROM_EMAIL S3_ENDPOINT S3_ACCESS_KEY_ID S3_SECRET_ACCESS_KEY; do
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
