#!/usr/bin/env bash
set -euo pipefail

APP_NAME="${APP_NAME:-commonink}"
CONFIG_FILE="${CONFIG_FILE:-fly.toml}"

# Check flyctl is installed
if ! command -v flyctl &> /dev/null; then
    echo "ERROR: flyctl is not installed."
    echo "Install it: curl -L https://fly.io/install.sh | sh"
    exit 1
fi

echo "=== commonink Fly.io Deploy ==="
echo "App: ${APP_NAME}"
echo "Config: ${CONFIG_FILE}"
echo ""
echo "Required secrets (set via 'fly secrets set KEY=VALUE'):"
echo "  MASTER_KEY           - Database encryption master key (64 hex chars)"
echo "  OAUTH_HMAC_SECRET    - OAuth HMAC secret (64+ hex chars)"
echo "  OAUTH_SIGNING_KEY    - OAuth Ed25519 signing key seed (64 hex chars)"
echo "  GOOGLE_CLIENT_ID     - Google OAuth client ID"
echo "  GOOGLE_CLIENT_SECRET - Google OAuth client secret"
echo "  RESEND_API_KEY       - Resend email API key"
echo "  SPRITE_TOKEN         - Fly Sprites API token"
echo ""
echo "Auto-set by Tigris (fly storage create):"
echo "  AWS_ACCESS_KEY_ID    - Tigris access key"
echo "  AWS_SECRET_ACCESS_KEY - Tigris secret key"
echo "  AWS_ENDPOINT_URL_S3  - Tigris endpoint URL"
echo "  BUCKET_NAME          - Tigris bucket name"
echo ""
echo "Optional:"
echo "  RESEND_FROM_EMAIL    - Sender email (default: noreply@common.ink)"
echo ""

# Check that required secrets are configured
required_secrets=(
  MASTER_KEY
  OAUTH_HMAC_SECRET
  OAUTH_SIGNING_KEY
  GOOGLE_CLIENT_ID
  GOOGLE_CLIENT_SECRET
  RESEND_API_KEY
  AWS_ENDPOINT_URL_S3
  AWS_REGION
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  BUCKET_NAME
  SPRITE_TOKEN
)
secret_list="$(flyctl secrets list --app "${APP_NAME}" 2>/dev/null || true)"
missing=()
for SECRET in "${required_secrets[@]}"; do
    if ! printf '%s\n' "${secret_list}" | grep -q "${SECRET}"; then
        echo "WARNING: Secret ${SECRET} may not be set."
        missing+=("${SECRET}")
    fi
done

if [ "${#missing[@]}" -gt 0 ]; then
    echo ""
    if [ "${CI:-}" = "true" ]; then
        echo "ERROR: Missing required secrets in CI: ${missing[*]}"
        exit 1
    fi
    read -rp "Some secrets may be missing. Continue deployment? [y/N] " REPLY
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

echo ""
echo "Deploying..."
flyctl deploy \
  --remote-only \
  --config "${CONFIG_FILE}" \
  --app "${APP_NAME}"
