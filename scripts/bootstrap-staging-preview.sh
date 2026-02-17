#!/usr/bin/env bash
set -euo pipefail

# Bootstrap a named staging preview app with the required non-rotating secrets.
#
# Usage:
#   ./scripts/bootstrap-staging-preview.sh staging-1-commonink
#
# The script expects a local, non-committed staging secret file:
#   ./secrets.staging.sh

APP_NAME="${1:?Usage: ./scripts/bootstrap-staging-preview.sh <app-name>}"
FLY_ORG="commonink-staging"
STAGING_SECRETS_FILE="./secrets.staging.sh"

if [ ! -f "${STAGING_SECRETS_FILE}" ]; then
  echo "ERROR: ${STAGING_SECRETS_FILE} is required."
  echo "Create it from local secrets and staging OAuth client credentials."
  exit 1
fi

# shellcheck source=/dev/null
set -a
source "${STAGING_SECRETS_FILE}"
set +a

# Each preview app uses its own Tigris bucket so Fly can inject per-app S3 credentials.
BUCKET_NAME="${BUCKET_NAME:-${APP_NAME}-public}"

: "${GOOGLE_CLIENT_ID:?Set GOOGLE_CLIENT_ID in environment}"
: "${GOOGLE_CLIENT_SECRET:?Set GOOGLE_CLIENT_SECRET in environment}"
: "${RESEND_API_KEY:?Set RESEND_API_KEY in environment}"
: "${OPENAI_API_KEY:?Set OPENAI_API_KEY in environment}"
: "${MASTER_KEY:?Set MASTER_KEY in environment}"
: "${OAUTH_HMAC_SECRET:?Set OAUTH_HMAC_SECRET in environment}"
: "${OAUTH_SIGNING_KEY:?Set OAUTH_SIGNING_KEY in environment}"

if ! command -v flyctl >/dev/null 2>&1; then
  echo "ERROR: flyctl is required."
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required."
  exit 1
fi

echo "Preparing staging app: ${APP_NAME}"
echo "Target org: ${FLY_ORG}"

if ! flyctl apps list --json --org "${FLY_ORG}" | jq -e --arg app "${APP_NAME}" '.[] | select(.Name == $app)' >/dev/null; then
  flyctl apps create "${APP_NAME}" --org "${FLY_ORG}" --yes
  echo "Created ${APP_NAME}"
else
  echo "App ${APP_NAME} already exists"
fi

if flyctl storage status "${BUCKET_NAME}" --app "${APP_NAME}" >/dev/null 2>&1; then
  echo "Bucket ${BUCKET_NAME} already exists"
else
  flyctl storage create --app "${APP_NAME}" --name "${BUCKET_NAME}" --public --yes
  echo "Created bucket ${BUCKET_NAME}"
fi

secret_args=(
  "GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}" \
  "GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}" \
  "RESEND_API_KEY=${RESEND_API_KEY}" \
  "OPENAI_API_KEY=${OPENAI_API_KEY}" \
  "MASTER_KEY=${MASTER_KEY}" \
  "OAUTH_HMAC_SECRET=${OAUTH_HMAC_SECRET}" \
  "OAUTH_SIGNING_KEY=${OAUTH_SIGNING_KEY}" \
  "BUCKET_NAME=${BUCKET_NAME}" \
)

if [ -n "${S3_PUBLIC_URL:-}" ]; then
  secret_args+=("S3_PUBLIC_URL=${S3_PUBLIC_URL}")
fi

flyctl secrets set \
  "${secret_args[@]}" \
  --app "${APP_NAME}"

echo "Bootstrap complete for ${APP_NAME}."
