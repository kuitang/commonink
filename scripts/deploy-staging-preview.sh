#!/usr/bin/env bash
set -euo pipefail

FLY_ORG="commonink-staging"
SLOT_COUNT=3
APP_PREFIX="staging"
APP_SUFFIX="commonink"

PR_NUMBER="${PR_NUMBER:?Set PR_NUMBER (for GitHub Actions, use github.event.number)}"
: "${FLY_API_TOKEN:?Missing FLY_API_TOKEN_STAGING secret}"

if ! command -v flyctl >/dev/null 2>&1; then
  echo "ERROR: flyctl is required."
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required."
  exit 1
fi

SLOT=$(( (PR_NUMBER - 1) % SLOT_COUNT + 1 ))
APP_NAME="${APP_PREFIX}-${SLOT}-${APP_SUFFIX}"
BUCKET_NAME="${APP_NAME}-public"

if ! flyctl apps list --json --org "${FLY_ORG}" | jq -e --arg app "${APP_NAME}" '.[] | select(.Name == $app)' >/dev/null; then
  echo "Preview app '${APP_NAME}' does not exist in org '${FLY_ORG}'."
  echo "Run ./scripts/bootstrap-staging-preview.sh ${APP_NAME} first."
  exit 1
fi

secret_list="$(flyctl secrets list --app "${APP_NAME}")"
required_secrets=(
  GOOGLE_CLIENT_ID
  GOOGLE_CLIENT_SECRET
  RESEND_API_KEY
  MASTER_KEY
  OAUTH_HMAC_SECRET
  OAUTH_SIGNING_KEY
  AWS_ENDPOINT_URL_S3
  AWS_REGION
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  BUCKET_NAME
)

missing=()
for key in "${required_secrets[@]}"; do
  if ! printf '%s\n' "${secret_list}" | grep -q "${key}"; then
    missing+=("${key}")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  echo "Missing required staged secrets for ${APP_NAME}: ${missing[*]}"
  echo "Run ./scripts/bootstrap-staging-preview.sh ${APP_NAME} to provision secrets and Tigris bucket."
  exit 1
fi

flyctl secrets set \
  "BUCKET_NAME=${BUCKET_NAME}" \
  --app "${APP_NAME}"

flyctl deploy \
  --remote-only \
  --config fly.staging.toml \
  --app "${APP_NAME}"
