#!/usr/bin/env bash
# Resolves a Fly Sprites API token.
# Priority: $SPRITE_TOKEN env > flyctl auth token exchange > error.
# Outputs only the token string on stdout (all diagnostics go to stderr).
set -euo pipefail

# Already set?
if [ -n "${SPRITE_TOKEN:-}" ]; then
  printf '%s' "$SPRITE_TOKEN"
  exit 0
fi

# Source secrets.sh if available (may set SPRITE_TOKEN).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -f "$SCRIPT_DIR/secrets.sh" ]; then
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/secrets.sh"
  if [ -n "${SPRITE_TOKEN:-}" ]; then
    printf '%s' "$SPRITE_TOKEN"
    exit 0
  fi
fi

# Locate flyctl.
flyctl_bin=""
if command -v flyctl >/dev/null 2>&1; then
  flyctl_bin="$(command -v flyctl)"
elif [ -x "$HOME/.fly/bin/flyctl" ]; then
  flyctl_bin="$HOME/.fly/bin/flyctl"
fi

if [ -z "$flyctl_bin" ]; then
  echo "ERROR: SPRITE_TOKEN not set and flyctl not found." >&2
  echo "Set SPRITE_TOKEN, add secrets.sh, or install flyctl." >&2
  exit 1
fi

# Get raw Fly auth token.
fly_raw_token="$("$flyctl_bin" auth token --json 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' || true)"
fly_raw_token="$(printf '%s' "$fly_raw_token" | tr -d '[:space:]')"

if [ -z "$fly_raw_token" ]; then
  echo "ERROR: failed to get Fly auth token from $flyctl_bin" >&2
  echo "Run: $flyctl_bin auth login" >&2
  exit 1
fi

# Exchange Fly token for Sprites API token.
sprite_org="${SPRITE_ORG_SLUG:-personal}"
sprite_invite="${SPRITE_INVITE_CODE:-}"

sprite_body='{"description":"commonink auto"}'
if [ -n "$sprite_invite" ]; then
  sprite_body="{\"description\":\"commonink auto\",\"invite_code\":\"$sprite_invite\"}"
fi

sprite_resp="$(mktemp -t sprite-token-resp-XXXXXX)"
trap 'rm -f "$sprite_resp"' EXIT

sprite_code="$(curl -sS -o "$sprite_resp" -w "%{http_code}" \
  -X POST "https://api.sprites.dev/v1/organizations/$sprite_org/tokens" \
  -H "Authorization: FlyV1 $fly_raw_token" \
  -H "Content-Type: application/json" \
  -d "$sprite_body" || true)"

if [ "$sprite_code" = "200" ] || [ "$sprite_code" = "201" ]; then
  token="$(python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); print(data.get("token",""))' "$sprite_resp" 2>/dev/null || true)"
  token="$(printf '%s' "$token" | tr -d '[:space:]')"
  if [ -n "$token" ]; then
    printf '%s' "$token"
    exit 0
  fi
fi

echo "ERROR: Sprites token exchange failed (HTTP $sprite_code)." >&2
if [ -f "$sprite_resp" ]; then
  cat "$sprite_resp" >&2
  echo >&2
fi
echo "Set SPRITE_TOKEN directly or check flyctl auth." >&2
exit 1
