# common.ink

Project documentation has been consolidated under `docs/`.

Primary docs:
- `docs/SPEC.md`
- `docs/ARCHITECTURE.md`
- `docs/AUTH.md`
- `docs/CRYPTO.md`
- `docs/SECURITY_AUDIT.md`
- `docs/PERFORMANCE_AUDIT.md`

Runtime informational pages served by the app are sourced from:
- `static/src/privacy.md`
- `static/src/tos.md`
- `static/src/about.md`
- `static/src/api-docs.md`

## Copyright and license

Project copyright is held by the project owner and contributors.

- Project status: **Source Available (not Open Source)**  
- Active license: **Elastic License 2.0** (`LICENSE`)

The repository is intentionally using a Source-Available license. See `LICENSE` for full terms.

Live production target: `https://common.ink`

## Deployment and URL behavior

This repo is configured to be hostname-agnostic for redirects and absolute URLs.

- Production domain: `https://common.ink`
- PR preview domains: `staging-1-commonink.fly.dev` to `staging-3-commonink.fly.dev` (assigned by PR number in CI)
- GitHub CI `test` and `deploy-preview` use `SPRITE_TOKEN_STAGING` (minted from Sprite org `commonink-staging`).
- GitHub CI `deploy-preview` also requires `FLY_API_TOKEN_STAGING`.
- GitHub CI `deploy-prod` requires `FLY_API_TOKEN_PROD` only for deployment.
- Preview apps are expected in Fly org `commonink-staging` (hardcoded in bootstrap + CI).

### Sprite token policy

- Staging token source: Sprite org `commonink-staging`.
- GitHub secret for non-prod CI paths: `SPRITE_TOKEN_STAGING`.
- CI test job runs Sprite-backed browser/API tests with `SPRITE_TOKEN_STAGING`.
- Preview deploy syncs Fly app secret `SPRITE_TOKEN` from `SPRITE_TOKEN_STAGING` on every deploy.
- Production token source: Sprite org `commonink-prod`.
- Production runtime token is Fly app secret `SPRITE_TOKEN` on app `commonink`.
- Do not store production Sprite token in GitHub Actions secrets.

Production token bootstrap (one-time, local):
```bash
SPRITE_TOKEN="$(SPRITE_ORG_SLUG=commonink-prod ./scripts/resolve-sprite-token.sh)" \
  && flyctl secrets set "SPRITE_TOKEN=${SPRITE_TOKEN}" --app commonink
```

Staging token bootstrap for CI (repeat when rotated):
```bash
SPRITE_TOKEN="$(SPRITE_ORG_SLUG=commonink-staging ./scripts/resolve-sprite-token.sh)" \
  && gh secret set SPRITE_TOKEN_STAGING --repo kuitang/commonink --body "${SPRITE_TOKEN}"
```

### Preview app secret bootstrap (recommended)

1. Create (or reuse) one-time staging secrets locally using the same format as `secrets.sh` and provision each slot app directly in Fly:

```bash
flyctl orgs create commonink-staging

cat > ./secrets.staging.sh <<'EOF'
#!/usr/bin/env bash
# secrets.staging.sh - Secret values only for commonink staging/preview
# This file follows the same format as secrets.sh (secrets only).
# DO NOT COMMIT THIS FILE (it is in .gitignore).
# Redirect URL and bucket name are injected dynamically per preview slot.
# Tigris AWS_* secrets are auto-injected by Fly per app bucket.

export GOOGLE_CLIENT_ID=""
export GOOGLE_CLIENT_SECRET=""
export RESEND_API_KEY=""
export MASTER_KEY=""
export OAUTH_HMAC_SECRET=""
export OAUTH_SIGNING_KEY=""
EOF
source ./secrets.staging.sh

./scripts/bootstrap-staging-preview.sh staging-1-commonink
./scripts/bootstrap-staging-preview.sh staging-2-commonink
./scripts/bootstrap-staging-preview.sh staging-3-commonink
```

2. Bootstrap creates a per-app Tigris bucket (`<app-name>-public`) and Fly injects:

- `AWS_ENDPOINT_URL_S3`
- `AWS_REGION`
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `BUCKET_NAME`

3. Local preview deploy test (same logic CI runs):
```bash
export FLY_API_TOKEN="<org-scoped-token>"
PR_NUMBER=123 bash ./scripts/deploy-staging-preview.sh
```

CI updates `BUCKET_NAME` per PR slot on each preview deploy.
