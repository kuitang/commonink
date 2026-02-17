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
- GitHub CI for previews should only require `FLY_API_TOKEN_STAGING`.

Staging / preview storage uses a dedicated bucket:

- `commonink-staging-public`

### Preview app secret bootstrap (recommended)

1. Create (or reuse) one-time staging secrets locally using the same format as `secrets.sh` and provision each slot app directly in Fly:

```bash
cat > ./secrets.staging.sh <<'EOF'
#!/usr/bin/env bash
# secrets.staging.sh - Secret values only for commonink staging/preview
# This file follows the same format as secrets.sh (secrets only).
# DO NOT COMMIT THIS FILE (it is in .gitignore).
# The identifiers/URLs are injected dynamically per preview slot.

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

2. Create staging storage (once) in Fly/Tigris and keep the bucket name as:
```bash
flyctl storage create --app commonink-staging --name commonink-staging-public
```

3. Keep bucket name explicit:

- `BUCKET_NAME=commonink-staging-public`

CI updates `BASE_URL`, `GOOGLE_REDIRECT_URL`, and `BUCKET_NAME` per PR slot on each preview deploy.
