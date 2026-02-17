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
- PR previews: `https://pr-<number>-<owner>-commonink.fly.dev` (configured in CI)
- Staging secrets are defined in `.env.staging` and are separate from production secrets.

Staging / preview storage uses a dedicated bucket:

- `BUCKET_NAME=commonink-staging-public`

To create staging storage in Fly/Tigris:

1. Configure Fly auth/session in your shell.
2. Ensure the staging app exists (`commonink-staging`) or that preview is allowed to create apps.
3. Create the dedicated bucket once:

```bash
flyctl storage create --app commonink-staging --name commonink-staging-public
```

4. Set `BUCKET_NAME=commonink-staging-public` in `.env.staging`.
