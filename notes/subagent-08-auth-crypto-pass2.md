# Subagent Note 08 - Auth/Crypto Pass 2 (Delta)

## Auth interoperability delta
- Revalidated DCR allowlist includes ChatGPT production/review and Claude callback URIs (`internal/oauth/dcr.go`).
- Revalidated authorization endpoint enforces PKCE S256 and resource normalization checks (`internal/oauth/handlers.go`).
- Revalidated token endpoint supports JSON/form payloads and Basic auth fallback (`internal/oauth/handlers.go`).
- Confirmed runtime consent persistence gap remains due placeholder `auth.ConsentService` wiring.

## Crypto delta
- Revalidated envelope design implementation: HKDF-derived KEK, AES-GCM DEK wrapping, SQLCipher per-user DB keying (`internal/crypto`, `internal/db`).
- Revalidated Argon2id params in code are m=19456, t=2, p=1 (`internal/auth/user.go`).
- Revalidated token/API key hash-at-rest strategy (`internal/oauth/provider.go`, `internal/auth/apikey.go`).

## Consolidation output generated
- `docs/AUTH.md`
- `docs/CRYPTO.md`
