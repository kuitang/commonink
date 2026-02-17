# Subagent Note 03 - Crypto Implementation and Initial Assessment

## Implemented crypto architecture
- Root secret: `MASTER_KEY` (32 bytes hex) from environment.
- KEK derivation: HKDF-SHA256 from master key with info string `user:{userID}:v{version}`.
- DEK: random 32-byte per-user key.
- DEK wrapping: AES-256-GCM with random 12-byte nonce; ciphertext stored in `sessions.user_keys.encrypted_dek`.
- Data-at-rest encryption: SQLCipher database key is per-user DEK.
- KEK rotation: `RotateUserKEK` rewraps DEK under incremented KEK version.

## Password hashing
- Argon2id with params currently: m=19456 KiB, t=2, p=1, output 32 bytes.
- Hash string embeds parameters and salt.

## API and OAuth secret handling
- API keys: random token, SHA-256 hash stored in per-user DB.
- OAuth client secrets (confidential clients): bcrypt hash stored.
- OAuth access and refresh tokens: plaintext tokens issued to clients; SHA-256 hashes stored server-side.

## Strengths
- Envelope encryption with per-user DEKs and KEK versioning implemented.
- AEAD (GCM) for DEK wrapping with integrity/authentication.
- SQLCipher used for per-user DB encryption.
- Password hashing uses Argon2id and parameterized storage.

## Gaps / risks to call out in CRYPTO.md
- HKDF derives KEK with nil salt; acceptable with high-entropy master key but should be justified/documented.
- No explicit key separation context between environments (dev/prod) beyond master key value itself.
- No formal KMS/HSM integration; key lifecycle depends on env secret management.
- Some security-critical error handling currently logs internals.
- Argon2 parameters reduced for memory constraints; tradeoff should be explicitly documented.
