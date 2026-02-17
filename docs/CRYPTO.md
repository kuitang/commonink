# common.ink CRYPTO

## Scope
This document describes the cryptographic design implemented in code, evaluates it against current best practice, and highlights prioritized risks and improvements.

Code references:
- `internal/crypto/crypto.go`
- `internal/crypto/keymanager.go`
- `internal/auth/user.go`
- `internal/oauth/provider.go`
- `internal/auth/apikey.go`
- `internal/db/db.go`
- `internal/db/schema.go`

## Implemented Crypto Design

## 1) Envelope Encryption for User Databases
- Root key: `MASTER_KEY` (32-byte secret from environment).
- Per-user KEK derivation: HKDF-SHA256 with info string `user:{userID}:v{version}`.
- Per-user DEK: random 32-byte key.
- DEK wrapping: AES-256-GCM with random 12-byte nonce.
- Data encryption at rest: SQLCipher key set to DEK for `{user_id}.db`.
- Key rotation: `RotateUserKEK` re-wraps DEK under incremented KEK version.

Result: Compromise of one user DEK does not directly expose other users' DEKs.

## 2) Password Hashing
- Algorithm: Argon2id.
- Current params in code: `m=19456 KiB`, `t=2`, `p=1`, output `32 bytes`.
- Hash string stores algorithm/version/parameters/salt/hash for forward compatibility.

## 3) Token and Secret Storage
- API keys: random secret shown once; SHA-256 hash stored.
- OAuth access/refresh tokens: plaintext issued to client, SHA-256 hash stored server-side.
- OAuth client secrets (confidential clients): bcrypt-hashed.
- Session IDs and magic/reset tokens: random secrets; magic/reset tokens stored hashed.

## Assessment vs State of the Art

### Strengths
- Uses modern primitives: HKDF, AES-GCM, Argon2id, Ed25519 JWT signing.
- Per-user DEKs with envelope encryption and versioned KEKs are a solid architecture.
- SQLCipher gives file-level encryption for user data at rest.
- Secret material is generally not persisted in plaintext (API keys, OAuth tokens, magic tokens).

### Gaps and Risks

#### A. Shared bootstrap DB is unencrypted (medium)
`sessions.db` stores high-value metadata (sessions, OAuth client/token hashes, user key envelopes, short URLs) without SQLCipher.

Impact: host-level disk disclosure exposes session and auth metadata, even if user note payload DBs remain encrypted.

#### B. HKDF salt is nil (low/medium)
HKDF with nil salt is acceptable when input keying material is uniformly random and high entropy, but explicit salt/domain strategy is preferable for stronger key-separation hygiene across deployments.

Impact: mostly hardening gap, not an immediate break with strong `MASTER_KEY`.

#### C. No KMS/HSM integration for master key lifecycle (medium)
`MASTER_KEY` is process/env managed. There is no hardware-backed key custody, audited key usage boundary, or automated rotation workflow.

Impact: operational risk concentrates in environment secret handling.

#### D. Argon2id work factor tuned for small instances (tradeoff)
Current Argon2 settings intentionally target constrained runtime memory. This is aligned with OWASP minimum-compatible guidance but lower than aggressively hardened profiles.

Impact: acceptable for availability, but lower offline cracking cost than higher-memory profiles.

#### E. No cryptographic binding/AAD for DEK envelope context (low)
DEK wrapping currently does not pass additional authenticated data (AAD) such as `(userID, version)` into GCM sealing.

Impact: low with current schema and keyed lookup model, but AAD would strengthen misuse resistance.

## Risk Summary
- Overall cryptographic posture: **good foundational design with operational hardening gaps**.
- Highest practical improvements:
1. Encrypt or otherwise harden `sessions.db` at rest and backup handling.
2. Move master-key custody to KMS/HSM-backed flow.
3. Formalize key-rotation and environment separation policy.

## Recommended Improvements (Priority Order)
1. Encrypt `sessions.db` with SQLCipher or equivalent host-level disk controls + strict backup encryption.
2. Introduce managed KMS/HSM-based envelope root (or at minimum split-key + rotation playbook).
3. Add explicit HKDF salt/context policy (environment- and tenant-scoped domain separation).
4. Add AAD when wrapping DEKs (bind ciphertext to `userID` and `kek_version`).
5. Increase Argon2 memory/time where deployment budget allows and rehash on login policy.

## References
[1] RFC 5869 (HKDF): https://datatracker.ietf.org/doc/html/rfc5869

[2] NIST SP 800-38D (GCM): https://csrc.nist.gov/pubs/sp/800/38/d/final

[3] RFC 9106 (Argon2): https://datatracker.ietf.org/doc/html/rfc9106

[4] OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

[5] SQLCipher documentation: https://www.zetetic.net/sqlcipher/

[6] RFC 7519 (JWT): https://datatracker.ietf.org/doc/html/rfc7519

[7] RFC 8037 (EdDSA/OKP for JOSE): https://datatracker.ietf.org/doc/html/rfc8037
