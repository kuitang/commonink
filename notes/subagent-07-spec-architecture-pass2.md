# Subagent Note 07 - Spec/Architecture Pass 2 (Delta)

## Delta from subagent-01
- Confirmed route truth from `cmd/server/main.go` and `internal/web/handlers.go` is narrower than legacy spec docs.
- Confirmed top-level MCP deployment shape is POST-only (`GET`/`DELETE` intentionally return 405), despite internal Streamable handler support.
- Confirmed public note rendering mismatch remains in runtime (`renderPublicNote` placeholder payload).
- Confirmed per-user DB encryption path is active via `auth.Middleware` + `crypto.KeyManager` + `db.OpenUserDBWithDEK`.

## Consolidation output generated
- `docs/SPEC.md`
- `docs/ARCHITECTURE.md`
