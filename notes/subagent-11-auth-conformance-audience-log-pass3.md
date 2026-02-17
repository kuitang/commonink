# Subagent Note 11 - AUTH Conformance + Audience/History Pass 3

## Inputs reviewed
- `docs/*.md`
- `notes/subagent*md`
- `tests/e2e/oauth_auth_test.go`
- `tests/e2e/testutil/server.go`
- `tests/e2e/openai/conformance_test.go`
- `tests/e2e/claude/conformance_test.go`
- `internal/oauth/provider.go`
- `internal/auth/oauth_middleware.go`
- `cmd/server/main.go`
- `server.log`
- Git history for OAuth/auth files (`cfcdbf9`, `971b4a3`, `48f9092`, `e30f93d`)

## Findings
- OAuth conformance testing is implemented in code (ChatGPT + Claude modes) in `tests/e2e/oauth_auth_test.go`.
- A standards-client path exists via `golang.org/x/oauth2` in `tests/e2e/testutil/server.go`.
- Runtime bearer verification path still does not enforce explicit `aud` checks (`cmd/server/main.go` -> `internal/auth/middleware.go` -> `internal/oauth/provider.go`).
- A strict audience checker exists in `internal/auth/oauth_middleware.go`, but it is not wired in production server startup.
- Git history shows no commit that explicitly removed audience checks for Claude compatibility.
- `server.log` shows successful ChatGPT and Claude MCP traffic after OAuth token issuance and no `invalid audience` log events.

## Actions taken
- Updated `docs/AUTH.md` with:
  - Conformance test coverage details and file references
  - Audience-validation runtime behavior and history analysis
  - Server log evidence summary
- Deleted legacy `spec.md` per user request.
