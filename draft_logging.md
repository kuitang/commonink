# Logging + MCP Error Handling Refactor (Draft)

## What This Change Does
Unify logging and error surfacing across HTTP and MCP by introducing a single observability boundary (`internal/obs`) and a single error shaping layer (`internal/errs`). Remove ad-hoc per-tool/per-service logging and replace it with structured, request-scoped logs and consistent MCP tool error envelopes.

## Why (Current Problems)
- Redundant logging across multiple layers for the same event:
- Top-level HTTP access logs and connection logs in `cmd/server/main.go`.
- MCP transport logs in `internal/mcp/server.go`.
- Per-tool “stage=” logs in `internal/mcp/handlers.go`.
- Service logs in `internal/apps/service.go`.
- Unstructured `log.Printf` output forces bespoke tooling (`scripts/parse_mcp_debug_log.py`) to reconstruct tool-call flows.
- Sensitive-data risk: request/response body logging is currently “log everything then redact heuristically” (`internal/logutil/logutil.go`) and request bodies are read into memory in debug mode.
- Error handling is inconsistent and duplicated:
- Panics are recovered in multiple places (`cmd/server/main.go`, `internal/mcp/server.go`, `internal/mcp/handlers.go`).
- “No response written” guard exists in multiple places.
- MCP callers receive a mix of human strings, JSON text, and sometimes transport-level failures.
- Validation/parsing logic is repeated per tool handler (type assertions, array parsing, bounds checks), producing slop and inconsistent error messages.

## Goals
- Single logging mode: everything is “debug” (no levels).
- Bounded previews for everything (requests and responses), never unbounded reads.
- For MCP tool calls: redact `params.arguments` content; preserve tool name and total call length (bytes).
- Keep verbose connection lifecycle logs, but only for connections that handle `/mcp*`.
- Ignore health-check request noise (skip logging `/health` requests).
- One structured log line per HTTP request (access log) and one structured log line per MCP tool call (tool log).
- Request-scoped correlation keys: request ID, (optional) connection ID, auth mode (coarse), route/tool name.
- Single panic recovery policy per boundary (HTTP and MCP), with a consistent caller-visible failure shape.
- Consistent MCP tool error envelope with stable error codes (minimal set) and safe messages.
- Centralized redaction policy with explicit “never log” fields for MCP tools (especially app content and commands).
- Centralized argument parsing/validation helpers for MCP tools (consistent messages, consistent codes).

## Non-Goals
- Changing product semantics, routes, or MCP tool behavior beyond the error envelope and logging output.
- Comprehensive tracing/metrics system (can be added later; this draft focuses on logs + error shaping).
- Making logs depend on many verbosity levels.

## Proposed Architecture

### 1) `internal/obs` (Observability Boundary)
Responsibilities:
- Configure `slog` once (format, level, output destination).
- Context helpers:
- Attach/retrieve a request-scoped logger from `context.Context`.
- Attach request ID (and optionally connection ID) to the logger.
- Middleware:
- HTTP `Recover` middleware (panic -> 500) with one log event containing request_id and route.
- HTTP `AccessLog` middleware emitting method, path, status, duration, bytes written, request_id.
- MCP connection tracking: buffer connection state transitions until a request to `/mcp*` is observed, then flush and continue logging transitions for that connection.
- Redaction helpers:
- Central definition of sensitive header names and sensitive JSON field keys.
- Prefer allowlist logging of request metadata; do not log arbitrary maps.

Logging policy:
- One mode: emit everything as debug (no info/warn/error levels).
- Always bounded previews; never `io.ReadAll` on request bodies.
- MCP tool calls: log tool name and call length; redact tool arguments.
- Connection lifecycle logs: emit all noise for `/mcp*` connections; suppress for non-MCP connections.
- Request logs: suppress `/health` requests (and optionally other low-signal probes).

### 2) `internal/errs` (Typed Errors + Shaping)
Define a minimal error taxonomy for caller-facing errors:
- `invalid_argument`
- `not_found`
- `failed_precondition` (missing server config such as SPRITE_TOKEN)
- `unavailable` (timeouts, upstream failures)
- `internal`

Error object carries:
- `code` (stable, machine-readable)
- `message` (safe, user-facing)
- Optional safe fields (e.g., `app`, `path`, `limit_bytes`) that are safe to return to clients
- Wrapped cause (Go error) for server logs only

Shaping rules:
- Services return typed errors (or wrap with typed errors).
- Boundaries map typed errors into:
- HTTP: status code + JSON error for API endpoints (where applicable).
- MCP: tool result with `isError=true` and a consistent JSON text envelope.

### 3) MCP Boundary: Single Tool Wrapper + Single Transport Wrapper

Tool wrapper (inside `internal/mcp`):
- Standardizes:
- Argument parsing and validation (via shared helpers).
- Panic recovery (tool-level) into a typed `internal` error.
- Converting any `error` into a consistent tool error envelope (not transport-level failure).
- Structured tool logging:
- Always log: tool name, duration, ok/error, error code, request_id, request_bytes.
- Never log: `params.arguments` values.
- Never log: app file contents, commands, Authorization/Cookies, raw note bodies.

Transport wrapper (inside `internal/mcp/server.go` or at the route mount, but only one place):
- Handles:
- Request-level panic recovery.
- “No response written” guard.
- Bounded request/response previews using `io.LimitReader` (not unbounded `ReadAll`).
- One request log event for MCP transport (method/path/status/duration/request_id/request_bytes/response_bytes).
- For tool calls: parse the JSON-RPC envelope and log a sanitized summary (tool name + argument byte length), not the arguments themselves.

Eliminate duplication:
- Pick exactly one layer to do panic recovery and “no write” guarding for MCP (either the MCP transport wrapper or the route wrapper) and remove the others.
- Remove per-tool “stage=” logs from `internal/mcp/handlers.go` once the wrapper emits start/end and the error envelope is reliable.

## MCP Error Envelope (Caller-Facing)
For any tool call, return a single text payload that can be parsed by automation and read by humans:
- Success:
- Fields: `ok=true`, `result=<tool-specific>`, `request_id`.
- Failure:
- Fields: `ok=false`, `error.code`, `error.message`, `request_id`.

Rules:
- Expected failures (validation, not-found, missing config, upstream timeout) return `isError=true` and do not rely on transport-level failures.
- Truly catastrophic handler failures still return an `internal` tool error envelope when possible (panic recovery).

## MCP Argument Parsing/Validation Deduplication
Introduce shared helpers for tool argument parsing:
- Strongly typed getters: string/int/bool/array/object.
- Built-in size and item count limits (reuse current limits; centralize enforcement).
- Consistent error messages and `invalid_argument` codes.

Outcome:
- Tool handlers become “parse -> call service -> return tool result”, with minimal repetition.

## Sensitive Data Policy (Hard Rules)
- Never log:
- `Authorization` header, cookies, tokens, secrets, passwords.
- MCP `params.arguments` values (log tool name + total call length instead).
- `app_write` file contents (implicitly covered by the MCP arguments rule).
- Full `app_bash` command content (implicitly covered by the MCP arguments rule).
- Raw note bodies by default.
- All logging must be bounded previews and must apply a strict denylist that errs on the side of omission.

## Migration Plan (Incremental, Low-Risk)
1. Add `internal/errs` and convert a small set of paths to typed errors (start with MCP apps tools).
2. Add `internal/obs`:
- `slog` initialization and HTTP middleware.
- Request ID generation and propagation through context.
3. Implement MCP tool wrapper:
- Centralize parsing + error envelope + tool logging.
- Remove `[MCP][APPS] ... stage=...` logs from `internal/mcp/handlers.go`.
4. Consolidate MCP panic/no-write guard:
- Keep only one place (transport wrapper OR route wrapper).
- Remove the duplicate guards to prevent double-logging and double-writing.
5. Reduce/retune service logs:
- Move `internal/apps/service.go` logs behind debug level or keep only high-signal events.
- Prefer a single “operation completed” log with key fields rather than many step logs.
6. Update or retire `scripts/parse_mcp_debug_log.py`:
- If structured logs are JSON, parsing becomes simpler and less brittle.
7. Clean up test scaffolding duplication:
- Replace per-folder `helpers_alias_test.go` copies with a shared helper package.

## Validation Plan
- `make test` for quick feedback on non-conformance packages.
- `make test-full` to ensure conformance + browser tests still pass and logs are not leaking sensitive fields in debug runs.
- Add targeted tests for:
- MCP tool error envelope shape (both success and failure).
- Redaction correctness for headers and known sensitive fields.
- No-write guard behavior (only once, no double-writes).

## Success Criteria
- A single MCP tool call produces:
- Exactly one “tool completed” log event (single debug mode), but no payload leaks.
- Logs include tool name + request byte length for tool calls.
- Caller receives a consistent parseable error envelope for all expected failures.
- No more per-tool “stage=” logs or duplicated panic/no-write logs.

## Open Questions
- Log format: JSON logs for machines vs text logs for local dev (or dual-mode).
- Should logs be gated solely by `DEBUG` (single switch), or always-on in early dev.
- Request ID propagation:
- Return request_id in MCP tool envelopes for correlation.
- Optionally accept an inbound request id header for proxying.
- Where to keep the MCP transport wrapper (route layer vs `internal/mcp/server.go`) to minimize duplication while keeping ownership clear.
- Whether to keep connection ID logging at all, and if so, which lifecycle events are worth the noise.
