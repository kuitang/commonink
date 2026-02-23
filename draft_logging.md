# Logging + Errors Plan (MCP-first)

## Goal
- Remove ad-hoc logging duplication (`[REQ]`, `MCP[debug] ...`, `[MCP][APPS] stage=...`, `appLogf(...)`) and replace with one consistent, always-on, JSON structured logging system.
- Make MCP request/response logging useful for debugging OpenAI MCP traffic without logging tool arguments or `_meta`.
- Standardize error shaping so MCP callers get consistent tool error responses, and HTTP endpoints map errors consistently.

## Decisions (locked in)
- Logger: Go `log/slog` JSON output.
- Log level: single level only (everything is `debug`).
- Timestamps: UTC.
- Every line: include `pkg` (package name) and request correlation fields when available.
- URL logging: log `path` only (never query string).
- `/mcp*` headers: dump all headers (but still redact obvious secrets; see below).
- `/mcp*` bodies:
- `tools/call`: never log raw body, never log `params.arguments` or `params._meta`. Log tool name and byte lengths only.
- Non-tool methods (`initialize`, `notifications/initialized`, etc): log the full JSON request body (bounded by the request-body hard limit).
- Special exception: if `/mcp` JSON parsing fails, log the raw body string (bounded) with an explicit in-code comment acknowledging the risk.
- Responses: bytes only for all endpoints (including `/mcp*`).

## Core logger (`internal/obs`)
Create `internal/obs` as the only logging API used by application code.

Requirements:
- `obs.Init()` configures a global `*slog.Logger` with JSON handler and UTC timestamps.
- `obs.Pkg("internal/mcp")` returns a logger with `pkg` attached.
- `obs.From(ctx)` returns a logger pre-bound with `request_id`, `conn_id`, and correlation fields if present.
- No code uses `log.Printf` directly once migrated.

## Request correlation (HTTP middleware)
Implement an HTTP middleware that runs for all routes.

Request ID:
- If inbound `X-Request-Id` exists: use it.
- Else if inbound `traceparent` exists: extract W3C `trace_id` and use that as `request_id`.
- Else: generate `request_id`.
- Always echo `X-Request-Id: <request_id>` in the response.

Correlation fields to extract and attach to context:
- W3C: `traceparent` to `trace_id`, also record `tracestate` (raw).
- Datadog: `x-datadog-trace-id`, `x-datadog-parent-id`, `x-datadog-sampling-priority`, `x-datadog-tags`.
- MCP: `mcp-protocol-version`, `mcp-session-id`.
- OpenAI headers: `x-openai-session`, `x-openai-subject`:
- Keep verbatim in logs (no hashing), per decision to keep today’s behavior and let log readers decide how to use them.

About `traceparent` vs `trace_id`:
- We do not “rename headers”. We derive a stable field (`trace_id`) from `traceparent` for searching and correlation.

## HTTP access logging
Replace existing request logs with a single structured event emitted by middleware.

Rules:
- Always log `method`, `path` (no query), `status`, `dur_ms`, `req_bytes`, `resp_bytes`, `request_id`, `conn_id`, `pkg`.
- Outside `/mcp*`: do not log request or response bodies. Log bytes only.
- For `/mcp*`: body logging rules are handled by MCP wrapper (below).

## Connection noise (ConnState / ConnContext)
Keep connection lifecycle logs because they help debug MCP connection churn.

Implementation:
- Use `http.Server.ConnContext` to attach `conn_id` to context derived from the `net.Conn`.
- Use `http.Server.ConnState` to log transitions (`new`, `active`, `idle`, `hijacked`, `closed`) as events.
- Connection logs have no headers and no HTTP path, so mark them as `unattributed=true` until the first request binds metadata.

## MCP transport wrapper (`internal/mcp/server.go`)
Make exactly one MCP transport wrapper responsible for:
- Enforcing request size limits (hard boundary).
- Logging request headers for `/mcp*`.
- Logging MCP request details (bytes + derived JSON-RPC summary).
- Preventing duplicated “panic/no-write guard” behavior (delete the other guard layer).

## MCP session ID (`Mcp-Session-Id`) management
We treat “new client” as “new MCP session”.

Detection:
- If the request has no `Mcp-Session-Id` header, it is a new (or broken) session.

Handshake:
- On JSON-RPC `initialize` with no `Mcp-Session-Id`: generate a new cryptographically-random session id (UUIDv4-style string) and return it in the response header `Mcp-Session-Id`.
- Client must echo `Mcp-Session-Id` on all subsequent `/mcp*` requests.

Validation:
- If `Mcp-Session-Id` is missing on non-`initialize` requests: return HTTP 400.
- If `Mcp-Session-Id` is present but unknown/expired (if we implement a session table): return HTTP 404 so the client re-initializes.

Notes:
- `Mcp-Session-Id` is an opaque ASCII string (not a timestamp). RFC3339Nano is for log timestamps; `Mcp-Session-Id` should be random.

### MCP request body hard limit (HTTP 413)
Pick a concrete byte limit based on “~200k LLM tokens”.

Recommendation:
- `MAX_MCP_BODY_BYTES = 1_000_000` (about 1MB).

Canonical Go mechanism:
- Use `net/http`’s `http.MaxBytesReader(w, r.Body, MAX_MCP_BODY_BYTES)`.
- If exceeded: return HTTP `413 Payload Too Large` and stop early.

### `/mcp*` header dump policy
Emit one event per request: `mcp_headers`.

Rules:
- Dump all headers (including unknown keys) using the *current style* (one log line with `key="value"` pairs).
- Do not maintain an allowlist; unknown headers must be kept so log readers can debug new vendors.
- Redact only auth-bearing headers:
- Always redact header values for: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`.
- Everything else is logged verbatim, including `x-openai-session` and `x-openai-subject`.

### `/mcp*` request logging policy
Emit one event per request: `mcp_req`.

Fields:
- `rpc_method`, `rpc_id` (if parseable), `req_bytes`, `resp_bytes`, `dur_ms`, plus correlation fields from context.

Body handling:
- If JSON parses and `rpc_method != tools/call`: log the full JSON request body string (bounded by max bytes).
- If JSON parses and `rpc_method == tools/call`: do not log body. Extract and log only:
- `tool_name`
- `args_bytes` (length of `params.arguments` encoding)
- `meta_bytes` (length of `params._meta` encoding)
- If JSON parsing fails: log the raw body string (bounded). Add a code comment: “SECURITY EXCEPTION: logging raw /mcp parse-failure body by explicit decision”.

Responses:
- Never log response body. Log bytes only.

## Tool wrapper (`internal/mcp/handlers.go`)
Create a single wrapper around each tool handler that standardizes:
- Argument parsing (shared helper) using `encoding/json` and typed structs.
- Validation errors become `invalid_argument` or `failed_precondition`.
- Panic recovery becomes `internal`.
- Logging: one `mcp_tool` event per tool call with `tool_name`, `dur_ms`, `ok`, `error_code` (if any), `req_bytes`, `resp_bytes`.

Then delete per-tool stage logs like `[MCP][APPS] stage=...` once wrapper exists.

## Error taxonomy (`internal/errs`)
Keep it minimal, but include permission.

Codes:
- `invalid_argument`
- `not_found`
- `failed_precondition`
- `permission_denied`
- `unavailable`
- `internal`

HTTP mapping (non-MCP endpoints):
- `invalid_argument` -> 400
- `permission_denied` -> 403
- `not_found` -> 404
- `failed_precondition` -> 409 (recommended for prior-hash mismatch; 412 is typically for `If-Match` style headers)
- `unavailable` -> 503
- `internal` -> 500

MCP mapping:
- Transport failures (too large, not JSON) -> real HTTP error (413, 400).
- Tool failures -> tool result error (`isError=true`) with a consistent JSON payload (no stack traces).

## Retries (internal only)
Default retry policy for known transient backend errors:
- 3 retries, total budget 5s, exponential backoff with jitter.
- Never surface “retry failed after N attempts” details to MCP callers. They just get the final shaped error.

Library:
- There is no stdlib retry helper. If you want a dependency, `cenkalti/backoff/v4` is the common choice.
- If avoiding deps, implement a small `retry.Do(ctx, policy, fn)` in `internal/retry`.

## Remove existing duplication (concrete deletions)
Delete or migrate these patterns:
- `internal/apps/service.go`: delete `appLogf(...)` and any boundary-style logs.
- `internal/mcp/handlers.go`: delete per-tool “stage” logs after wrapper exists.
- `cmd/server/main.go`: replace ad-hoc `[REQ]` logging with middleware event(s) from `internal/obs`.
- Ensure only one MCP panic/no-write guard exists (pick the MCP transport wrapper).

