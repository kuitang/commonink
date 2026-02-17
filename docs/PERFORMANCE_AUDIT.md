# Performance Audit (Pass 2)

Date: 2026-02-17

Scope reviewed: hot request paths in `cmd/server/main.go`, `internal/auth`, `internal/mcp`, `internal/notes`, `internal/db`, `internal/ratelimit`, `internal/web`.

## Findings (Highest Impact First)

1. High - MCP server rebuilt on every request
- `AuthenticatedMCPHandler.ServeHTTP` constructs `notes.NewService(...)` and `mcp.NewServer(...)` per request (`cmd/server/main.go`).
- Effect: repeated tool registration/handler setup adds avoidable allocation and latency overhead on MCP traffic.

2. Medium - Auth path re-reads key envelope metadata on each authenticated request
- Middleware executes `GetOrCreateUserDEK` and user DB open path each request (`internal/auth/middleware.go`).
- User DB handles are cached, but DEK lookup still hits shared DB path repeatedly.

3. Medium - Per-user DB connection cache is unbounded
- `internal/db/db.go` caches user DB handles in `userDBs` map with no TTL/eviction.
- Effect: memory/file-descriptor growth risk as active user cardinality increases.

4. Medium - Public publish flow performs synchronous render + object storage I/O in request path
- `HandleTogglePublish` -> `PublicNoteService.SetPublic` performs Markdown render and S3 put/delete inline (`internal/web/handlers.go`, `internal/notes/public.go`).
- Effect: user-facing latency tied directly to storage/network performance.

5. Medium - Rate limiter updates mutable state in read-lock fast path
- `RateLimiter.GetLimiter` mutates `entry.lastUsed` while holding RLock (`internal/ratelimit/limiter.go`).
- Effect: race-risk and inconsistent cleanup recency tracking under concurrency.

6. Low/Medium - Notes service uses `context.Background()` instead of request-scoped context
- `internal/notes/notes.go` methods create background contexts.
- Effect: request cancellation/timeouts are not propagated to DB operations.

## Positive Performance Characteristics
- SQLite WAL mode and tuned busy timeout for better mixed read/write behavior (`internal/db/db.go`).
- FTS5-backed search with triggers for incremental index sync (`internal/db/schema.go`, `internal/db/db.go`).
- In-memory per-user rate limiters with periodic cleanup (`internal/ratelimit/limiter.go`).

## Recommended Optimization Order
1. Reuse a per-user MCP server instance (or shared server with user-scoped service injection) instead of per-request rebuild.
2. Cache decrypted DEKs (short TTL) or cache key lookup metadata to reduce shared DB round-trips.
3. Introduce bounded/evicting user DB handle cache (LRU/TTL + max-open budget).
4. Move publish upload work to async job/outbox with user-visible status.
5. Fix limiter state mutation concurrency and add race-test coverage.
6. Thread request context into notes service methods.
