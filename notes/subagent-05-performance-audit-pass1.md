# Subagent Note 05 - Performance Audit Pass 1 (Working)

## Scope
- Hot request paths: auth middleware, DB open/cache behavior, notes CRUD, MCP tool calls.
- Startup/shutdown behavior.
- Potential contention points.

## Preliminary performance observations
1. Per-request DB open path in auth middleware
- Every authenticated request calls key manager and `db.OpenUserDBWithDEK` path.
- User DB connections are cached, so repeated opens become map lookups + existing handle reuse.
- Good pattern, but key/dek fetch still hits sessions DB in some paths.

2. Argon2 cost tradeoff
- Password hash params reduced to ~19 MiB memory to fit smaller Fly VMs.
- Improves availability under constrained memory, lowers brute-force resistance relative to heavier profiles.

3. FTS search implementation
- Uses FTS5 table and indexed triggers, query escapes user input to avoid parser failures.
- Search orders by rank and caps by `MaxLimit`.

4. Rate limiting
- In-memory per-user limiter map with periodic cleanup; low overhead and simple.
- Paid/free tier currently determined by stub (`getIsPaid` always false in `main.go`).

5. Public note publish path
- Synchronous render + S3 upload in request path for publish toggle.
- Could be user-visible latency spike and failure coupling to object storage availability.

## Next performance audit actions
- Run `make test` and spot long-running suites touching auth/crypto paths.
- Review logs for expensive code path instrumentation already present (`[ARGON2]`, register/login timings).
- Propose optimization options in final performance section without changing runtime behavior yet.
