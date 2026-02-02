# Milestone 1: Unauthenticated CRUD Implementation Plan

**Goal**: Implement all MCP tools and HTTP API without authentication, test with Claude Code and OpenAI

---

## Implementation DAG

```
[Research Complete] ✓
    ├─> [Database Layer] ──┐
    ├─> [OpenAI SDK Setup] │
    └─> [MCP SDK Setup]    │
                           │
    [Database Layer] ──────┴──> [Notes CRUD Logic]
                                     │
                ┌────────────────────┼────────────────────┐
                │                    │                    │
          [MCP Server]          [HTTP API]        [Property Tests]
                │                    │                    │
                └────────────────────┴────────────────────┘
                                     │
                              [Master Test Script]
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
          [Claude Code Test]  [OpenAI Test]  [HTTP curl Test]
                    │                │                │
                    └────────────────┴────────────────┘
                                     │
                                 [Verify]
                                     │
                                 [Commit]
```

---

## Tasks (Topologically Sorted for Parallel Execution)

### Layer 0 (No Dependencies) - DONE ✓
- [x] Research MCP server implementation
- [x] Research OpenAI function calling

### Layer 1 (Parallel)
1. **Database Layer** (`internal/db/`)
   - `db.go` - Database connection manager
   - `schema.go` - SQL schema definitions
   - Hardcode test user: `user_id = "test-user-001"`
   - Create sessions.db (minimal)
   - Create test-user-001.db (encrypted with SQLCipher)

2. **Add OpenAI SDK**
   - `go get github.com/openai/openai-go`
   - Update go.mod

### Layer 2 (Depends on Layer 1)
3. **Notes CRUD Logic** (`internal/notes/`)
   - `notes.go` - Core CRUD operations
   - `types.go` - Note struct definitions
   - All operations use hardcoded `user_id = "test-user-001"`

### Layer 3 (Depends on Layer 2)
4. **MCP Server** (`internal/mcp/`)
   - `server.go` - MCP server with SSE transport
   - `tools.go` - All 6 MCP tools
   - `handlers.go` - Tool handlers calling notes CRUD

5. **HTTP API** (`internal/api/`)
   - `handlers.go` - HTTP handlers
   - Routes: GET /notes, GET /notes/{id}, PUT /notes/{id}, POST /notes, DELETE /notes/{id}, POST /notes/search

6. **Property Tests** (`tests/property/`)
   - `notes_rapid_test.go` - Property-based tests with rapid
   - `notes_fuzz_test.go` - Native Go fuzzing

### Layer 4 (Depends on Layer 3)
7. **Update main.go**
   - Initialize database
   - Start MCP server on /mcp
   - Start HTTP API on other routes
   - Health check endpoint

### Layer 5 (Parallel, depends on Layer 4)
8. **Claude Code Conformance Test** (`tests/e2e/claude/`)
   - `.mcp.json` - Local MCP configuration
   - `test.sh` - Shell script to drive Claude Code
   - Test all 6 MCP tools

9. **OpenAI Conformance Test** (`tests/e2e/openai/`)
   - `conformance_test.go` - Go test using OpenAI SDK
   - Execute all 6 functions against local server
   - Property tests with rapid

10. **HTTP curl Test** (`tests/e2e/curl/`)
    - `test.sh` - Shell script with curl commands
    - Test all HTTP endpoints

### Layer 6 (Depends on Layer 5)
11. **Master Test Script** (`scripts/milestone1-test.sh`)
    - Start server
    - Run MCP conformance (official suite)
    - Run Claude Code test
    - Run OpenAI test
    - Run HTTP curl test
    - Verify all tests pass
    - Stop server

---

## Simplified Decisions for Milestone 1

**Authentication**: SKIP - Hardcode `user_id = "test-user-001"`

**Encryption**: KEEP - Still use SQLCipher with a hardcoded DEK for testing

**Database Structure**:
- sessions.db (minimal, just structure)
- test-user-001.db (contains all notes)

**No Rate Limiting**: SKIP for now

**No Payments**: SKIP for now

**No OAuth Provider**: SKIP for now

---

## Expected File Structure

```
/home/kuitang/git/agent-notes/
├── internal/
│   ├── db/
│   │   ├── db.go           # Database connection manager
│   │   └── schema.go       # SQL schemas
│   ├── notes/
│   │   ├── notes.go        # CRUD operations
│   │   └── types.go        # Note types
│   ├── mcp/
│   │   ├── server.go       # MCP server
│   │   ├── tools.go        # Tool definitions
│   │   └── handlers.go     # Tool handlers
│   └── api/
│       └── handlers.go     # HTTP handlers
├── tests/
│   ├── property/
│   │   ├── notes_rapid_test.go
│   │   └── notes_fuzz_test.go
│   └── e2e/
│       ├── claude/
│       │   ├── .mcp.json
│       │   └── test.sh
│       ├── openai/
│       │   └── conformance_test.go
│       └── curl/
│           └── test.sh
├── scripts/
│   └── milestone1-test.sh  # Master orchestrator
├── cmd/server/
│   └── main.go             # Updated main
└── go.mod                  # Add openai-go
```

---

## Testing Strategy

**Unit Tests**: Each package (db, notes, mcp, api)
**Property Tests**: rapid + fuzzing for notes CRUD
**Integration Tests**: MCP conformance suite
**E2E Tests**: Claude Code + OpenAI + HTTP curl
**Orchestration**: Master script runs everything

---

## Success Criteria

✅ All 6 MCP tools working
✅ MCP conformance tests pass
✅ Claude Code can create/read/update/delete notes
✅ OpenAI function calling can create/read/update/delete notes
✅ HTTP API can create/read/update/delete notes via curl
✅ Property tests pass (no panics, consistent state)
✅ Database persists data correctly
✅ Encryption works (SQLCipher)

---

## Time Estimate

- Database layer: 30 min
- Notes CRUD: 30 min
- MCP server: 1 hour
- HTTP API: 30 min
- Property tests: 30 min
- Conformance tests: 1 hour
- Integration & debugging: 1 hour

**Total**: ~5 hours

---

## Next Steps

Execute tasks in parallel following the DAG:
1. Start Layer 1 tasks in parallel
2. Wait for Layer 1 completion
3. Start Layer 2 tasks
4. Continue through layers
5. Run master test script
6. Fix any issues
7. Commit

