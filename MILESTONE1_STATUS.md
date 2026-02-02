# Milestone 1 Status - Unauthenticated CRUD

**Last Updated**: 2026-02-02
**Current Progress**: Database Layer Complete, Ready for Notes CRUD

---

## ✅ Completed

### 1. Research Phase (DONE)
- ✅ MCP server implementation patterns researched
  - Document: `notes/mcp-implementation-research.md`
  - Comprehensive guide on MCP Go SDK usage
  - Claude Code configuration (.mcp.json format)

- ✅ OpenAI Responses API with MCP integration researched
  - OpenAI Responses API uses `type: "mcp"` to connect to MCP servers
  - No manual function definitions needed!
  - OpenAI auto-discovers tools from MCP server
  - Requires ngrok to expose local server publicly
  - SDK: `github.com/openai/openai-go/v3` (installed)

### 2. Database Layer (DONE - Committed: d31fa80)
- ✅ `internal/db/db.go` - Complete connection manager
- ✅ `internal/db/schema.go` - All SQL schemas from spec.md
- ✅ Full SQLCipher encryption support
- ✅ FTS5 full-text search with automatic triggers
- ✅ 19 tests passing (100% core functionality coverage)
- ✅ Makefile with proper CGO flags
- ✅ Hardcoded test user: `test-user-001`
- ✅ Hardcoded DEK for Milestone 1

### 3. Dependencies (DONE)
- ✅ github.com/openai/openai-go v1.12.0 (old version, function calling)
- ✅ github.com/openai/openai-go/v3 v3.17.0 (NEW - Responses API with MCP)

---

## 🚧 In Progress / Next Steps

Following the DAG from MILESTONE1_PLAN.md:

### Layer 2: Notes CRUD Logic
**Files to create**:
```
internal/notes/
├── types.go     # Note struct, NoteListResult, etc.
├── notes.go     # CRUD operations (Create, Read, Update, Delete, List, Search)
└── notes_test.go
```

**Implementation details**:
- Hardcode `userID = "test-user-001"`
- Use `internal/db` package for database access
- FTS5 search using the triggers we set up
- Return proper errors
- All operations tested

### Layer 3: Servers & Tests (Parallel)

**3a. MCP Server** (`internal/mcp/`)
```
internal/mcp/
├── server.go    # MCP server with Streamable HTTP transport (MCP Spec 2025-03-26)
├── tools.go     # 6 MCP tool definitions
└── handlers.go  # Tool handlers calling internal/notes
```

**6 MCP Tools**:
1. note_view(id) - Read note
2. note_create(title, content) - Create note
3. note_update(id, title?, content?) - Update note
4. note_search(query) - FTS5 search
5. note_list(limit?, offset?) - List notes
6. note_delete(id) - Delete note

**3b. HTTP API** (`internal/api/`)
```
internal/api/
└── handlers.go  # HTTP handlers for notes
```

**HTTP Endpoints**:
- GET /notes - List all notes
- GET /notes/{id} - Get one note
- POST /notes - Create note
- PUT /notes/{id} - Update note
- DELETE /notes/{id} - Delete note
- POST /notes/search?q=query - Search notes

**3c. Property Tests** (`tests/property/`)
```
tests/property/
├── notes_rapid_test.go  # rapid property tests
└── notes_fuzz_test.go   # Go fuzzing
```

### Layer 4: Main Application
**Update**: `cmd/server/main.go`
- Initialize database (`internal/db`)
- Start MCP server on `/mcp` endpoint
- Start HTTP API on other routes
- Health check on `/health`

### Layer 5: Conformance Testing (Parallel)

**5a. Claude Code Test** (`tests/e2e/claude/`)
```
tests/e2e/claude/
├── .mcp.json    # Local MCP configuration
└── test.sh      # Shell script to drive Claude Code
```

**Test script approach**:
1. Start server in background
2. Configure Claude Code to use local MCP server
3. Run Claude Code with prompts that exercise all 6 tools
4. Verify results via HTTP API
5. Stop server

**5b. OpenAI Responses API Test** (`tests/e2e/openai/`)
```
tests/e2e/openai/
└── conformance_test.go  # Go test using Responses API
```

**Test approach** (NATIVE MCP - No wrapper code needed!):
1. Start MCP server: `./bin/server` (runs on localhost:8080/mcp)
2. Expose via ngrok: `ngrok http 8080`
3. Point OpenAI at MCP server with `type: "mcp"`
4. **OpenAI natively calls your MCP server** - discovers tools, executes them
5. Send prompts, verify responses
6. Property tests with rapid

**Complete example** (NO wrapper functions, NO HTTP client):
```go
func TestOpenAI_MCP_Integration(t *testing.T) {
    // Source API key
    source("~/openai_key.sh")
    apiKey := os.Getenv("OPENAI_API_KEY")

    // Initialize OpenAI client
    client := openai.NewClient(option.WithAPIKey(apiKey))

    // Point OpenAI at your MCP server (via ngrok)
    mcpTool := responses.ToolUnionParam{
        OfMCP: &responses.MCPToolParam{
            Type:            "mcp",
            ServerLabel:     "notes-server",
            ServerURL:       "https://abc123.ngrok.app/mcp", // Your ngrok URL
            RequireApproval: "never",
        },
    }

    // THAT'S IT! OpenAI now has native access to your 6 MCP tools
    params := responses.ResponseNewParams{
        Model: openai.ChatModelGPT4oMini,  // ⚠️ USE MINI NOT 4o
        Tools: []responses.ToolUnionParam{mcpTool},
        Input: responses.ResponseNewParamsInputUnion{
            OfString: openai.String("Create a note titled 'Test' with content 'Hello World'"),
        },
    }

    // OpenAI calls your MCP server directly, executes note_create tool
    resp, err := client.Responses.New(ctx, params)
    if err != nil {
        t.Fatal(err)
    }

    // Verify OpenAI successfully created the note
    assert.Contains(t, resp.OutputText(), "created")
}
```

**What happens under the hood**:
1. OpenAI calls your MCP server's `tools/list` endpoint
2. Discovers: note_view, note_create, note_update, note_search, note_list, note_delete
3. Model decides to call `note_create` with the parameters
4. OpenAI calls your MCP server's `tools/call` endpoint
5. Your server creates the note, returns result
6. OpenAI synthesizes final response

**NO HTTP client code needed. NO wrapper functions. OpenAI does it all.**

**5c. HTTP curl Test** (`tests/e2e/curl/`)
```
tests/e2e/curl/
└── test.sh  # Shell script with curl commands
```

### Layer 6: Master Test Script
**File**: `scripts/milestone1-test.sh`

**Orchestration**:
1. Build server with proper CGO flags
2. Start server on :8080
3. Wait for health check
4. Run MCP conformance (official suite)
5. Run Claude Code test
6. Start ngrok, run OpenAI test
7. Run HTTP curl test
8. Collect results
9. Stop server & ngrok
10. Report pass/fail

---

## Configuration

### Environment Variables Needed
```bash
export PATH=/usr/local/go/bin:$PATH
export CGO_ENABLED=1
export CGO_CFLAGS="-DSQLITE_ENABLE_FTS5"
export CGO_LDFLAGS="-lm"
export OPENAI_API_KEY="<from ~/openai_key.sh>"
```

### For Testing
- **MCP Server**: http://localhost:8080/mcp
- **HTTP API**: http://localhost:8080
- **Health Check**: http://localhost:8080/health
- **Ngrok** (for OpenAI): `ngrok http 8080`

---

## Success Criteria

✅ All 6 MCP tools working
✅ MCP conformance tests pass
✅ Claude Code can create/read/update/delete notes
✅ OpenAI Responses API can create/read/update/delete notes (via MCP)
✅ HTTP API can create/read/update/delete notes via curl
✅ Property tests pass (no panics, consistent state)
✅ Database persists data correctly
✅ Encryption works (SQLCipher)

---

## Time Estimate for Remaining Work

Based on MILESTONE1_PLAN.md:
- Notes CRUD: 30 min
- MCP server: 1 hour
- HTTP API: 30 min
- Main.go update: 15 min
- Property tests: 30 min
- Claude Code test: 30 min
- OpenAI Responses API test: 30 min
- HTTP curl test: 15 min
- Master script: 30 min
- Integration & debugging: 1 hour

**Total remaining**: ~5 hours of implementation work

---

## Key Changes from Original Plan

### ❌ OLD Approach (Function Calling)
- Define 6 functions manually in OpenAI SDK
- Map each function to HTTP endpoints
- Execute locally when OpenAI calls

### ✅ NEW Approach (Responses API with MCP)
- Point OpenAI at MCP server URL (via ngrok)
- OpenAI auto-discovers tools from MCP server
- OpenAI calls MCP server directly
- Much simpler integration!

**Why this is better**:
1. No duplicate tool definitions
2. Tests the actual MCP protocol
3. Same tools work for Claude Code and OpenAI
4. True conformance testing (not just HTTP API testing)

---

## Files Ready for Next Steps

**Documentation**:
- ✅ MILESTONE1_PLAN.md - Implementation plan
- ✅ notes/mcp-implementation-research.md - MCP server guide
- ✅ internal/db/README.md - Database documentation

**Code Ready to Use**:
- ✅ internal/db/ - Database layer
- ✅ Makefile - Build automation
- ✅ scripts/verify-db-layer.sh - DB verification

**Next File to Create**:
- 🚧 internal/notes/types.go - Start here!

---

## Commands to Continue

```bash
# Verify database layer still works
export PATH=/usr/local/go/bin:$PATH
make test-db

# Start implementing notes CRUD
mkdir -p internal/notes
# Create types.go, notes.go, notes_test.go

# Then implement MCP server
mkdir -p internal/mcp
# Create server.go, tools.go, handlers.go

# Then HTTP API
mkdir -p internal/api
# Create handlers.go

# Update main.go to wire everything together

# Create conformance tests
mkdir -p tests/e2e/{claude,openai,curl}

# Finally, create master test script
scripts/milestone1-test.sh
```

---

**Status**: Database layer complete and tested. Ready to implement notes CRUD logic.

**Next Action**: Implement `internal/notes/` package.
