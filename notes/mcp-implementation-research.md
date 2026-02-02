# MCP Server Implementation Research - Go + Claude Code Integration

**Date**: 2026-02-02
**Purpose**: Research MCP Go SDK implementation patterns and Claude Code configuration for conformance testing

---

## Table of Contents
1. [MCP Go SDK Overview](#mcp-go-sdk-overview)
2. [Server Implementation Patterns](#server-implementation-patterns)
3. [SSE Transport Implementation](#sse-transport-implementation)
4. [Tool Registration & Implementation](#tool-registration--implementation)
5. [Claude Code MCP Configuration](#claude-code-mcp-configuration)
6. [Claude Code Programmatic Testing](#claude-code-programmatic-testing)
7. [Example Implementations](#example-implementations)
8. [Testing Strategy](#testing-strategy)

---

## MCP Go SDK Overview

### Official Go SDK
- **Repository**: `github.com/modelcontextprotocol/go-sdk`
- **Version**: v1.2.0 (published Dec 19, 2024)
- **Status**: Production-ready (v1.0.0+ stable)
- **License**: MIT
- **Maintained by**: Model Context Protocol org + Google collaboration

### Package Structure
```
github.com/modelcontextprotocol/go-sdk/
├── mcp/           # Primary APIs (server, client, sessions)
├── jsonrpc/       # Custom transport implementations
└── auth/          # OAuth primitives
```

### Core Architecture Pattern
```
Client                                    Server
  ⇅                   (jsonrpc2)            ⇅
ClientSession ⇄ Client Transport ⇄ Server Transport ⇄ ServerSession
```

Both Client and Server handle concurrent connections, creating new sessions for each connection.

**Sources**:
- [GitHub - modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- [mcp package - Go Packages](https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp)

---

## Server Implementation Patterns

### 1. Basic Server Creation

```go
package main

import (
    "context"
    "log"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
    // Create server with metadata
    server := mcp.NewServer(&mcp.Implementation{
        Name:    "my-server",
        Version: "v1.0.0",
    }, nil)

    // Register capabilities (tools, resources, prompts)
    registerTools(server)

    // Run on transport
    if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
        log.Fatal(err)
    }
}
```

### 2. Server Initialization Pattern

**Three-step process**:
1. Create server instance
2. Add features (tools, resources, prompts)
3. Connect transport and run

```go
// Step 1: Create server
server := mcp.NewServer(&mcp.Implementation{
    Name:    "notes-mcp",
    Version: "v0.1.0",
}, &mcp.ServerOptions{
    InitializedHandler: func(ctx context.Context, req *mcp.InitializedRequest) {
        log.Println("Client connected")
    },
    PageSize: 1000, // Default pagination size
})

// Step 2: Register tools
mcp.AddTool(server, toolDef, handler)

// Step 3: Run on transport
server.Run(ctx, transport)
```

### 3. ServerOptions Configuration

```go
type ServerOptions struct {
    InitializedHandler      func(context.Context, *InitializedRequest)
    RootsListChangedHandler func(context.Context, *RootsListChangedRequest)
    PageSize                int // DefaultPageSize = 1000
}
```

**Sources**:
- [Building a Model Context Protocol (MCP) Server in Go](https://navendu.me/posts/mcp-server-go/)
- [Writing your first MCP Server with the Go SDK | Medium](https://medium.com/@xcoulon/writing-your-first-mcp-server-with-the-go-sdk-62fada87e5eb)

---

## Streamable HTTP Transport (MCP Spec 2025-03-26)

### Overview

**Protocol Revision**: 2025-03-26

**Streamable HTTP** is the standard HTTP transport for MCP, replacing the deprecated HTTP+SSE transport from protocol version 2024-11-05. It provides a unified approach where:
- A **single endpoint** (e.g., `/mcp`) handles all communication
- **POST** requests send JSON-RPC messages from client to server
- **GET** requests optionally allow server to push messages to client
- **SSE** is used optionally within responses for streaming, not as a separate transport

### Key Differences from Deprecated SSE Transport

| Aspect | Old HTTP+SSE (Deprecated) | Streamable HTTP (Current) |
|--------|---------------------------|---------------------------|
| Endpoints | Two: `/sse` + `/messages` | Single: `/mcp` |
| Architecture | Dual-endpoint | Unified |
| Streaming | Always SSE | Optional (JSON or SSE) |
| Connection | Long-lived | Request-based |
| Recovery | No built-in mechanism | Resumability via event IDs |
| Session Management | None | `Mcp-Session-Id` header |

### Server Implementation (Official SDK)

```go
package main

import (
    "net/http"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
    server := mcp.NewServer(&mcp.Implementation{
        Name:    "my-server",
        Version: "v1.0.0",
    }, nil)

    // Register tools
    registerTools(server)

    // Create Streamable HTTP handler (single endpoint)
    handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
        return server
    }, nil)

    // Mount single MCP endpoint
    http.Handle("/mcp", handler)

    // Start server
    http.ListenAndServe(":8080", nil)
}
```

### Protocol Details

#### Sending Messages to Server (POST)

Per MCP spec, clients MUST use HTTP POST to send JSON-RPC messages:

1. Client sends POST with `Content-Type: application/json`
2. Client MUST include `Accept` header with both `application/json` and `text/event-stream`
3. Body contains JSON-RPC request, notification, response, or batch
4. Server responds with either:
   - `Content-Type: application/json` (single JSON response)
   - `Content-Type: text/event-stream` (SSE stream for multiple messages)

```bash
# Example: Send initialize request
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26"},"id":1}'
```

#### Receiving Server Messages (GET)

Clients MAY issue HTTP GET to open an SSE stream for server-initiated messages:

1. Client sends GET with `Accept: text/event-stream`
2. Server returns SSE stream OR 405 Method Not Allowed
3. Server MAY send JSON-RPC requests/notifications on the stream
4. Used for server-to-client communication without client first sending data

```bash
# Example: Open server message stream
curl -N http://localhost:8080/mcp \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: abc123"
```

#### Session Management

Sessions enable stateful interactions:

1. Server MAY assign session ID via `Mcp-Session-Id` header in InitializeResult
2. Clients MUST include session ID in all subsequent requests
3. Session ID must be visible ASCII characters (0x21-0x7E)
4. Session termination: Client sends DELETE with session ID

```go
// Session ID in response header
w.Header().Set("Mcp-Session-Id", generateSecureSessionID())
```

#### Resumability

To handle connection drops:

1. Server MAY attach `id` field to SSE events
2. Client includes `Last-Event-ID` header when reconnecting
3. Server MAY replay missed messages from that point

### Security Requirements

Per MCP spec:

1. **Origin Validation**: Servers MUST validate `Origin` header to prevent DNS rebinding
2. **Localhost Binding**: Local servers SHOULD bind to 127.0.0.1, not 0.0.0.0
3. **Authentication**: Servers SHOULD implement proper auth for all connections

### Backwards Compatibility

**For clients** supporting older servers:
1. POST InitializeRequest to server URL
2. If successful → server supports Streamable HTTP
3. If 4xx error → try GET, expecting SSE stream with `endpoint` event (old transport)

**For servers** supporting older clients:
- Keep hosting old SSE+POST endpoints alongside new MCP endpoint
- Or combine old POST endpoint with new MCP endpoint (adds complexity)

**Sources**:
- [MCP Transports Specification 2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)
- [Why MCP Deprecated SSE and Went with Streamable HTTP](https://blog.fka.dev/blog/2025-06-06-why-mcp-deprecated-sse-and-go-with-streamable-http/)
- [Exploring the Future of MCP Transports](http://blog.modelcontextprotocol.io/posts/2025-12-19-mcp-transport-future/)

---

## Tool Registration & Implementation

### MCP Core Features

The six core MCP features:
1. **Tools** - Actions the server exposes (like API functions)
2. **Resources** - Data the server provides (files, database records)
3. **Prompts** - Predefined instruction templates
4. **Sampling** - AI model invocation capability
5. **Roots** - File system roots for context
6. **Elicitation** - Interactive parameter gathering

### Tool Registration (Type-Safe - Recommended)

```go
// 1. Define input/output types with JSON schema annotations
type NoteViewArgs struct {
    ID string `json:"id" jsonschema:"Note ID to view"`
}

type NoteViewOutput struct {
    Title   string `json:"title" jsonschema:"Note title"`
    Content string `json:"content" jsonschema:"Note content"`
}

// 2. Implement handler function
func handleNoteView(
    ctx context.Context,
    req *mcp.CallToolRequest,
    args NoteViewArgs,
) (*mcp.CallToolResult, NoteViewOutput, error) {
    // Business logic
    note, err := getNote(args.ID)
    if err != nil {
        return &mcp.CallToolResult{IsError: true}, NoteViewOutput{}, err
    }

    // Return result
    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: "Note retrieved successfully"},
        },
    }, NoteViewOutput{
        Title:   note.Title,
        Content: note.Content,
    }, nil
}

// 3. Register tool with type-safe helper
mcp.AddTool(server, &mcp.Tool{
    Name:        "note_view",
    Description: "View a note by ID",
}, handleNoteView)
```

**Key Benefits**:
- **Automatic schema inference** from Go types
- **Automatic validation** of input arguments
- **Type safety** - compile-time checking
- **Schema descriptions** via `jsonschema` struct tags

### Tool Registration (Raw Handler)

```go
// Manual schema control
server.AddTool(&mcp.Tool{
    Name:         "note_view",
    Description:  "View a note by ID",
    InputSchema: &mcp.Schema{
        Type: "object",
        Properties: map[string]*mcp.Schema{
            "id": {Type: "string", Description: "Note ID"},
        },
        Required: []string{"id"},
    },
}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    // Extract arguments manually
    args := req.Params.Arguments
    id := args["id"].(string)

    // Business logic
    note, err := getNote(id)
    if err != nil {
        return &mcp.CallToolResult{IsError: true}, err
    }

    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: note.Content},
        },
    }, nil
})
```

### Implementing the 6 Required Tools

#### 1. note_view - Read a note
```go
type NoteViewArgs struct {
    ID string `json:"id" jsonschema:"Note ID"`
}

mcp.AddTool(server, &mcp.Tool{
    Name:        "note_view",
    Description: "View a note by ID",
}, func(ctx context.Context, req *mcp.CallToolRequest, args NoteViewArgs) (*mcp.CallToolResult, any, error) {
    note, err := db.GetNote(args.ID)
    if err != nil {
        return &mcp.CallToolResult{IsError: true}, nil, err
    }
    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: fmt.Sprintf("# %s\n\n%s", note.Title, note.Content)},
        },
    }, note, nil
})
```

#### 2. note_create - Create new note
```go
type NoteCreateArgs struct {
    Title   string `json:"title" jsonschema:"Note title"`
    Content string `json:"content" jsonschema:"Note content"`
}

type NoteCreateOutput struct {
    ID string `json:"id" jsonschema:"Created note ID"`
}

mcp.AddTool(server, &mcp.Tool{
    Name:        "note_create",
    Description: "Create a new note",
}, func(ctx context.Context, req *mcp.CallToolRequest, args NoteCreateArgs) (*mcp.CallToolResult, NoteCreateOutput, error) {
    id, err := db.CreateNote(args.Title, args.Content)
    if err != nil {
        return &mcp.CallToolResult{IsError: true}, NoteCreateOutput{}, err
    }
    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: fmt.Sprintf("Created note: %s", id)},
        },
    }, NoteCreateOutput{ID: id}, nil
})
```

#### 3. note_update - Update existing note
```go
type NoteUpdateArgs struct {
    ID      string `json:"id" jsonschema:"Note ID to update"`
    Title   string `json:"title,omitempty" jsonschema:"New title (optional)"`
    Content string `json:"content,omitempty" jsonschema:"New content (optional)"`
}

mcp.AddTool(server, &mcp.Tool{
    Name:        "note_update",
    Description: "Update an existing note",
}, func(ctx context.Context, req *mcp.CallToolRequest, args NoteUpdateArgs) (*mcp.CallToolResult, any, error) {
    err := db.UpdateNote(args.ID, args.Title, args.Content)
    if err != nil {
        return &mcp.CallToolResult{IsError: true}, nil, err
    }
    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: "Note updated successfully"},
        },
    }, nil, nil
})
```

#### 4. note_search - Search notes
```go
type NoteSearchArgs struct {
    Query string `json:"query" jsonschema:"Search query"`
    Limit int    `json:"limit,omitempty" jsonschema:"Max results (default: 10)"`
}

type NoteSearchOutput struct {
    Results []NoteSearchResult `json:"results" jsonschema:"Search results"`
}

type NoteSearchResult struct {
    ID      string `json:"id"`
    Title   string `json:"title"`
    Snippet string `json:"snippet"`
}

mcp.AddTool(server, &mcp.Tool{
    Name:        "note_search",
    Description: "Search notes by content",
}, func(ctx context.Context, req *mcp.CallToolRequest, args NoteSearchArgs) (*mcp.CallToolResult, NoteSearchOutput, error) {
    limit := args.Limit
    if limit == 0 {
        limit = 10
    }

    results, err := db.SearchNotes(args.Query, limit)
    if err != nil {
        return &mcp.CallToolResult{IsError: true}, NoteSearchOutput{}, err
    }

    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: fmt.Sprintf("Found %d results", len(results))},
        },
    }, NoteSearchOutput{Results: results}, nil
})
```

#### 5. note_list - List all notes
```go
type NoteListArgs struct {
    Offset int `json:"offset,omitempty" jsonschema:"Pagination offset"`
    Limit  int `json:"limit,omitempty" jsonschema:"Page size (default: 100)"`
}

type NoteListOutput struct {
    Notes []NoteListItem `json:"notes" jsonschema:"List of notes"`
    Total int            `json:"total" jsonschema:"Total count"`
}

type NoteListItem struct {
    ID        string    `json:"id"`
    Title     string    `json:"title"`
    CreatedAt time.Time `json:"created_at"`
}

mcp.AddTool(server, &mcp.Tool{
    Name:        "note_list",
    Description: "List all notes",
}, func(ctx context.Context, req *mcp.CallToolRequest, args NoteListArgs) (*mcp.CallToolResult, NoteListOutput, error) {
    limit := args.Limit
    if limit == 0 {
        limit = 100
    }

    notes, total, err := db.ListNotes(args.Offset, limit)
    if err != nil {
        return &mcp.CallToolResult{IsError: true}, NoteListOutput{}, err
    }

    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: fmt.Sprintf("Listed %d notes (total: %d)", len(notes), total)},
        },
    }, NoteListOutput{Notes: notes, Total: total}, nil
})
```

#### 6. note_delete - Delete a note
```go
type NoteDeleteArgs struct {
    ID string `json:"id" jsonschema:"Note ID to delete"`
}

mcp.AddTool(server, &mcp.Tool{
    Name:        "note_delete",
    Description: "Delete a note by ID",
}, func(ctx context.Context, req *mcp.CallToolRequest, args NoteDeleteArgs) (*mcp.CallToolResult, any, error) {
    err := db.DeleteNote(args.ID)
    if err != nil {
        return &mcp.CallToolResult{IsError: true}, nil, err
    }
    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: "Note deleted successfully"},
        },
    }, nil, nil
})
```

### Content Types

MCP supports multiple content types in responses:

```go
// Text content
&mcp.TextContent{
    Text: "Hello world",
    Annotations: &mcp.Annotations{
        Audience: []string{"developers"},
        Priority: 0.8,
    },
}

// Image content
&mcp.ImageContent{
    Data:     imageBytes,
    MIMEType: "image/png",
}

// Embedded resource
&mcp.EmbeddedResource{
    URI:      "note://123",
    MIMEType: "text/markdown",
    Data:     noteBytes,
}

// Resource link
&mcp.ResourceLink{
    URI: "note://123",
}
```

**Sources**:
- [Understanding MCP features: Tools, Resources, Prompts | WorkOS](https://workos.com/blog/mcp-features-guide)
- [Specification - Model Context Protocol](https://modelcontextprotocol.io/specification/2025-11-25)

---

## Claude Code MCP Configuration

### Configuration Scopes

Claude Code supports **three configuration scopes**:

1. **Local scope** (default) - Personal to you, current project only
   - Stored in: `~/.claude.json` under project path
   - Use case: Personal dev servers, sensitive credentials, experiments

2. **Project scope** - Shared with team via `.mcp.json` in repo
   - Stored in: `.mcp.json` at project root (checked into git)
   - Use case: Team-shared servers, project-specific tools

3. **User scope** - Personal to you, all projects
   - Stored in: `~/.claude.json` (global)
   - Use case: Personal utilities used across projects

### Configuration File Locations

```
~/.claude.json                    # User + local scope config
/path/to/project/.mcp.json        # Project scope config (checked into git)
```

### Adding MCP Servers (Three Transport Types)

#### Option 1: HTTP Server (Recommended for Remote)

```bash
# Basic HTTP server
claude mcp add --transport http notes-server http://localhost:8080/mcp

# With authentication header
claude mcp add --transport http secure-api https://api.example.com/mcp \
  --header "Authorization: Bearer your-token"

# Specify scope
claude mcp add --transport http --scope project notes http://localhost:8080/mcp
```

#### Option 2: SSE Server (Deprecated, but supported)

```bash
# Basic SSE server
claude mcp add --transport sse notes-sse http://localhost:8080/sse

# With authentication
claude mcp add --transport sse private-api https://api.company.com/sse \
  --header "X-API-Key: your-key-here"
```

**⚠️ Warning**: SSE transport is deprecated. Use HTTP servers instead.

#### Option 3: Stdio Server (Local Process)

```bash
# Run local command
claude mcp add --transport stdio --scope local my-server \
  -- /path/to/server

# Run with npm/npx
claude mcp add --transport stdio --env API_KEY=secret airtable \
  -- npx -y airtable-mcp-server

# Run Go binary
claude mcp add --transport stdio notes-local \
  -- /home/user/bin/notes-mcp-server --port 8080
```

**Important**: The `--` separator is critical - it separates Claude's flags from the server's command and arguments.

### Configuration File Format

#### Project Scope (.mcp.json)

```json
{
  "mcpServers": {
    "notes-http": {
      "type": "http",
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer ${API_TOKEN}"
      }
    },
    "notes-stdio": {
      "type": "stdio",
      "command": "./bin/notes-server",
      "args": ["--data-dir", "${DATA_DIR}"],
      "env": {
        "LOG_LEVEL": "debug"
      }
    }
  }
}
```

#### User/Local Scope (~/.claude.json)

```json
{
  "mcpServers": {
    "notes-local": {
      "type": "stdio",
      "command": "/home/user/notes-server",
      "args": [],
      "env": {}
    }
  },
  "projects": {
    "/home/user/project": {
      "mcpServers": {
        "project-specific": {
          "type": "http",
          "url": "http://localhost:8080/mcp"
        }
      }
    }
  }
}
```

### Environment Variable Expansion

Claude Code supports environment variable expansion in `.mcp.json`:

```json
{
  "mcpServers": {
    "api-server": {
      "type": "http",
      "url": "${API_BASE_URL:-https://api.example.com}/mcp",
      "headers": {
        "Authorization": "Bearer ${API_KEY}"
      }
    },
    "local-server": {
      "type": "stdio",
      "command": "${HOME}/bin/server",
      "args": ["--data", "${DATA_DIR:-/tmp/data}"],
      "env": {
        "DB_PATH": "${DB_PATH}"
      }
    }
  }
}
```

**Syntax**:
- `${VAR}` - Expand environment variable VAR (error if not set)
- `${VAR:-default}` - Expand VAR or use default if not set

### Managing MCP Servers

```bash
# List all configured servers
claude mcp list

# Get details for specific server
claude mcp get notes-server

# Remove a server
claude mcp remove notes-server

# Check server status (within Claude Code)
> /mcp

# Reset project approval choices
claude mcp reset-project-choices
```

### Configuration Priority

When servers have the same name at multiple scopes:
1. **Local scope** (highest priority)
2. **Project scope**
3. **User scope** (lowest priority)

### Important Configuration Options

```bash
# Set scope
--scope local       # Default: Personal, current project only
--scope project     # Shared via .mcp.json (checked into git)
--scope user        # Personal, all projects

# Set environment variables
--env KEY=value     # Pass environment variables to server
--env API_KEY=secret --env LOG_LEVEL=debug

# Add authentication headers
--header "Authorization: Bearer token"
--header "X-API-Key: key123"

# Configure timeout
MCP_TIMEOUT=10000 claude  # 10-second timeout

# Configure max output tokens
MAX_MCP_OUTPUT_TOKENS=50000 claude  # Default: 25,000
```

### Testing Configuration

For conformance testing, use stdio transport to run your server:

```bash
# Build Go server
CGO_ENABLED=1 go build -o bin/notes-server ./cmd/server

# Add to Claude Code (local scope for testing)
claude mcp add --transport stdio --scope local notes-test \
  -- /home/user/git/agent-notes/bin/notes-server --mcp-mode

# Verify it's registered
claude mcp list

# Test in Claude Code
> /mcp
# You should see "notes-test" in the list

# Use the tools
> "Create a test note with title 'Hello' and content 'World'"
```

**Sources**:
- [Connect Claude Code to tools via MCP - Claude Code Docs](https://code.claude.com/docs/en/mcp)
- [Add MCP Servers to Claude Code - Setup & Configuration Guide | MCPcat](https://mcpcat.io/guides/adding-an-mcp-server-to-claude-code/)
- [Connect to local MCP servers - Model Context Protocol](https://modelcontextprotocol.io/docs/develop/connect-local-servers)

---

## Claude Code Programmatic Testing

### Running Claude Code Programmatically

Claude Code supports **headless mode** via the `-p` flag (previously called "headless mode"):

```bash
# Basic usage
claude -p "prompt text"

# With tool permissions
claude -p "Find and fix the bug" --allowedTools "Read,Edit,Bash"

# With JSON output
claude -p "Summarize this project" --output-format json

# Continue conversation
claude -p "First prompt"
claude -p "Follow-up" --continue
```

### Output Formats

```bash
# Text output (default)
claude -p "What does auth.py do?"

# JSON output (with metadata)
claude -p "Summarize project" --output-format json
# Returns: {"result": "...", "session_id": "...", "usage": {...}}

# Streaming JSON (real-time)
claude -p "Explain recursion" --output-format stream-json --verbose --include-partial-messages

# Extract text result with jq
claude -p "Summarize" --output-format json | jq -r '.result'
```

### Structured Output with JSON Schema

```bash
# Extract structured data
claude -p "Extract function names from auth.py" \
  --output-format json \
  --json-schema '{
    "type": "object",
    "properties": {
      "functions": {"type": "array", "items": {"type": "string"}}
    },
    "required": ["functions"]
  }'

# Result in .structured_output field
claude -p "Extract data" --output-format json --json-schema '...' | \
  jq '.structured_output'
```

### Auto-Approving Tools

```bash
# Allow specific tools without prompts
claude -p "Run tests and fix failures" \
  --allowedTools "Bash,Read,Edit"

# Use permission rule syntax with wildcards
claude -p "Create a commit" \
  --allowedTools "Bash(git diff *),Bash(git status *),Bash(git commit *)"

# Note: Space before * is important!
# "Bash(git diff *)"  - Matches "git diff --staged", etc.
# "Bash(git diff*)"   - Also matches "git diff-index", etc.
```

### Continuing Conversations

```bash
# Continue most recent conversation
claude -p "First request"
claude -p "Follow-up" --continue

# Resume specific conversation by ID
session_id=$(claude -p "Start review" --output-format json | jq -r '.session_id')
claude -p "Continue review" --resume "$session_id"
```

### Custom System Prompts

```bash
# Append to default system prompt
gh pr diff "$1" | claude -p \
  --append-system-prompt "You are a security engineer. Review for vulnerabilities." \
  --output-format json

# Replace system prompt entirely
claude -p "Review code" \
  --system-prompt "You are a code reviewer focused on performance."
```

### Testing Strategy for MCP Server

#### Approach 1: Conformance Test (Automated)

```bash
#!/bin/bash
# scripts/test-mcp-with-claude.sh

set -e

# Build and start MCP server in background
CGO_ENABLED=1 go build -o bin/notes-server ./cmd/server
./bin/notes-server --mcp-mode &
SERVER_PID=$!
trap "kill $SERVER_PID" EXIT

# Wait for server to start
sleep 2

# Add server to Claude Code
claude mcp add --transport http --scope local notes-test http://localhost:8080/mcp

# Test basic operations with Claude
echo "Testing note creation..."
result=$(claude -p "Create a note with title 'Test' and content 'Hello'" \
  --allowedTools "notes-test:note_create" \
  --output-format json)

echo "Result: $result"

# Verify result
note_id=$(echo "$result" | jq -r '.structured_output.id')
if [ -z "$note_id" ]; then
    echo "FAIL: Could not create note"
    exit 1
fi

echo "Testing note retrieval..."
result=$(claude -p "View note $note_id" \
  --allowedTools "notes-test:note_view" \
  --output-format json)

echo "PASS: All tests successful"
```

#### Approach 2: Interactive Testing

```bash
# Start server
./bin/notes-server --mcp-mode &

# Add to Claude Code
claude mcp add --transport http --scope local notes-test http://localhost:8080/mcp

# Launch Claude Code interactively
claude

# Then in Claude Code:
> /mcp
> "List all available MCP tools"
> "Create a test note"
> "Search for notes containing 'test'"
> "Delete the test note"
```

#### Approach 3: Official Conformance Suite

```bash
#!/bin/bash
# scripts/mcp-conformance.sh

MCP_URL="http://localhost:8080/mcp"
OUTPUT_DIR="./test-results/mcp-conformance"

# Start server
./bin/notes-server --mcp-mode &
SERVER_PID=$!
trap "kill $SERVER_PID" EXIT

sleep 2

# Run official conformance tests
npx @modelcontextprotocol/conformance server \
    --url "$MCP_URL" \
    --output-dir "$OUTPUT_DIR"

echo "Conformance tests complete. Results in $OUTPUT_DIR"
```

### CI/CD Integration

```bash
# GitHub Actions example
name: Test MCP Server with Claude Code

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Claude Code
        run: |
          curl -fsSL https://code.claude.com/install.sh | sh

      - name: Build MCP Server
        run: CGO_ENABLED=1 go build -o bin/server ./cmd/server

      - name: Start MCP Server
        run: ./bin/server --mcp-mode &

      - name: Wait for Server
        run: sleep 5

      - name: Add to Claude Code
        run: |
          claude mcp add --transport http --scope local test http://localhost:8080/mcp

      - name: Test with Claude Code
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          claude -p "Test all note operations" \
            --allowedTools "MCPSearch,test:*" \
            --output-format json > results.json

      - name: Verify Results
        run: |
          cat results.json
          # Add assertions here
```

**Sources**:
- [Run Claude Code programmatically - Claude Code Docs](https://code.claude.com/docs/en/headless)
- [How I Automate API Testing Using Claude Code - DEV Community](https://dev.to/therealmrmumba/how-i-automate-api-testing-using-claude-code-16ka)
- [Shell Scripting in 2026: Mastering System Automation with Claude Code](https://vocal.media/journal/shell-scripting-in-2026-mastering-system-automation-with-claude-code)

---

## Example Implementations

### Complete MCP Server Example (Streamable HTTP Transport)

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Note represents a note in the system
type Note struct {
    ID        string    `json:"id"`
    Title     string    `json:"title"`
    Content   string    `json:"content"`
    CreatedAt time.Time `json:"created_at"`
}

// In-memory storage (replace with real DB)
var notes = make(map[string]*Note)

func main() {
    // Create MCP server
    server := mcp.NewServer(&mcp.Implementation{
        Name:    "notes-mcp",
        Version: "v1.0.0",
    }, &mcp.ServerOptions{
        InitializedHandler: func(ctx context.Context, req *mcp.InitializedRequest) {
            log.Println("Client connected to notes MCP server")
        },
        PageSize: 100,
    })

    // Register all tools
    registerTools(server)

    // Create Streamable HTTP handler (MCP Spec 2025-03-26)
    handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
        // Could return different servers based on auth, etc.
        return server
    }, nil)

    // Setup HTTP routes - single endpoint for all MCP communication
    http.Handle("/mcp", handler)
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })

    // Start server
    log.Println("Notes MCP Server starting on :8080")
    log.Println("   Endpoint: http://localhost:8080/mcp")
    log.Println("   Transport: Streamable HTTP (MCP Spec 2025-03-26)")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}

func registerTools(server *mcp.Server) {
    // Tool 1: note_view
    type NoteViewArgs struct {
        ID string `json:"id" jsonschema:"Note ID to view"`
    }

    mcp.AddTool(server, &mcp.Tool{
        Name:        "note_view",
        Description: "View a note by ID",
    }, func(ctx context.Context, req *mcp.CallToolRequest, args NoteViewArgs) (*mcp.CallToolResult, *Note, error) {
        note, exists := notes[args.ID]
        if !exists {
            return &mcp.CallToolResult{IsError: true}, nil, fmt.Errorf("note not found: %s", args.ID)
        }
        return &mcp.CallToolResult{
            Content: []mcp.Content{
                &mcp.TextContent{Text: fmt.Sprintf("# %s\n\n%s", note.Title, note.Content)},
            },
        }, note, nil
    })

    // Tool 2: note_create
    type NoteCreateArgs struct {
        Title   string `json:"title" jsonschema:"Note title"`
        Content string `json:"content" jsonschema:"Note content"`
    }

    type NoteCreateOutput struct {
        ID string `json:"id" jsonschema:"Created note ID"`
    }

    mcp.AddTool(server, &mcp.Tool{
        Name:        "note_create",
        Description: "Create a new note",
    }, func(ctx context.Context, req *mcp.CallToolRequest, args NoteCreateArgs) (*mcp.CallToolResult, NoteCreateOutput, error) {
        id := fmt.Sprintf("note-%d", time.Now().Unix())
        note := &Note{
            ID:        id,
            Title:     args.Title,
            Content:   args.Content,
            CreatedAt: time.Now(),
        }
        notes[id] = note

        return &mcp.CallToolResult{
            Content: []mcp.Content{
                &mcp.TextContent{Text: fmt.Sprintf("Created note: %s", id)},
            },
        }, NoteCreateOutput{ID: id}, nil
    })

    // Tool 3: note_list
    type NoteListArgs struct {
        Limit int `json:"limit,omitempty" jsonschema:"Max results (default: 100)"`
    }

    type NoteListOutput struct {
        Notes []*Note `json:"notes" jsonschema:"List of notes"`
        Total int     `json:"total" jsonschema:"Total count"`
    }

    mcp.AddTool(server, &mcp.Tool{
        Name:        "note_list",
        Description: "List all notes",
    }, func(ctx context.Context, req *mcp.CallToolRequest, args NoteListArgs) (*mcp.CallToolResult, NoteListOutput, error) {
        limit := args.Limit
        if limit == 0 {
            limit = 100
        }

        noteList := make([]*Note, 0, len(notes))
        for _, note := range notes {
            noteList = append(noteList, note)
            if len(noteList) >= limit {
                break
            }
        }

        return &mcp.CallToolResult{
            Content: []mcp.Content{
                &mcp.TextContent{Text: fmt.Sprintf("Found %d notes", len(noteList))},
            },
        }, NoteListOutput{Notes: noteList, Total: len(notes)}, nil
    })

    // Add remaining tools: note_update, note_delete, note_search
    // ... (similar pattern)

    log.Println("✓ Registered 6 MCP tools: note_view, note_create, note_update, note_search, note_list, note_delete")
}
```

### Alternative: Stdio Transport Example

```go
// For local development/testing
func main() {
    server := mcp.NewServer(&mcp.Implementation{
        Name:    "notes-mcp",
        Version: "v1.0.0",
    }, nil)

    registerTools(server)

    // Run on stdio (for Claude Desktop, etc.)
    log.Println("🚀 Notes MCP Server (stdio transport)")
    if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
        log.Fatal(err)
    }
}
```

**Sources**:
- [GitHub - davidferlay/mcp-go-sse-server](https://github.com/davidferlay/mcp-go-sse-server)
- [Building a Model Context Protocol (MCP) Server in Go](https://navendu.me/posts/mcp-server-go/)

---

## Testing Strategy

### 1. Official MCP Conformance Suite

**Best for**: Protocol compliance verification

```bash
# Install conformance test suite
npm install -D @modelcontextprotocol/conformance

# Run against your server
npx @modelcontextprotocol/conformance server \
    --url "http://localhost:8080/mcp" \
    --output-dir "./test-results/mcp-conformance"
```

**What it tests**:
- Protocol handshake
- Tool discovery
- Tool invocation
- Error handling
- Content type support

### 2. Claude Code Integration Testing

**Best for**: Real-world usage verification

```bash
# Add server to Claude Code
claude mcp add --transport http --scope local notes-test http://localhost:8080/mcp

# Interactive testing
claude
> /mcp
> "Create a test note"
> "List all notes"

# Automated testing
claude -p "Test all note CRUD operations" \
  --allowedTools "notes-test:*" \
  --output-format json
```

### 3. Unit Testing with In-Memory Transport

**Best for**: Development and CI/CD

```go
// tests/mcp_test.go
package tests

import (
    "context"
    "testing"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNoteOperations(t *testing.T) {
    // Create server
    server := createTestServer()

    // Create client
    client := mcp.NewClient(&mcp.Implementation{
        Name:    "test-client",
        Version: "v0.0.1",
    }, nil)

    // Use in-memory transport
    serverTransport, clientTransport := mcp.NewInMemoryTransports()

    // Connect
    ctx := context.Background()
    serverSession, err := server.Connect(ctx, serverTransport, nil)
    if err != nil {
        t.Fatal(err)
    }
    defer serverSession.Close()

    clientSession, err := client.Connect(ctx, clientTransport, nil)
    if err != nil {
        t.Fatal(err)
    }
    defer clientSession.Close()

    // Test tool calls
    result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
        Name: "note_create",
        Arguments: map[string]any{
            "title":   "Test Note",
            "content": "Test Content",
        },
    })
    if err != nil {
        t.Fatal(err)
    }

    if result.IsError {
        t.Fatal("Tool call failed")
    }

    // Verify result
    // ...
}
```

### 4. End-to-End Testing with Playwright

**Best for**: Full stack integration testing

```go
// tests/e2e/mcp_integration_test.go
package e2e

import (
    "testing"
    "github.com/playwright-community/playwright-go"
)

func TestMCPIntegration(t *testing.T) {
    // Start server
    server := startTestServer(t)
    defer server.Shutdown()

    // Launch browser
    pw, err := playwright.Run()
    if err != nil {
        t.Fatal(err)
    }
    defer pw.Stop()

    browser, err := pw.Chromium.Launch()
    if err != nil {
        t.Fatal(err)
    }
    defer browser.Close()

    page, err := browser.NewPage()
    if err != nil {
        t.Fatal(err)
    }

    // Navigate to Claude Code
    page.Goto("http://localhost:3000")

    // Test MCP operations via UI
    // ...
}
```

### Testing Checklist

- [ ] Protocol handshake works
- [ ] All 6 tools registered and discoverable
- [ ] Tool input validation works
- [ ] Tool execution succeeds
- [ ] Error handling returns proper MCP errors
- [ ] Content types serialize correctly (JSON and SSE)
- [ ] Streamable HTTP POST/GET work correctly
- [ ] Session management via Mcp-Session-Id header
- [ ] Concurrent requests handled correctly
- [ ] Authentication works (if applicable)
- [ ] Claude Code can discover and use tools
- [ ] Official conformance suite passes

---

## Quick Reference

### Build and Run Commands

```bash
# Build server (with CGO for SQLCipher)
CGO_ENABLED=1 go build -o bin/notes-server ./cmd/server

# Run server (Streamable HTTP transport)
./bin/notes-server --mcp-mode

# Run conformance tests
npm run mcp-conformance

# Add to Claude Code
claude mcp add --transport http --scope local notes http://localhost:8080/mcp

# Test interactively
claude
> /mcp
> "Create a note titled 'Test' with content 'Hello World'"
```

### Key URLs

- MCP Specification (2025-03-26): https://modelcontextprotocol.io/specification/2025-03-26/basic/transports
- Go SDK: https://github.com/modelcontextprotocol/go-sdk
- Go SDK Docs: https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp
- Claude Code MCP Docs: https://code.claude.com/docs/en/mcp
- Conformance Tests: https://www.npmjs.com/package/@modelcontextprotocol/conformance

### Next Steps

1. **Implement MCP server** with Streamable HTTP transport (single `/mcp` endpoint)
2. **Register 6 tools** (note_view, note_create, note_update, note_search, note_list, note_delete)
3. **Test locally** with curl/httpie
4. **Run conformance suite** to verify protocol compliance
5. **Add to Claude Code** and test interactively
6. **Automate testing** in CI/CD

---

**Research completed**: 2026-02-02
**Updated**: 2026-02-02 (Updated for Streamable HTTP transport per MCP Spec 2025-03-26)
**Total sources reviewed**: 25+ articles, documentation pages, and repositories
