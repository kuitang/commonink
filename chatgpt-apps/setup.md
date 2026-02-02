# Build your MCP server

By the end of this guide, you’ll know how to connect your backend MCP server to ChatGPT, define tools, register UI templates, and tie everything together using the widget runtime. You’ll build a working foundation for a ChatGPT App that returns structured data, renders an interactive widget, and keeps your model, server, and UI in sync. If you prefer to dive straight into the implementation, you can skip ahead to the [example](#example) at the end.



Build faster with the [OpenAI Docs MCP server](https://developers.openai.com/resources/docs-mcp) in your
  editor.



## Overview

### What an MCP server does for your app

ChatGPT Apps have three components:

- **Your MCP server** defines tools, enforces auth, returns data, and points each tool to a UI bundle.
- **The widget/UI bundle** renders inside ChatGPT’s iframe, reading data and widget-runtime globals exposed through `window.openai`.
- **The model** decides when to call tools and narrates the experience using the structured data you return.

A solid server implementation keeps those boundaries clean so you can iterate on UI and data independently. Remember: you build the MCP server and define the tools, but ChatGPT’s model chooses when to call them based on the metadata you provide.

### Before you begin

Pre-requisites:

- Comfortable with TypeScript or Python and a web bundler (Vite, esbuild, etc.).
- MCP server reachable over HTTP (local is fine to start).
- Built UI bundle that exports a root script (React or vanilla).

Example project layout:

```
your-chatgpt-app/
├─ server/
│  └─ src/index.ts          # MCP server + tool handlers
├─ web/
│  ├─ src/component.tsx     # React widget
│  └─ dist/app.{js,css}  # Bundled assets referenced by the server
└─ package.json
```

## Architecture flow

1. A user prompt causes ChatGPT to call one of your MCP tools.
2. Your server runs the handler, fetches authoritative data, and returns `structuredContent`, `_meta`, and UI metadata.
3. ChatGPT loads the HTML template linked in the tool descriptor (served as `text/html+skybridge`) and injects the payload through `window.openai`.
4. The widget renders from `window.openai.toolOutput`, persists UI state with `window.openai.setWidgetState`, and can call tools again via `window.openai.callTool`.
5. The model reads `structuredContent` to narrate what happened, so keep it tight and idempotent—ChatGPT may retry tool calls.

```
User prompt
   ↓
ChatGPT model ──► MCP tool call ──► Your server ──► Tool response (`structuredContent`, `_meta`, `content`)
   │                                                   │
   └───── renders narration ◄──── widget iframe ◄──────┘
                              (HTML template + `window.openai`)
```

## Understand the `window.openai` widget runtime

The sandboxed iframe exposes a single global object:

Key capabilities include:

- **State & data:** `toolInput`, `toolOutput`, `toolResponseMetadata`, and `widgetState` carry tool data and persisted UI state.
- **Tool + messaging APIs:** `callTool` and `sendFollowUpMessage` let the widget invoke tools or post user-authored follow-ups.
- **File handling:** `uploadFile` and `getFileDownloadUrl` cover image uploads and previews.
- **Layout + host controls:** `requestDisplayMode`, `requestModal`, `notifyIntrinsicHeight`, and `openExternal` manage layout and host navigation.
- **Context signals:** `theme`, `displayMode`, `maxHeight`, `safeArea`, `view`, `userAgent`, and `locale` let you adapt UI and copy.

For the full `window.openai` reference, see the [ChatGPT UI guide](https://developers.openai.com/apps-sdk/build/chatgpt-ui#understand-the-windowopenai-api).

Use `requestModal` when you need a host-controlled overlay—for example, open a checkout or detail view anchored to an “Add to cart” button so shoppers can review options without forcing the inline widget to resize. To show a different UI template in the modal, pass the template URI you registered via `registerResource`.

Subscribe to any of these fields with `useOpenAiGlobal` so multiple components stay in sync.

Here's an example React component that reads `toolOutput` and persists UI state with `setWidgetState`:
For more information on how to build your UI, check out the [ChatGPT UI guide](https://developers.openai.com/apps-sdk/build/chatgpt-ui).

```tsx
// Example helper hook that keeps state
// in sync with the widget runtime via window.openai.setWidgetState.


export function KanbanList() {
  const [widgetState, setWidgetState] = useWidgetState(() => ({
    selectedTask: null,
  }));
  const tasks = window.openai.toolOutput?.tasks ?? [];

  return tasks.map((task) => (
    <button
      key={task.id}
      data-selected={widgetState?.selectedTask === task.id}
      onClick={() =>
        setWidgetState((prev) => ({ ...prev, selectedTask: task.id }))
      }
    >
      {task.title}
    </button>
  ));
}
```

If you're not using React, you don’t need a helper like useWidgetState. Vanilla JS widgets can read and write window.openai directly—for example, window.openai.toolOutput or window.openai.setWidgetState(state).

## Pick an SDK

Apps SDK works with any MCP implementation, but the official SDKs are the quickest way to get started. They ship tool/schema helpers, HTTP server scaffolding, resource registration utilities, and end-to-end type safety so you can stay focused on business logic:

- **Python SDK** – Iterate quickly with FastMCP or FastAPI. Repo: [`modelcontextprotocol/python-sdk`](https://github.com/modelcontextprotocol/python-sdk).
- **TypeScript SDK** – Ideal when your stack is already Node/React. Repo: [`modelcontextprotocol/typescript-sdk`](https://github.com/modelcontextprotocol/typescript-sdk), published as `@modelcontextprotocol/sdk`. Docs live on [modelcontextprotocol.io](https://modelcontextprotocol.io/).

Install whichever SDK matches your backend language, then follow the steps below.

```bash
# TypeScript / Node
npm install @modelcontextprotocol/sdk zod

# Python
pip install mcp
```

## Build your MCP server

### Step 1 – Register a component template

Each UI bundle is exposed as an MCP resource whose `mimeType` is `text/html+skybridge`, signaling to ChatGPT that it should treat the payload as a sandboxed HTML entry point and inject the widget runtime. In other words, `text/html+skybridge` marks the file as a widget template instead of generic HTML.

Register the template and include metadata for borders, domains, and CSP rules:

```ts
// Registers the Kanban widget HTML entry point served to ChatGPT.



const server = new McpServer({ name: "kanban-server", version: "1.0.0" });
const HTML = readFileSync("web/dist/kanban.js", "utf8");
const CSS = readFileSync("web/dist/kanban.css", "utf8");

server.registerResource(
  "kanban-widget",
  "ui://widget/kanban-board.html",
  {},
  async () => ({
    contents: [
      {
        uri: "ui://widget/kanban-board.html",
        mimeType: "text/html+skybridge",
        text: `
<div id="kanban-root"></div>
<style>${CSS}</style>
<script type="module">${HTML}</script>
        `.trim(),
        _meta: {
          "openai/widgetPrefersBorder": true,
          "openai/widgetDomain": "https://myapp.example.com",
          "openai/widgetCSP": {
            connect_domains: ["https://api.myapp.example.com"], // example API domain
            resource_domains: ["https://*.oaistatic.com"], // example CDN allowlist
            // Optional: allow embedding specific iframe origins. See “frame_domains” docs.
            frame_domains: ["https://*.example-embed.com"],
          },
        },
      },
    ],
  })
);
```

If you need to embed iframes inside your widget, use `frame_domains` to declare an allowlist of origins. Without `frame_domains` set, subframes are blocked by default. Because iframe content is harder for us to inspect, widgets that set `frame_domains` are reviewed with extra scrutiny and may not be approved for directory distribution.

**Best practice:** When you change your widget’s HTML/JS/CSS in a breaking way, give the template a new URI (or use a new file name) so ChatGPT always loads the updated bundle instead of a cached one.

Treat the URI as your cache key. When you update the markup or bundle, version the URI and update every reference to it (for example, the `registerResource` URI, `_meta["openai/outputTemplate"]` in your tool descriptor, and the `contents[].uri` in your template list). A simple pattern is to add a version suffix:

```ts
// Old
contents: [{ uri: "ui://widget/kanban-board.html" /* ... */ }];
// New
contents: [{ uri: "ui://widget/kanban-board-v2.html" /* ... */ }];
```

If you ship updates frequently, keep a short, consistent versioning scheme so you can roll forward (or back) without reusing the same URI.

### Step 2 – Describe tools

Tools are the contract the model reasons about. Define one tool per user intent (e.g., `list_tasks`, `update_task`). Each descriptor should include:

- Machine-readable name and human-readable title.
- JSON schema for arguments (`zod`, JSON Schema, or dataclasses).
- `_meta["openai/outputTemplate"]` pointing to the template URI.
- Optional `_meta` for invoking/invoked strings, `widgetAccessible`, read-only hints, etc.

_The model inspects these descriptors to decide when a tool fits the user’s request, so treat names, descriptions, and schemas as part of your UX._

Design handlers to be **idempotent**—the model may retry calls.

```ts
// Example app that exposes a kanban-board tool with schema, metadata, and handler.


server.registerTool(
  "kanban-board",
  {
    title: "Show Kanban Board",
    inputSchema: { workspace: z.string() },
    _meta: {
      "openai/outputTemplate": "ui://widget/kanban-board.html",
      "openai/toolInvocation/invoking": "Preparing the board…",
      "openai/toolInvocation/invoked": "Board ready.",
    },
  },
  async ({ workspace }) => {
    const board = await loadBoard(workspace);
    return {
      structuredContent: board.summary,
      content: [{ type: "text", text: `Showing board ${workspace}` }],
      _meta: board.details,
    };
  }
);
```

#### Memory and tool calls

Memory is user-controlled and model-mediated: the model decides if and how to use it when selecting or parameterizing a tool call. By default, memories are turned off with apps. Users can enable or disable memory for an app. Apps do not receive a separate memory feed; they only see whatever the model includes in tool inputs. When memory is off, a request is re-evaluated without memory in the model context.

<img src="https://developers.openai.com/images/apps-sdk/memories.png"
  alt="Memory settings in ChatGPT"
  class="w-full max-w-xl mx-auto rounded-lg"
/>

**Best practices**

- Keep tool inputs explicit and required for correctness; do not rely on memory for critical fields.
- Treat memory as a hint, not authority; confirm user preferences when it is important to your user flow and may have side effects
- Provide safe defaults or ask a follow-up question when context is missing.
- Make tools resilient to retries or re-evaluation or missing memories
- For write or destructive actions, re-confirm intent and key parameters in the current turn.

### Step 3 – Return structured data and metadata

Every tool response can include three sibling payloads:

- **`structuredContent`** – concise JSON the widget uses _and_ the model reads. Include only what the model should see.
- **`content`** – optional narration (Markdown or plaintext) for the model’s response.
- **`_meta`** – large or sensitive data exclusively for the widget. `_meta` never reaches the model.

```ts
// Returns concise structuredContent for the model plus rich _meta for the widget.
async function loadKanbanBoard(workspace: string) {
  const tasks = await db.fetchTasks(workspace);
  return {
    structuredContent: {
      columns: ["todo", "in-progress", "done"].map((status) => ({
        id: status,
        title: status.replace("-", " "),
        tasks: tasks.filter((task) => task.status === status).slice(0, 5),
      })),
    },
    content: [
      {
        type: "text",
        text: "Here's the latest snapshot. Drag cards in the widget to update status.",
      },
    ],
    _meta: {
      tasksById: Object.fromEntries(tasks.map((task) => [task.id, task])),
      lastSyncedAt: new Date().toISOString(),
    },
  };
}
```

The widget reads those payloads through `window.openai.toolOutput` and `window.openai.toolResponseMetadata`, while the model only sees `structuredContent`/`content`.

### Step 4 – Run locally

1. Build your UI bundle (`npm run build` inside `web/`).
2. Start the MCP server (Node, Python, etc.).
3. Use [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) early and often to call `http://localhost:<port>/mcp`, list roots, and verify your widget renders correctly. Inspector mirrors ChatGPT’s widget runtime and catches issues before deployment.

For a TypeScript project, that usually looks like:

```bash
npm run build       # compile server + widget
node dist/index.js  # start the compiled MCP server
```

### Step 5 – Expose an HTTPS endpoint

ChatGPT requires HTTPS. During development, tunnel localhost with ngrok (or similar):

```bash
ngrok http <port>
# Forwarding: https://<subdomain>.ngrok.app -> http://127.0.0.1:<port>
```

Use the ngrok URL when creating a connector in ChatGPT developer mode. For production, deploy to a low-latency HTTPS host (Cloudflare Workers, Fly.io, Vercel, AWS, etc.).

## Example

Here’s a stripped-down TypeScript server plus vanilla widget. For full projects, reference the public [Apps SDK examples](https://github.com/openai/openai-apps-sdk-examples).

```ts
// server/src/index.ts


const server = new McpServer({ name: "hello-world", version: "1.0.0" });

server.registerResource("hello", "ui://widget/hello.html", {}, async () => ({
  contents: [
    {
      uri: "ui://widget/hello.html",
      mimeType: "text/html+skybridge",
      text: `
<div id="root"></div>
<script type="module" src="https://example.com/hello-widget.js"></script>
      `.trim(),
    },
  ],
}));

server.registerTool(
  "hello_widget",
  {
    title: "Show hello widget",
    inputSchema: { name: { type: "string" } },
    _meta: { "openai/outputTemplate": "ui://widget/hello.html" },
  },
  async ({ name }) => ({
    structuredContent: { message: `Hello ${name}!` },
    content: [{ type: "text", text: `Greeting ${name}` }],
    _meta: {},
  })
);
```

```js
// hello-widget.js
const root = document.getElementById("root");
const { message } = window.openai.toolOutput ?? { message: "Hi!" };
root.textContent = message;
```

## Troubleshooting

- **Widget doesn’t render** – Ensure the template resource returns `mimeType: "text/html+skybridge"` and that the bundled JS/CSS URLs resolve inside the sandbox.
- **`window.openai` is undefined** – The host only injects the widget runtime for `text/html+skybridge` templates; double-check the MIME type and that the widget loaded without CSP violations.
- **CSP or CORS failures** – Use `openai/widgetCSP` to allow the exact domains you fetch from; the sandbox blocks everything else.
- **Stale bundles keep loading** – Cache-bust template URIs or file names whenever you deploy breaking changes.
- **Structured payloads are huge** – Trim `structuredContent` to what the model truly needs; oversized payloads degrade model performance and slow rendering.

## Advanced capabilities

### Component-initiated tool calls

Set `_meta["openai/widgetAccessible"]` on the tool descriptor to `true` if the widget should call tools on its own (e.g., refresh data on a button click). That opt-in enables `window.openai.callTool`.

```json
"_meta": {
  "openai/outputTemplate": "ui://widget/kanban-board.html",
  "openai/widgetAccessible": true
}
```

#### Tool visibility

Set `_meta["openai/visibility"]` on the tool descriptor to `"private"` when a tool should be callable from your widget but hidden from the model. This helps avoid awkward prompts or unsafe UX. Visibility defaults to `"public"`; private tools still work with `window.openai.callTool`.

```json
"_meta": {
  "openai/outputTemplate": "ui://widget/kanban-board.html",
  "openai/widgetAccessible": true,
  "openai/visibility": "private"
}
```

### Tool annotations and elicitation

MCP tools can include [`tool annotations`](https://modelcontextprotocol.io/legacy/concepts/tools#tool-annotations) that describe the tool’s _potential impact_. ChatGPT uses these hints to classify tools and decide when to ask the user for confirmation (elicitation) before using the tool.

The three hints we look at are:

- `readOnlyHint`: Set to `true` for tools that only retrieve or compute information and do not create, update, delete, or send data outside of ChatGPT (search, lookups, previews).
- `openWorldHint`: Set to `false` for tools that only affect a bounded target (for example, “update a task by id” in your own product). Leave `true` for tools that can write to arbitrary URLs/files/resources.
- `destructiveHint`: Set to `true` for tools that can delete, overwrite, or have irreversible side effects.

`openWorldHint` and `desctructiveHint` are only considered for writes (i.e. when `readOnlyHint=false`).

Read only tools do not require elication. Destructive writes do not require elicitation. Only open world writes require elicitation. This distinctation is done so only the most impactful writes (open world) will need elicitation.

If you omit these hints (or leave them as `null`), ChatGPT defaults to the “worst case”: `readOnlyHint=false`, `openWorldHint=true`, and `destructiveHint=true`. This means with the hints are ommited, the tool will be an open world destructive write which will require elicitation.

Example tool descriptor:

```json
{
  "name": "update_task",
  "title": "Update task",
  "annotations": {
    "readOnlyHint": false,
    "openWorldHint": false,
    "destructiveHint": false
  }
}
```

### Files out (file params)

If your tool accepts user-provided files, declare file parameters with `_meta["openai/fileParams"]`. The value is a list of top-level input schema fields that should be treated as files. Nested file fields are not supported.

Each file param must be an object with this shape:

```json
{
  "download_url": "https://...",
  "file_id": "file_..."
}
```

Example:

```ts
server.registerTool(
  "process_image",
  {
    title: "process_image",
    description: "Processes an image",
    inputSchema: {
      type: "object",
      properties: {
        imageToProcess: {
          type: "object",
          properties: {
            download_url: { type: "string" },
            file_id: { type: "string" },
          },
          required: ["download_url", "file_id"],
          additionalProperties: false,
        },
      },
      required: ["imageToProcess"],
      additionalProperties: false,
    },
    _meta: {
      "openai/outputTemplate": "ui://widget/widget.html",
      "openai/fileParams": ["imageToProcess"],
    },
  },
  async ({ imageToProcess }) => {
    return {
      content: [],
      structuredContent: {
        download_url: imageToProcess.download_url,
        file_id: imageToProcess.file_id,
      },
    };
  }
);
```

### Content security policy (CSP)

Set `_meta["openai/widgetCSP"]` on the widget resource so the sandbox knows which domains to allow for `connect-src`, `img-src`, `frame-src`, etc. This is required before broad distribution.

```json
"_meta": {
  "openai/widgetCSP": {
    connect_domains: ["https://api.example.com"],
    resource_domains: ["https://persistent.oaistatic.com"],
    redirect_domains: ["https://checkout.example.com"],
    frame_domains: ["https://*.example-embed.com"]
  }
}
```

- `connect_domains` – hosts your widget can fetch from.
- `resource_domains` – hosts for static assets like images, fonts, and scripts.
- `redirect_domains` – optional; hosts allowed to receive `openExternal` redirects without the safe-link modal. ChatGPT appends a `redirectUrl` query parameter to help external flows return to the conversation.
- `frame_domains` – optional; hosts your widget may embed as iframes. Widgets without `frame_domains` cannot render subframes.

Caution: Using `frame_domains` is discouraged and should only be done when embedding iframes is core to your experience (for example, a code editor or notebook environment). Apps that declare `frame_domains` are subject to higher scrutiny at review time and are likely to be rejected or held back from broad distribution.

### Widget domains

Set `_meta["openai/widgetDomain"]` on the widget resource template (the `registerResource` template). This is required for app submission and must be unique per app. ChatGPT renders the widget under `<domain>.web-sandbox.oaiusercontent.com`, which also enables the fullscreen punch-out button.

```json
"_meta": {
  "openai/widgetCSP": {
    connect_domains: ["https://api.example.com"],
    resource_domains: ["https://persistent.oaistatic.com"]
  },
  "openai/widgetDomain": "https://myapp.example.com"
}
```

### Component descriptions

Set `_meta["openai/widgetDescription"]` on the widget resource to let the widget describe itself, reducing redundant text beneath the widget.

```json
"_meta": {
  "openai/widgetCSP": {
    connect_domains: ["https://api.example.com"],
    resource_domains: ["https://persistent.oaistatic.com"]
  },
  "openai/widgetDomain": "https://myapp.example.com",
  "openai/widgetDescription": "Shows an interactive zoo directory rendered by get_zoo_animals."
}
```

### Localized content

ChatGPT sends the requested locale in `_meta["openai/locale"]` (with `_meta["webplus/i18n"]` as a legacy key) in the client request. Use RFC 4647 matching to select the closest supported locale, echo it back in your responses, and format numbers/dates accordingly.

### Client context hints

ChatGPT may also send hints in the client request metadata like `_meta["openai/userAgent"]` and `_meta["openai/userLocation"]`. These can be helpful for tailoring analytics or formatting, but **never** rely on them for authorization.

Once your templates, tools, and widget runtime are wired up, the fastest way to refine your app is to use ChatGPT itself: call your tools in a real conversation, watch your logs, and debug the widget with browser devtools. When everything looks good, put your MCP server behind HTTPS and your app is ready for users.

## Company knowledge compatibility

[Company knowledge in ChatGPT](https://openai.com/index/introducing-company-knowledge/) (Business, Enterprise, and Edu) can call any **read-only** tool in your app. It biases toward `search`/`fetch`, and only apps that implement the `search` and `fetch` tool input signatures are included as company knowledge sources. These are the same tool shapes required for connectors and deep research (see the [MCP docs](https://platform.openai.com/docs/mcp)).

In practice, you should:

- Implement [search](https://platform.openai.com/docs/mcp#search-tool) and [fetch](https://platform.openai.com/docs/mcp#fetch-tool) input schemas exactly to the MCP schema. Company knowledge compatibility checks the input parameters only.
- Mark other read-only tools with `readOnlyHint: true` so ChatGPT can safely call them.

To opt in, implement `search` and `fetch` using the MCP schema and return canonical `url` values for citations. For eligibility, admin enablement, and availability details, see [Company knowledge in ChatGPT](https://help.openai.com/en/articles/12628342/) and the MCP tool schema in [Building MCP servers](https://platform.openai.com/docs/mcp).

While compatibility checks focus on the input schema, you should still return the recommended result shapes for [search](https://platform.openai.com/docs/mcp#search-tool) and [fetch](https://platform.openai.com/docs/mcp#fetch-tool) so ChatGPT can cite sources reliably. The `text` fields are JSON-encoded strings in your tool response.

**Search result shape (tool payload before MCP wrapping):**

```json
{
  "results": [
    {
      "id": "doc-1",
      "title": "Human-readable title",
      "url": "https://example.com"
    }
  ]
}
```

Fields:

- `results` - array of search results.
- `results[].id` - unique ID for the document or item.
- `results[].title` - human-readable title.
- `results[].url` - canonical URL for citation.

In MCP, the tool response **wraps** this JSON inside a `content` array. For `search`, return exactly one content item with `type: "text"` and `text` set to the JSON string above:

**Search tool response wrapper (MCP content array):**

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"results\":[{\"id\":\"doc-1\",\"title\":\"Human-readable title\",\"url\":\"https://example.com\"}]}"
    }
  ]
}
```

**Fetch result shape (tool payload before MCP wrapping):**

```json
{
  "id": "doc-1",
  "title": "Human-readable title",
  "text": "Full text of the document",
  "url": "https://example.com",
  "metadata": { "source": "optional key/value pairs" }
}
```

Fields:

- `id` - unique ID for the document or item.
- `title` - human-readable title.
- `text` - full text of the document or item.
- `url` - canonical URL for citation.
- `metadata` - optional key/value pairs about the result.

For `fetch`, wrap the document JSON the same way:

**Fetch tool response wrapper (MCP content array):**

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"id\":\"doc-1\",\"title\":\"Human-readable title\",\"text\":\"Full text of the document\",\"url\":\"https://example.com\",\"metadata\":{\"source\":\"optional key/value pairs\"}}"
    }
  ]
}
```

Here is a minimal TypeScript example showing the `search` and `fetch` tools:

```ts



const server = new McpServer({ name: "acme-knowledge", version: "1.0.0" });

server.registerTool(
  "search",
  {
    title: "Search knowledge",
    inputSchema: { query: z.string() },
    annotations: { readOnlyHint: true },
  },
  async ({ query }) => ({
    content: [
      {
        type: "text",
        text: JSON.stringify({
          results: [
            { id: "doc-1", title: "Overview", url: "https://example.com" },
          ],
        }),
      },
    ],
  })
);

server.registerTool(
  "fetch",
  {
    title: "Fetch document",
    inputSchema: { id: z.string() },
    annotations: { readOnlyHint: true },
  },
  async ({ id }) => ({
    content: [
      {
        type: "text",
        text: JSON.stringify({
          id,
          title: "Overview",
          text: "Full text...",
          url: "https://example.com",
          metadata: { source: "acme" },
        }),
      },
    ],
  })
);
```

## Security reminders

- Treat `structuredContent`, `content`, `_meta`, and widget state as user-visible—never embed API keys, tokens, or secrets.
- Do not rely on `_meta["openai/userAgent"]`, `_meta["openai/locale"]`, or other hints for authorization; enforce auth inside your MCP server and backing APIs.
- Avoid exposing admin-only or destructive tools unless the server verifies the caller’s identity and intent.
