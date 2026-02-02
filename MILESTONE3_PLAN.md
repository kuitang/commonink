# Milestone 3: Rate Limiting + Public Notes + Web UI

**Goal**: Implement rate limiting, public note publishing, complete web interface with Tailwind CSS, and OAuth consent screens. Everything needed before signing up for real external services.

**Prerequisites**: Milestone 2 complete (auth with mocks + envelope encryption)

**Key Principles**:
- **Tailwind CSS** for styling (via CDN, no build step)
- **Minimal JavaScript** - only where absolutely required (e.g., form validation)
- **Server-rendered HTML** - Go templates, no SPA framework
- Use **frontend-design skill** for UI implementation

---

## Implementation DAG

```
                           [Milestone 2 Complete]
                           (Auth + Encryption)
                                    │
    ┌────────────────┬──────────────┼──────────────┬───────────────────┐
    │                │              │              │                   │
[Rate Limiter] [ObjectStorage  [Markdown     [Public Notes   [OAuth Consent
               Interface+Mock]  Renderer]     Logic]          Logic]
    │                │              │              │                   │
    └────────────────┴──────────────┼──────────────┴───────────────────┘
                                    │
                        [Rate Limit Middleware]
                        [Sessions DB Queries]
                                    │
              ┌─────────────────────┼─────────────────────────┐
              │                     │                         │
      [Web UI: Auth Pages]  [Web UI: Notes Pages]  [Web UI: OAuth Consent]
              │                     │                         │
              └─────────────────────┼─────────────────────────┘
                                    │
                            [Tailwind Styling]
                            (frontend-design skill)
                                    │
                          [Wire into main.go]
                          (inject MockObjectStorage)
                                    │
                ┌───────────────────┼───────────────────────────┐
                │                   │                           │
        [Rate Limit Tests]  [Public Notes Tests]  [Playwright Browser Tests]
                │                   │                           │
                └───────────────────┼───────────────────────────┘
                                    │
                          [Master Test Script]
                                    │
                                [Commit]

Note: TigrisStorage implementation deferred to deployment (see DEPLOYMENT_ARCHITECTURE.md)
```

---

## Tasks (Topologically Sorted for Parallel Execution)

### Layer 0: Prerequisites
- [x] Milestone 2 complete (auth + encryption working)
- [x] Multi-user support working
- [x] Mock auth flows tested

### Layer 1 (Parallel - No Dependencies)

**Reference**: See `DEPLOYMENT_ARCHITECTURE.md` for comprehensive details on:
- Tigris global object storage architecture
- Local development with MinIO (Docker)
- URL structure and SEO
- Production deployment to Fly.io
- Cost breakdown

1. **Rate Limiter** (`internal/ratelimit/limiter.go`)
   - Use `golang.org/x/time/rate` (stdlib)
   - `RateLimiter` struct:
     ```go
     type RateLimiter struct {
         limiters map[string]*rateLimiterEntry
         mu       sync.RWMutex
         config   Config
     }

     type rateLimiterEntry struct {
         limiter  *rate.Limiter
         lastUsed time.Time
     }

     type Config struct {
         FreeRPS      float64  // 10 req/sec for free tier
         FreeBurst    int      // 20 burst
         PaidRPS      float64  // 1000 req/sec for paid
         PaidBurst    int      // 2000 burst
         CleanupInterval time.Duration  // 1 hour
     }
     ```
   - `NewRateLimiter(config)` - Constructor
   - `Allow(userID, isPaid)` - Check if request allowed
   - `GetLimiter(userID, isPaid)` - Get or create limiter
   - `Cleanup()` - Remove idle limiters (background goroutine)
   - Per-user rate limiting (not per-IP)

2. **Public Notes Storage Interface** (`internal/storage/`)

   **Following M2/M4 dependency injection pattern:**

   - `service.go` - Interface:
     ```go
     type ObjectStorage interface {
         // PutObject uploads content with content-type
         PutObject(ctx context.Context, key string, content []byte, contentType string) error
         // GetObject retrieves content
         GetObject(ctx context.Context, key string) ([]byte, error)
         // DeleteObject removes content
         DeleteObject(ctx context.Context, key string) error
         // GetPublicURL returns the publicly accessible URL
         GetPublicURL(key string) string
     }
     ```

   - `mock.go` - Mock implementation (for M3 tests):
     ```go
     type MockObjectStorage struct {
         mu      sync.RWMutex
         Objects map[string][]byte
         BaseURL string  // e.g., "http://localhost:8080/public"
     }
     func NewMockObjectStorage(baseURL string) *MockObjectStorage
     func (m *MockObjectStorage) PutObject(ctx, key, content, contentType) error
     func (m *MockObjectStorage) GetObject(ctx, key) ([]byte, error)
     func (m *MockObjectStorage) DeleteObject(ctx, key) error
     func (m *MockObjectStorage) GetPublicURL(key string) string
     ```

   - `tigris.go` - Real Tigris/S3 implementation (deferred to M4/deployment):
     ```go
     type TigrisStorage struct {
         client     *s3.Client
         bucketName string
         publicURL  string  // e.g., "https://notes.domain.com"
     }
     func NewTigrisStorage(endpoint, accessKey, secretKey, bucket, publicURL string) (*TigrisStorage, error)
     ```

3. **Public Notes Logic** (`internal/notes/public.go`)
   - Add to notes service:
     - `SetPublic(noteID, isPublic)` - Toggle flag + upload/delete from storage
     - `GetPublic(noteID)` - Get note if public (no auth required)
     - `ListPublicByUser(userID)` - List user's public notes
   - Public note URL: `/public/{user_id}/{note_id}`
   - Update DB schema if needed (is_public flag already in spec)

4. **Markdown Renderer** (`internal/notes/render.go`)
   - `RenderMarkdownToHTML(markdown, title, description, canonicalURL) []byte`
   - Uses `github.com/gomarkdown/markdown`
   - Includes SEO meta tags:
     - Open Graph (og:title, og:description, og:url)
     - Twitter Cards
     - Canonical URL
   - Minimal CSS inline (no external dependencies)

5. **OAuth Consent Logic** (`internal/auth/consent.go`)
   - For OAuth 2.1 provider (AI clients connecting to us)
   - `ConsentService` struct:
     - `GetPendingConsent(userID, clientID)` - Check if consent needed
     - `RecordConsent(userID, clientID, scopes)` - Store consent
     - `HasConsent(userID, clientID, scopes)` - Check existing consent
   - Consent stored in sessions.db
   - Required for Milestone 5 (OAuth provider) but UI built now

### Layer 2 (Depends on Layer 1)

6. **Rate Limit Middleware** (`internal/ratelimit/middleware.go`)
   - `RateLimitMiddleware(limiter, getUserID, getIsPaid)`
   - Returns 429 Too Many Requests when limit exceeded
   - Includes `Retry-After` header
   - Includes `X-RateLimit-Remaining` header
   - Different limits for free vs paid (check user subscription status)

7. **Sessions DB Queries for Consent** (`internal/db/sql/sessions_consent.sql`)
   - `CreateConsent(user_id, client_id, scopes, granted_at)`
   - `GetConsent(user_id, client_id)`
   - `DeleteConsent(user_id, client_id)`
   - `ListConsentsForUser(user_id)`

### Layer 3 (Depends on Layer 2) - Web UI

**NOTE**: Use `frontend-design` skill for all UI templates. Provide these requirements:
- Tailwind CSS via CDN
- Minimal/no JavaScript
- Clean, modern design
- Mobile responsive
- Dark mode support (via Tailwind)

8. **Web UI: Auth Pages** (`web/templates/auth/`)
   - `login.html` - All three login options:
     - "Sign in with Google" button
     - Email + "Send Magic Link" form
     - Email + Password + "Sign In" form
     - Link to register
   - `register.html` - Registration form:
     - Email + Password + Confirm Password
     - Password requirements shown
   - `magic_sent.html` - Confirmation:
     - "Check your email" message
     - Email address shown
     - "Didn't receive? Resend" link
   - `password_reset.html` - Request reset form
   - `password_reset_confirm.html` - New password form
   - `error.html` - Auth error display

9. **Web UI: Notes Pages** (`web/templates/notes/`)
   - `list.html` - Notes list:
     - Note title + preview
     - Created/updated timestamps
     - Public/private badge
     - Pagination
     - "New Note" button
   - `view.html` - Single note:
     - Title + content (rendered markdown?)
     - Edit button (if owner)
     - Public/private toggle
     - Share link (if public)
     - Delete button
   - `edit.html` - Edit/create note:
     - Title input
     - Content textarea
     - Save/Cancel buttons
   - `public_view.html` - Public note view (no auth required):
     - Note content
     - Author attribution
     - "View more from this author" link

10. **Web UI: OAuth Consent** (`web/templates/oauth/`)
   - `consent.html` - OAuth consent screen:
     - App name + icon (from client registration)
     - Requested scopes with descriptions:
       - `notes:read` - "View your notes"
       - `notes:write` - "Create and edit notes"
     - "Allow" / "Deny" buttons
     - "This app will be able to..." explanation
   - `consent_denied.html` - User denied consent
   - `consent_granted.html` - Success, redirecting...

11. **Base Template** (`web/templates/base.html`)
   - Tailwind CSS CDN include
   - Navigation header:
     - Logo/app name
     - User dropdown (if logged in): email, logout
     - Login button (if not logged in)
   - Footer with links
   - Mobile hamburger menu

### Layer 4 (Depends on Layer 3)

12. **Template Renderer** (`internal/web/render.go`)
    - `Renderer` struct with template cache
    - `NewRenderer(templatesDir)` - Parse all templates
    - `Render(w, templateName, data)` - Execute template
    - `RenderError(w, code, message)` - Error page
    - Template functions:
      - `formatTime(t time.Time)` - Human-readable dates
      - `truncate(s string, n int)` - Preview text
      - `markdown(s string)` - Render markdown (optional)

13. **Web Handlers** (`internal/web/handlers.go`)
    - `WebHandler` struct: renderer, notesService, authService
    - **Landing**:
      - `GET /` - If logged in → notes list, else → login
    - **Notes CRUD** (HTML responses):
      - `GET /notes` - List notes page
      - `GET /notes/new` - New note form
      - `POST /notes` - Create note (form submit)
      - `GET /notes/{id}` - View note page
      - `GET /notes/{id}/edit` - Edit note form
      - `POST /notes/{id}` - Update note (form submit)
      - `POST /notes/{id}/delete` - Delete note
      - `POST /notes/{id}/publish` - Toggle public
    - **Public Notes**:
      - `GET /public/{user_id}/{note_id}` - View public note (no auth)
    - **OAuth Consent**:
      - `GET /oauth/consent` - Show consent screen
      - `POST /oauth/consent` - Process consent decision

### Layer 5 (Depends on Layer 4)

14. **Update main.go**
    - Initialize rate limiter with config
    - Add rate limit middleware to API routes
    - Initialize template renderer
    - **Initialize ObjectStorage (M2/M4 DI pattern)**:
      ```go
      var objectStore storage.ObjectStorage
      if cfg.UseMockStorage {
          objectStore = storage.NewMockObjectStorage(cfg.PublicNotesURL)
      } else {
          objectStore, err = storage.NewTigrisStorage(
              cfg.S3Endpoint,
              cfg.S3AccessKey,
              cfg.S3SecretKey,
              cfg.S3Bucket,
              cfg.PublicNotesURL,
          )
      }
      ```
    - Register web routes
    - Mount static files if any
    - Configure routes:
      - `/` - Landing
      - `/login`, `/register`, etc. - Auth pages
      - `/notes/*` - Notes web UI
      - `/public/*` - Public notes (serves from ObjectStorage or fallback)
      - `/oauth/consent` - OAuth consent
      - `/api/*` - JSON API (existing, rate limited)
      - `/mcp` - MCP server (existing, rate limited)

### Layer 6 (Parallel, Depends on Layer 5)

15. **Rate Limit Property Tests** (`internal/ratelimit/*_test.go`)
    - Property: Requests within limit succeed
    - Property: Requests exceeding limit return 429
    - Property: Different users have independent limits
    - Property: Paid users have higher limits
    - Property: Idle limiters cleaned up

16. **Public Notes Property Tests** (`internal/notes/public_test.go`)
    - Property: Public note accessible without auth
    - Property: Private note requires auth
    - Property: Owner can toggle public/private
    - Property: Non-owner cannot toggle
    - Property: Markdown renders to valid HTML with SEO tags

17. **Playwright Browser Tests** (`tests/browser/`)
    - `auth_flow_test.go` - Login/register/logout flows
    - `notes_crud_test.go` - Create/edit/delete notes via UI
    - `public_notes_test.go` - Public note viewing
    - `oauth_consent_test.go` - Consent screen flow
    - `rate_limit_test.go` - Verify 429 on rate limit
    - Use mock auth (from M2)

### Layer 7 (Depends on Layer 6)

18. **Master Test Script** (`scripts/milestone3-test.sh`)
    - Build server
    - Run rate limit tests
    - Run public notes tests
    - Run Playwright browser tests
    - Run accessibility check (optional: axe-core)
    - Verify all pass

---

## Web UI Design Requirements (for frontend-design skill)

### Style Guide
```
Colors (Tailwind):
- Primary: blue-600 (buttons, links)
- Background: white / gray-50
- Text: gray-900 / gray-600
- Error: red-600
- Success: green-600
- Dark mode: Toggle-able

Typography:
- Headings: font-bold, text-gray-900
- Body: text-gray-600
- Code/notes: font-mono (optional)

Spacing:
- Consistent p-4, p-6, p-8
- Cards with rounded-lg, shadow

Components:
- Buttons: rounded, hover states
- Forms: labeled inputs, validation states
- Cards: for notes list items
- Alerts: success/error/info
```

### Page Requirements

**Login Page**:
- Centered card on light background
- Three sections (tabs or stacked):
  1. Google button (prominent)
  2. Magic link form
  3. Password form
- "Don't have an account? Register" link

**Notes List**:
- Header with "My Notes" title + "New Note" button
- Grid or list of note cards
- Each card: title, preview, date, public badge
- Pagination at bottom
- Empty state: "No notes yet. Create your first note!"

**OAuth Consent**:
- App logo/name centered
- "APP_NAME wants to access your notes" heading
- Scope list with checkmarks
- Allow (primary) + Deny (secondary) buttons
- "You can revoke access anytime in settings"

---

## Expected File Structure

```
/home/kuitang/git/agent-notes/
├── internal/
│   ├── ratelimit/
│   │   ├── limiter.go          # Rate limiter implementation
│   │   ├── middleware.go       # HTTP middleware
│   │   └── limiter_test.go     # Property tests
│   ├── storage/                 # Object storage (M2/M4 DI pattern)
│   │   ├── service.go          # ObjectStorage interface
│   │   ├── mock.go             # Mock implementation (in-memory)
│   │   └── tigris.go           # Real Tigris/S3 (deferred to deployment)
│   ├── notes/
│   │   ├── public.go           # Public notes logic
│   │   └── render.go           # Markdown → HTML with SEO
│   ├── auth/
│   │   └── consent.go          # OAuth consent service
│   ├── web/
│   │   ├── render.go           # Template renderer
│   │   └── handlers.go         # Web page handlers
│   └── db/
│       └── sql/
│           └── sessions_consent.sql
├── web/
│   ├── templates/
│   │   ├── base.html           # Base layout with Tailwind
│   │   ├── auth/
│   │   │   ├── login.html
│   │   │   ├── register.html
│   │   │   ├── magic_sent.html
│   │   │   ├── password_reset.html
│   │   │   └── error.html
│   │   ├── notes/
│   │   │   ├── list.html
│   │   │   ├── view.html
│   │   │   ├── edit.html
│   │   │   └── public_view.html
│   │   └── oauth/
│   │       ├── consent.html
│   │       └── consent_denied.html
│   └── static/               # Minimal static assets if needed
│       └── favicon.ico
├── tests/
│   └── browser/
│       ├── auth_flow_test.go
│       ├── notes_crud_test.go
│       ├── public_notes_test.go
│       └── oauth_consent_test.go
└── scripts/
    └── milestone3-test.sh
```

---

## Rate Limiting Configuration

```go
// Default config (can be overridden via env)
var DefaultConfig = Config{
    FreeRPS:         10,     // 10 requests/second
    FreeBurst:       20,     // Allow burst of 20
    PaidRPS:         1000,   // Effectively unlimited
    PaidBurst:       2000,
    CleanupInterval: time.Hour,
}

// Per-endpoint overrides (optional)
var EndpointLimits = map[string]float64{
    "/auth/magic":    1,    // 1 req/sec for magic link (prevent spam)
    "/auth/register": 0.1,  // 1 req/10sec for registration
    "/notes/search":  5,    // 5 req/sec for search
}
```

---

## Environment Variables

**New for Milestone 3**:
```bash
# Rate limiting (optional, has defaults)
RATE_LIMIT_FREE_RPS=10
RATE_LIMIT_FREE_BURST=20
RATE_LIMIT_PAID_RPS=1000
RATE_LIMIT_PAID_BURST=2000
RATE_LIMIT_CLEANUP_INTERVAL=1h

# Object Storage (M3 uses mock by default)
USE_MOCK_STORAGE=true                     # true for M3, false for production
PUBLIC_NOTES_URL=http://localhost:8080/public

# Tigris/S3 (only needed when USE_MOCK_STORAGE=false)
# See DEPLOYMENT_ARCHITECTURE.md for production setup
AWS_ENDPOINT_URL_S3=https://fly.storage.tigris.dev
AWS_ACCESS_KEY_ID=<your-tigris-access-key>
AWS_SECRET_ACCESS_KEY=<your-tigris-secret-key>
BUCKET_NAME=agent-notes
```

---

## Success Criteria

### Rate Limiting
- [ ] Free users limited to 10 req/sec
- [ ] Paid users have higher limits
- [ ] 429 returned with Retry-After header
- [ ] Idle limiters cleaned up
- [ ] Per-user (not per-IP) limiting

### Public Notes
- [ ] Notes can be marked public
- [ ] Public notes viewable without auth
- [ ] Public note URL works: `/public/{user_id}/{note_id}`
- [ ] Private notes require auth
- [ ] Owner can toggle public/private
- [ ] Markdown rendered to HTML with SEO meta tags (Open Graph, Twitter Cards)
- [ ] ObjectStorage interface works with MockObjectStorage
- [ ] HTML uploaded/deleted correctly on publish/unpublish

### Web UI
- [ ] All auth pages render correctly
- [ ] Notes CRUD works via web forms
- [ ] OAuth consent screen displays correctly
- [ ] Tailwind CSS styling applied
- [ ] Mobile responsive
- [ ] No JavaScript except where essential

### Browser Tests
- [ ] Playwright tests pass for all flows
- [ ] Tests run with mock auth (no real services)

---

## What's Deferred to Later Milestones

**Milestone 4**: Real Auth Integrations (Google OIDC, Resend Email)
**Milestone 5**: OAuth 2.1 Provider (for AI clients)
**Milestone 6**: Payments (LemonSqueezy)

---

## Using frontend-design Skill

When implementing web templates, invoke the frontend-design skill with:

```
/frontend-design

Create a login page for a notes application with:
- Tailwind CSS (CDN)
- Three login methods: Google OAuth, Magic Link, Email/Password
- Clean, modern design
- Mobile responsive
- Dark mode support
- No JavaScript (server-rendered forms)
```

Repeat for each page type (notes list, note view, OAuth consent, etc.)

---

## Dependencies to Add

```go
// go.mod additions for Milestone 3
require (
    golang.org/x/time v0.5.0               // Rate limiting (stdlib extension)
    github.com/gomarkdown/markdown v0.0.0-20241205020045-f7e15b2f3e62  // Markdown rendering
    github.com/aws/aws-sdk-go-v2/config    // S3 client config (for Tigris)
    github.com/aws/aws-sdk-go-v2/service/s3 // S3 client (for Tigris)
)

// Note: AWS SDK only used by TigrisStorage (deferred to deployment)
// MockObjectStorage has no external dependencies
```

---

## Commands to Execute

```bash
# Initialize goenv
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)"

# No new Go dependencies needed

# Run tests
./scripts/ci.sh quick

# Run Playwright browser tests
./scripts/ci.sh full

# Run master milestone test
./scripts/milestone3-test.sh

# Install Playwright browsers (if not already)
go run github.com/playwright-community/playwright-go/cmd/playwright install chromium
```
