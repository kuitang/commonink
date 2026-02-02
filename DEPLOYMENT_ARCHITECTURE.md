# Fly.io + Tigris Deployment Architecture for Public Markdown Notes

## Executive Summary

This document outlines the architecture for deploying a public Markdown notes service using Fly.io for compute and Tigris for globally distributed object storage with built-in CDN capabilities.

**Key Findings:**
- **Tigris** is S3-compatible object storage with built-in global caching (not a traditional CDN)
- **Pre-rendering** Markdown to HTML on the server is recommended for SEO and performance
- **Local development** should use MinIO as an S3-compatible alternative
- **Cost structure** is highly favorable: $0.02/GB/month storage, no egress fees

---

## 1. Understanding Tigris: Object Storage + CDN Hybrid

### What is Tigris?

Tigris is a **globally distributed, S3-compatible object storage service** built on Fly.io infrastructure. It's not a traditional CDN, but rather object storage with intelligent global caching.

**Key Characteristics:**
- **S3-compatible API**: Drop-in replacement for AWS S3
- **Automatic global distribution**: Objects cached close to users based on traffic patterns
- **Zero-configuration CDN behavior**: No need for separate CDN setup
- **Multi-region writes**: Updates can occur in any region with fast local propagation

### How Tigris Works

1. **Initial Write**: Objects stored close to the region where they're written
2. **First Request**: When requested from another region, object is served and cached locally
3. **Intelligent Caching**: Tigris manages cache based on global traffic patterns
4. **Low Latency**: Small objects accessible at close to Redis speed

### Tigris vs S3 + CloudFront

| Feature | Tigris | S3 + CloudFront |
|---------|--------|-----------------|
| Global Distribution | Automatic | Manual CDN setup required |
| Configuration | Zero-config | CDN configuration needed |
| Multi-region Writes | Yes, any region | Complex replication setup |
| Egress Fees | **$0** | Expensive |
| API | S3-compatible | S3-compatible |
| Ideal Use Cases | Global apps, AI/ML workloads | Traditional web assets |

**Bottom Line**: Tigris eliminates the need for a separate CDN while providing S3 compatibility.

---

## 2. Tigris Integration with Fly.io

### Setup Process

```bash
# Navigate to your app directory
cd /home/kuitang/git/agent-notes

# Create a Tigris bucket (automatically sets environment variables)
fly storage create

# This automatically sets these secrets on your app:
# - AWS_ACCESS_KEY_ID (tid_xxxxxx)
# - AWS_SECRET_ACCESS_KEY (tsec_xxxxxx)
# - BUCKET_NAME
# - AWS_ENDPOINT_URL_S3 (https://fly.storage.tigris.dev)
```

### Authentication

**Credentials Format:**
- Access Key: `tid_xxxxxx`
- Secret Key: `tsec_xxxxxx`
- Endpoint: `https://fly.storage.tigris.dev`

**Access Methods:**
1. **Fly.io Console**: Access via Fly.io button on Tigris login page
2. **CLI**: Manage via `flyctl` commands
3. **Programmatic**: Use AWS SDK with Tigris credentials

### Using Tigris from Go

```go
import (
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    "github.com/aws/aws-sdk-go-v2/aws"
)

// Load configuration from environment variables
cfg, err := config.LoadDefaultConfig(context.TODO(),
    config.WithRegion("auto"), // Tigris uses "auto" region
)

// Override endpoint for Tigris
client := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String(os.Getenv("AWS_ENDPOINT_URL_S3"))
})

// Upload rendered HTML
_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
    Bucket:      aws.String(os.Getenv("BUCKET_NAME")),
    Key:         aws.String("public/user123/note456.html"),
    Body:        bytes.NewReader(htmlContent),
    ContentType: aws.String("text/html; charset=utf-8"),
    CacheControl: aws.String("public, max-age=3600"),
})
```

---

## 3. Markdown Rendering Strategy

### Server-Side vs Client-Side Rendering

**Recommendation: Server-Side Rendering (SSR) with Caching**

| Aspect | Server-Side | Client-Side |
|--------|-------------|-------------|
| **SEO** | Excellent (pre-rendered HTML) | Poor (requires JS execution) |
| **Initial Load** | Fast (HTML ready) | Slow (download + parse + render) |
| **Social Sharing** | Works (Open Graph tags) | Broken (no content for crawlers) |
| **Performance** | High (cached HTML) | Variable (client CPU dependent) |
| **Use Case** | Public notes, documentation | Interactive apps, authenticated UIs |

**Verdict**: For public Markdown notes with SEO requirements, SSR is the clear winner.

### Rendering Workflow

#### Option A: Pre-render and Upload to Tigris (Recommended)

```
User creates/updates note
    ↓
Go app receives Markdown
    ↓
Render to HTML (server-side with markdown library)
    ↓
Add SEO meta tags (Open Graph, Twitter Cards)
    ↓
Upload HTML to Tigris: /public/{user_id}/{note_id}.html
    ↓
Return public URL: https://notes.domain.com/{user_id}/{note_id}
```

**Advantages:**
- Fastest delivery (pre-rendered HTML served from Tigris cache)
- No server compute on each request
- Automatic global CDN via Tigris
- Best SEO

**Disadvantages:**
- Storage cost for each rendered note (minimal: $0.02/GB/month)
- Stale cache if Markdown rendering library updates

#### Option B: Render On-Demand with Caching

```
User requests note URL
    ↓
Go app checks Tigris for cached HTML
    ↓
If cached: serve from Tigris
    ↓
If not cached:
  1. Fetch Markdown from database
  2. Render to HTML
  3. Add meta tags
  4. Upload to Tigris
  5. Serve to user
```

**Advantages:**
- No stale cache issues
- Storage only for accessed notes
- Can regenerate on library updates

**Disadvantages:**
- First request has higher latency (render time)
- Requires server compute on cache misses

### Recommended Hybrid Approach

**Best of Both Worlds:**

1. **Pre-render on note creation/update** → Upload to Tigris
2. **Serve from Tigris** for all requests (cached globally)
3. **Cache invalidation**: Delete from Tigris when note is edited
4. **Background job**: Regenerate all HTML if rendering library updates

### Go Implementation Example

```go
package notes

import (
    "bytes"
    "context"
    "github.com/gomarkdown/markdown"
    "github.com/gomarkdown/markdown/html"
    "github.com/gomarkdown/markdown/parser"
)

// RenderMarkdownToHTML converts Markdown to HTML with SEO tags
func RenderMarkdownToHTML(md, title, description, canonicalURL string) []byte {
    // Parse Markdown
    extensions := parser.CommonExtensions | parser.AutoHeadingIDs
    p := parser.NewWithExtensions(extensions)
    doc := p.Parse([]byte(md))

    // Render HTML
    htmlFlags := html.CommonFlags | html.HrefTargetBlank
    opts := html.RendererOptions{Flags: htmlFlags}
    renderer := html.NewRenderer(opts)
    bodyHTML := markdown.Render(doc, renderer)

    // Build complete HTML document with SEO tags
    var buf bytes.Buffer
    buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>` + title + `</title>
    <meta name="description" content="` + description + `">
    <link rel="canonical" href="` + canonicalURL + `">

    <!-- Open Graph -->
    <meta property="og:type" content="article">
    <meta property="og:title" content="` + title + `">
    <meta property="og:description" content="` + description + `">
    <meta property="og:url" content="` + canonicalURL + `">
    <meta property="og:image" content="https://notes.domain.com/og-default.png">

    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="` + title + `">
    <meta name="twitter:description" content="` + description + `">

    <style>
        body { max-width: 800px; margin: 40px auto; padding: 0 20px; font-family: system-ui; }
        pre { background: #f4f4f4; padding: 15px; overflow-x: auto; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
`)
    buf.Write(bodyHTML)
    buf.WriteString(`
</body>
</html>`)

    return buf.Bytes()
}

// UploadToTigris uploads rendered HTML to Tigris
func (s *NotesService) UploadToTigris(ctx context.Context, userID, noteID string, html []byte) error {
    key := fmt.Sprintf("public/%s/%s.html", userID, noteID)

    _, err := s.s3Client.PutObject(ctx, &s3.PutObjectInput{
        Bucket:       aws.String(s.bucketName),
        Key:          aws.String(key),
        Body:         bytes.NewReader(html),
        ContentType:  aws.String("text/html; charset=utf-8"),
        CacheControl: aws.String("public, max-age=86400"), // 24 hour cache
    })

    return err
}
```

---

## 4. Public URL Structure & SEO

### URL Pattern Options

#### Option 1: Subdomain with User/Note Path (Recommended)

```
https://notes.domain.com/{user_id}/{note_id}
```

**Examples:**
- `https://notes.domain.com/alice/my-first-note`
- `https://notes.domain.com/bob/javascript-tips`

**Advantages:**
- Clear separation of public notes from main app
- Easy to apply different security/caching rules
- Clean, memorable URLs
- Subdomain isolation for security

**Implementation:**
```
Fly.io app: agent-notes
Subdomain: notes.domain.com → Routes to Fly.io app
Path routing: /{user_id}/{note_id} → Serves from Tigris
```

#### Option 2: Path-Based Public Routes

```
https://domain.com/public/{note_id}
```

**Examples:**
- `https://domain.com/public/a3f8d9e2`
- `https://domain.com/public/bob-javascript-tips`

**Advantages:**
- Single domain for everything
- No subdomain DNS setup

**Disadvantages:**
- Less intuitive
- Can't apply subdomain-specific security policies

#### Option 3: Hybrid (User-friendly + SEO)

```
https://notes.domain.com/@{username}/{slug}
```

**Examples:**
- `https://notes.domain.com/@alice/my-first-note`
- `https://notes.domain.com/@bob/javascript-tips-2024`

**Advantages:**
- User-friendly (social media style)
- SEO-friendly slugs
- Clear ownership indication

### SEO Implementation Checklist

#### Required Meta Tags

```html
<!-- Basic SEO -->
<title>Note Title - Author Name</title>
<meta name="description" content="First 150-200 chars of note content">
<link rel="canonical" href="https://notes.domain.com/user/note">

<!-- Open Graph (Facebook, LinkedIn) -->
<meta property="og:type" content="article">
<meta property="og:title" content="Note Title (max 60 chars)">
<meta property="og:description" content="Description (max 200 chars)">
<meta property="og:url" content="https://notes.domain.com/user/note">
<meta property="og:image" content="https://notes.domain.com/og-images/note-id.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="628">

<!-- Twitter Card -->
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Note Title">
<meta name="twitter:description" content="Description">
<meta name="twitter:image" content="https://notes.domain.com/og-images/note-id.png">

<!-- Article metadata -->
<meta property="article:published_time" content="2024-01-15T10:00:00Z">
<meta property="article:author" content="Author Name">
```

#### Image Requirements for Social Sharing

**Open Graph Image:**
- Dimensions: 1200 x 628 pixels (minimum)
- Aspect Ratio: 1.91:1
- File Size: Under 5 MB
- Format: PNG or JPEG

**Generation Strategy:**
- **Option A**: Static default image with logo
- **Option B**: Dynamic generation (take screenshot of note with Playwright)
- **Option C**: User uploads custom preview image

#### Subdomain vs Path: SEO Considerations

**Subdomains** are treated as separate entities by search engines:
- Good for branding distinct products
- Can build separate domain authority
- Requires separate sitemap

**Paths** under main domain:
- Consolidates domain authority
- Easier to manage in one sitemap
- Better if notes are core to your product

**Recommendation**: Use subdomain (`notes.domain.com`) for cleaner architecture and future flexibility.

---

## 5. Local Development Setup

### Challenge

Tigris is a cloud-only service tied to Fly.io. For local development, you need an S3-compatible alternative.

### Solution: MinIO

**MinIO** is an open-source, S3-compatible object storage server perfect for local development.

#### Why MinIO over LocalStack?

| Feature | MinIO | LocalStack |
|---------|-------|------------|
| Focus | Object storage (S3) | Full AWS emulation |
| Performance | Lightweight, fast | Heavier (many services) |
| S3 Compatibility | Excellent | Good |
| Ease of Setup | Simple | More complex |
| Cost | Free (open source) | Free tier limited |

**Verdict**: For a project that only needs S3 (Tigris), MinIO is simpler and more performant.

### Local Development with Docker Compose

Create `/home/kuitang/git/agent-notes/docker-compose.yml`:

```yaml
version: '3.8'

services:
  minio:
    image: minio/minio:latest
    container_name: agent-notes-minio
    ports:
      - "9000:9000"      # S3 API
      - "9001:9001"      # Web Console
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    volumes:
      - minio_data:/data
    command: server /data --console-address ":9001"
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 5s
      timeout: 5s
      retries: 5

  createbuckets:
    image: minio/mc:latest
    depends_on:
      minio:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
      mc alias set localminio http://minio:9000 minioadmin minioadmin;
      mc mb localminio/agent-notes --ignore-existing;
      mc anonymous set public localminio/agent-notes/public;
      exit 0;
      "

volumes:
  minio_data:
```

### Environment Configuration

Create `.env.local` for local development:

```bash
# Local MinIO (development)
AWS_ENDPOINT_URL_S3=http://localhost:9000
AWS_ACCESS_KEY_ID=minioadmin
AWS_SECRET_ACCESS_KEY=minioadmin
BUCKET_NAME=agent-notes
AWS_REGION=us-east-1

# Public URL base (local)
PUBLIC_NOTES_URL=http://localhost:8080/public
```

Create `.env.production` for Fly.io (set as secrets):

```bash
# Tigris (production) - Auto-set by `fly storage create`
AWS_ENDPOINT_URL_S3=https://fly.storage.tigris.dev
AWS_ACCESS_KEY_ID=tid_xxxxxxxxxxxxx
AWS_SECRET_ACCESS_KEY=tsec_xxxxxxxxxxxxx
BUCKET_NAME=agent-notes-prod-xxxxx
AWS_REGION=auto

# Public URL base (production)
PUBLIC_NOTES_URL=https://notes.domain.com
```

### Go Code with Environment Switching

```go
package config

import (
    "os"
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {
    S3Client        *s3.Client
    BucketName      string
    PublicNotesURL  string
}

func LoadConfig(ctx context.Context) (*Config, error) {
    // Load AWS config from environment
    cfg, err := config.LoadDefaultConfig(ctx,
        config.WithRegion(getEnv("AWS_REGION", "auto")),
    )
    if err != nil {
        return nil, err
    }

    // Create S3 client with custom endpoint (MinIO or Tigris)
    s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
        if endpoint := os.Getenv("AWS_ENDPOINT_URL_S3"); endpoint != "" {
            o.BaseEndpoint = aws.String(endpoint)
            o.UsePathStyle = true // Required for MinIO
        }
    })

    return &Config{
        S3Client:       s3Client,
        BucketName:     getEnv("BUCKET_NAME", "agent-notes"),
        PublicNotesURL: getEnv("PUBLIC_NOTES_URL", "http://localhost:8080/public"),
    }, nil
}

func getEnv(key, fallback string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return fallback
}
```

### Development Workflow

```bash
# 1. Start local MinIO
docker-compose up -d

# 2. Access MinIO Console
# Open http://localhost:9001
# Login: minioadmin / minioadmin

# 3. Run your Go app locally
go run cmd/server/main.go

# 4. Test uploading a note
curl -X POST http://localhost:8080/api/notes \
  -H "Content-Type: application/json" \
  -d '{"title": "Test Note", "content": "# Hello World"}'

# 5. Verify in MinIO Console
# Check bucket: agent-notes/public/{user_id}/{note_id}.html
```

---

## 6. Cost Structure

### Tigris Pricing (2026)

#### Storage Costs

| Tier | Price | Free Tier |
|------|-------|-----------|
| Standard | $0.02/GB/month | 5 GB |

#### Request Costs

| Request Type | Price | Free Tier |
|--------------|-------|-----------|
| PUT requests | Varies | 10,000/month |
| GET requests | Varies | 100,000/month |

#### Data Transfer

| Type | Price |
|------|-------|
| Regional transfer | **$0** (Free) |
| Inter-region transfer | **$0** (Free) |
| Egress to Internet | **$0** (Free) |

**Key Advantage**: No egress fees, unlike AWS S3 ($0.09/GB) or CloudFront.

#### Multi-Region Replication

- **Cost**: $0.02/GB/month per additional region
- **When to use**: Explicit multi-region storage for compliance or extreme low-latency needs
- **Default**: Single-region with global caching (usually sufficient)

### Fly.io Pricing (2026)

#### Compute (Machines)

| Resource | Price |
|----------|-------|
| Shared CPU (1x) | ~$0.0000008/sec (~$2/month) |
| Shared CPU (2x) | ~$0.0000016/sec (~$4/month) |
| RAM (256MB) | ~$0.0000002/sec (~$0.50/month) |

**Free Allowances:**
- 3 shared-cpu-1x VMs with 256MB RAM
- 160GB outbound data transfer

#### Estimations for Notes App

**Scenario**: 1,000 users, 10,000 notes

| Resource | Usage | Cost |
|----------|-------|------|
| **Tigris Storage** | 1GB HTML (10KB/note avg) | $0.02/month |
| **Tigris GET requests** | 100K/month | Free |
| **Tigris PUT requests** | 5K/month | Free |
| **Fly.io Compute** | 1x shared-cpu, 256MB | Free (within allowance) |
| **Data Transfer** | 50GB/month | Free (within 160GB) |
| **Total** | | **~$0.02/month** |

**Scaling Estimate**: 100,000 notes (10GB HTML)

| Resource | Cost |
|----------|------|
| Storage | $0.20/month (10GB × $0.02) |
| Compute | $2-4/month (1-2 instances) |
| Transfer | Free (Tigris has no egress) |
| **Total** | **~$2.20-4.20/month** |

**Comparison to AWS S3 + CloudFront:**

| Service | Tigris + Fly.io | S3 + CloudFront |
|---------|-----------------|-----------------|
| Storage (10GB) | $0.20/month | $0.23/month |
| GET requests (1M) | Free | $0.40/month |
| Data transfer (50GB) | **Free** | **$4.25/month** |
| **Total** | **$0.20-4.20** | **$4.88+** |

**Savings**: ~50-80% compared to traditional AWS setup, primarily due to zero egress fees.

---

## 7. Deployment Architecture

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                          User Browser                            │
│                     (requests public note)                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ HTTPS
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   notes.domain.com (DNS)                        │
│                 (points to Fly.io app)                          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Fly.io Application                          │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Go HTTP Server (Chi Router)                              │ │
│  │                                                             │ │
│  │  GET /{user_id}/{note_id}:                                 │ │
│  │    1. Generate Tigris key: public/{user}/{note}.html      │ │
│  │    2. Check if exists in Tigris                           │ │
│  │    3. If exists → redirect/proxy to Tigris URL            │ │
│  │    4. If not exists → 404                                 │ │
│  │                                                             │ │
│  │  POST /api/notes (authenticated):                          │ │
│  │    1. Save Markdown to SQLite (encrypted)                 │ │
│  │    2. Render Markdown → HTML + SEO tags                    │ │
│  │    3. Upload HTML to Tigris                               │ │
│  │    4. Return public URL                                    │ │
│  │                                                             │ │
│  │  PUT /api/notes/{id} (authenticated):                      │ │
│  │    1. Update Markdown in SQLite                           │ │
│  │    2. Re-render HTML                                       │ │
│  │    3. Invalidate cache (delete old HTML)                  │ │
│  │    4. Upload new HTML to Tigris                           │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                   │
│  SQLite (SQLCipher)      ┌────────────────────────────────────┐ │
│  - User accounts          │   AWS SDK for Go v2               │ │
│  - Notes metadata         │   (S3 Client)                      │ │
│  - Markdown content       │                                    │ │
│  - Encryption keys        │   Endpoint: Tigris or MinIO       │ │
│                           └────────────────┬───────────────────┘ │
└──────────────────────────────────────────┬─────────────────────┘
                                           │
                                           │ S3 API
                                           │ (PutObject, GetObject)
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────┐
│               Tigris Global Object Storage                       │
│                                                                   │
│  Bucket: agent-notes-prod                                        │
│  ├── public/                                                     │
│  │   ├── alice/                                                  │
│  │   │   ├── my-first-note.html (pre-rendered, cached)         │
│  │   │   └── javascript-tips.html                              │
│  │   ├── bob/                                                    │
│  │   │   └── golang-guide.html                                 │
│  │   └── ...                                                     │
│  │                                                               │
│  └── og-images/ (Open Graph preview images)                     │
│      ├── alice-my-first-note.png                               │
│      └── bob-golang-guide.png                                   │
│                                                                   │
│  Cache Locations: Automatically distributed globally            │
│  - North America                                                 │
│  - Europe                                                        │
│  - Asia-Pacific                                                  │
│  - ... (based on traffic)                                        │
└─────────────────────────────────────────────────────────────────┘
                             │
                             │ HTTPS (cached)
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                          User Browser                            │
│                (receives pre-rendered HTML)                      │
│        (Open Graph tags visible to social media crawlers)       │
└─────────────────────────────────────────────────────────────────┘
```

### Request Flow Examples

#### Example 1: User Creates a Note

```
1. User authenticated, sends POST /api/notes
   Body: { "title": "My Guide", "content": "# Hello\n\nMarkdown content..." }

2. Go app:
   - Saves to SQLite: notes table (id, user_id, title, markdown_content)
   - Generates: note_id = "abc123"
   - Renders Markdown → HTML with SEO meta tags
   - Uploads to Tigris:
     * Key: public/alice/abc123.html
     * Content-Type: text/html; charset=utf-8
     * Cache-Control: public, max-age=86400

3. Response: { "public_url": "https://notes.domain.com/alice/abc123" }

4. Tigris stores HTML in primary region, ready to cache globally
```

#### Example 2: Someone Views the Note (First Time from Europe)

```
1. User navigates to: https://notes.domain.com/alice/abc123

2. DNS resolves notes.domain.com → Fly.io app

3. Go app receives GET /alice/abc123:
   - Redirects to Tigris URL or proxies request

4. Tigris:
   - Retrieves from primary storage
   - Caches in Europe edge location
   - Serves HTML to user

5. User browser:
   - Renders HTML
   - Social media crawlers see Open Graph meta tags
```

#### Example 3: Same Note Viewed Again from Europe

```
1. User navigates to: https://notes.domain.com/alice/abc123

2. Go app redirects to Tigris

3. Tigris:
   - Serves from European cache (< 50ms latency)
   - No origin fetch needed

4. User receives HTML instantly
```

#### Example 4: User Edits the Note

```
1. User authenticated, sends PUT /api/notes/abc123
   Body: { "content": "# Updated\n\nNew content..." }

2. Go app:
   - Updates SQLite
   - Deletes old HTML from Tigris (cache invalidation):
     * DELETE public/alice/abc123.html
   - Re-renders Markdown → HTML
   - Uploads new HTML to Tigris

3. Next request:
   - Tigris serves new HTML
   - Global caches update on next request
```

### Deployment Flow (Fly.io + Tigris)

#### Initial Setup

```bash
# 1. Create Fly.io app
cd /home/kuitang/git/agent-notes
fly launch --name agent-notes --no-deploy

# 2. Create Tigris bucket (sets secrets automatically)
fly storage create

# 3. Set additional secrets
fly secrets set ENCRYPTION_KEY=$(openssl rand -hex 32)
fly secrets set SESSION_SECRET=$(openssl rand -hex 32)

# 4. Configure custom domain
fly certs create notes.domain.com

# 5. Update DNS (A/AAAA records)
# notes.domain.com → Fly.io IP addresses (from `fly ips list`)
```

#### Dockerfile for Fly.io

Create `/home/kuitang/git/agent-notes/Dockerfile`:

```dockerfile
# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies for SQLCipher (CGO)
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with CGO enabled for SQLCipher
RUN CGO_ENABLED=1 GOOS=linux go build -o /bin/server ./cmd/server

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates sqlite-libs

# Copy binary from builder
COPY --from=builder /bin/server /bin/server

# Copy static assets (if any)
COPY --from=builder /app/web /web

EXPOSE 8080

CMD ["/bin/server"]
```

#### Fly.io Configuration

Create `/home/kuitang/git/agent-notes/fly.toml`:

```toml
app = "agent-notes"
primary_region = "ewr" # Newark, NJ (or choose your preferred region)

[build]
  dockerfile = "Dockerfile"

[env]
  PORT = "8080"
  APP_ENV = "production"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 1

[[http_service.checks]]
  grace_period = "10s"
  interval = "30s"
  method = "GET"
  timeout = "5s"
  path = "/health"

[[vm]]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 256

# Auto-scale configuration
[scaling]
  min_count = 1
  max_count = 3

# Volume for SQLite database (persistent storage)
[[mounts]]
  source = "agent_notes_db"
  destination = "/data"
```

#### Create Persistent Volume

```bash
# Create volume for SQLite database
fly volumes create agent_notes_db --size 1 --region ewr

# This ensures database persists across deployments
```

#### Deploy

```bash
# Deploy to Fly.io
fly deploy

# View logs
fly logs

# Check app status
fly status

# Open app in browser
fly open
```

### Monitoring & Maintenance

```bash
# View metrics
fly dashboard

# SSH into running instance
fly ssh console

# Check Tigris usage
fly storage dashboard

# Scale instances
fly scale count 2

# Update secrets
fly secrets set NEW_SECRET=value
```

---

## 8. Step-by-Step Deployment Guide

### Prerequisites

```bash
# Install Fly.io CLI
curl -L https://fly.io/install.sh | sh

# Authenticate
fly auth login

# Install Docker (for local testing)
# Install MinIO CLI (optional, for testing)
brew install minio/stable/mc
```

### Step 1: Prepare Your Go Application

```bash
cd /home/kuitang/git/agent-notes

# Ensure go.mod has AWS SDK
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/service/s3
go get github.com/gomarkdown/markdown

# Test locally with MinIO
docker-compose up -d
go run cmd/server/main.go
```

### Step 2: Create Fly.io App

```bash
# Initialize Fly.io app (don't deploy yet)
fly launch --name agent-notes --no-deploy

# Choose region (e.g., ewr for Newark, NJ)
# Choose Postgres? No (we're using SQLite)
# Choose Redis? No (not needed initially)
```

### Step 3: Set Up Tigris Storage

```bash
# Create Tigris bucket (automatically sets secrets)
fly storage create

# Verify secrets were set
fly secrets list

# Expected secrets:
# - AWS_ACCESS_KEY_ID
# - AWS_SECRET_ACCESS_KEY
# - AWS_ENDPOINT_URL_S3
# - BUCKET_NAME
```

### Step 4: Create Persistent Volume for SQLite

```bash
# Create 1GB volume for database
fly volumes create agent_notes_db --size 1 --region ewr

# Update fly.toml to mount volume (already in config above)
```

### Step 5: Set Application Secrets

```bash
# Generate and set encryption keys
fly secrets set ENCRYPTION_KEY=$(openssl rand -hex 32)
fly secrets set SESSION_SECRET=$(openssl rand -hex 32)

# Set Google OAuth credentials (if using)
fly secrets set GOOGLE_CLIENT_ID=your-client-id
fly secrets set GOOGLE_CLIENT_SECRET=your-secret

# Set email API key (if using Resend)
fly secrets set RESEND_API_KEY=your-api-key

# Set payment keys (if using Stripe)
fly secrets set STRIPE_SECRET_KEY=sk_live_...
fly secrets set STRIPE_WEBHOOK_SECRET=whsec_...
```

### Step 6: Configure Custom Domain

```bash
# Add certificate for your domain
fly certs create notes.domain.com

# Get IP addresses to configure DNS
fly ips list

# Expected output:
# VERSION IP                      TYPE
# v4      XX.XXX.XXX.XXX         shared
# v6      XXXX:XXXX:XXXX::X      shared
```

### Step 7: Update DNS Records

Add these records to your DNS provider (e.g., Cloudflare, Route53):

```
Type: A
Name: notes
Value: [IPv4 from fly ips list]
TTL: Auto

Type: AAAA
Name: notes
Value: [IPv6 from fly ips list]
TTL: Auto
```

### Step 8: Deploy Application

```bash
# Deploy to Fly.io
fly deploy

# Monitor deployment
fly logs

# Check status
fly status

# Test health endpoint
curl https://agent-notes.fly.dev/health
```

### Step 9: Test Public Notes

```bash
# Create a test note (authenticated request)
curl -X POST https://notes.domain.com/api/notes \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Public Note",
    "content": "# Hello World\n\nThis is a test note."
  }'

# Expected response:
# {
#   "id": "abc123",
#   "public_url": "https://notes.domain.com/alice/abc123"
# }

# Access public URL
curl https://notes.domain.com/alice/abc123

# Should return pre-rendered HTML with meta tags
```

### Step 10: Verify Tigris Distribution

```bash
# Check Tigris dashboard
fly storage dashboard

# Expected structure:
# Bucket: agent-notes-prod-xxxxx
# └── public/
#     └── alice/
#         └── abc123.html
```

### Step 11: Test Social Media Sharing

1. **Twitter Card Validator**: https://cards-dev.twitter.com/validator
2. **Facebook Sharing Debugger**: https://developers.facebook.com/tools/debug/
3. **LinkedIn Post Inspector**: https://www.linkedin.com/post-inspector/

Test URL: `https://notes.domain.com/alice/abc123`

Expected: Rich preview with title, description, and image.

### Step 12: Monitor and Scale

```bash
# View real-time metrics
fly dashboard

# Check logs
fly logs --app agent-notes

# Scale instances if needed
fly scale count 2 --region ewr
fly scale count 1 --region ams  # Add European instance

# Check Tigris costs
fly storage dashboard
```

---

## 9. Local Development Complete Setup

### Complete Docker Compose with Services

```yaml
version: '3.8'

services:
  # MinIO (S3-compatible storage for local dev)
  minio:
    image: minio/minio:latest
    container_name: agent-notes-minio
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    volumes:
      - minio_data:/data
    command: server /data --console-address ":9001"
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 5s
      timeout: 5s
      retries: 5

  # Create buckets and set policies
  createbuckets:
    image: minio/mc:latest
    depends_on:
      minio:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
      mc alias set localminio http://minio:9000 minioadmin minioadmin;
      mc mb localminio/agent-notes --ignore-existing;
      mc anonymous set download localminio/agent-notes/public;
      echo 'MinIO bucket created and configured';
      exit 0;
      "

  # MailHog (for testing emails locally)
  mailhog:
    image: mailhog/mailhog:latest
    container_name: agent-notes-mailhog
    ports:
      - "1025:1025"  # SMTP server
      - "8025:8025"  # Web UI

volumes:
  minio_data:
```

### Local Environment Variables

Create `/home/kuitang/git/agent-notes/.env.local`:

```bash
# Server
PORT=8080
APP_ENV=development

# Database
DB_PATH=/tmp/agent-notes-dev.db
DB_ENCRYPTION_KEY=local-dev-key-32-bytes-long!!!

# S3/Tigris (MinIO for local dev)
AWS_ENDPOINT_URL_S3=http://localhost:9000
AWS_ACCESS_KEY_ID=minioadmin
AWS_SECRET_ACCESS_KEY=minioadmin
BUCKET_NAME=agent-notes
AWS_REGION=us-east-1

# Public URLs
PUBLIC_NOTES_URL=http://localhost:8080/public
BASE_URL=http://localhost:8080

# Email (MailHog)
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_FROM=noreply@localhost

# OAuth (use test credentials)
GOOGLE_CLIENT_ID=test-client-id
GOOGLE_CLIENT_SECRET=test-secret
GOOGLE_REDIRECT_URL=http://localhost:8080/auth/google/callback

# Session
SESSION_SECRET=local-dev-session-secret-change-in-prod

# Feature Flags
ENABLE_SIGNUPS=true
ENABLE_PUBLIC_NOTES=true
```

### Development Startup Script

Create `/home/kuitang/git/agent-notes/scripts/dev.sh`:

```bash
#!/bin/bash
set -e

echo "Starting local development environment..."

# Start Docker services
docker-compose up -d

# Wait for services
echo "Waiting for MinIO to be ready..."
sleep 3

# Load environment variables
export $(cat .env.local | grep -v '^#' | xargs)

# Run database migrations (if needed)
# go run cmd/migrate/main.go

# Start Go server with live reload (using air, optional)
if command -v air &> /dev/null; then
    echo "Starting server with live reload..."
    air
else
    echo "Starting server (install 'air' for live reload)..."
    go run cmd/server/main.go
fi
```

### Make it executable:

```bash
chmod +x /home/kuitang/git/agent-notes/scripts/dev.sh
```

### Usage:

```bash
# Start development environment
./scripts/dev.sh

# Access services:
# - App: http://localhost:8080
# - MinIO Console: http://localhost:9001 (minioadmin/minioadmin)
# - MailHog UI: http://localhost:8025
```

---

## 10. Production Best Practices

### Security

1. **Secrets Management**
   - Never commit secrets to Git
   - Use `fly secrets set` for production
   - Rotate keys regularly

2. **Database Encryption**
   - Use SQLCipher for at-rest encryption
   - Derive per-note keys with HKDF
   - Store encryption key in Fly.io secrets

3. **Access Control**
   - Public notes: Read-only, no authentication required
   - Private notes: User authentication required
   - Admin API: Additional authorization checks

4. **Rate Limiting**
   - Apply rate limits to public note endpoints
   - Prevent scraping and abuse
   - Use Fly.io edge rate limiting or Tollbooth

### Caching Strategy

1. **Tigris Cache-Control Headers**
   ```go
   CacheControl: "public, max-age=86400, stale-while-revalidate=3600"
   ```
   - 24-hour cache
   - Serve stale while revalidating

2. **Cache Invalidation**
   - Delete from Tigris on note update
   - Let Tigris cache naturally expire
   - Consider versioned URLs for immutable content

3. **ETags**
   - Generate ETag from note version
   - Support conditional requests (304 Not Modified)

### Monitoring

1. **Health Checks**
   ```go
   router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
       // Check database connection
       // Check Tigris connection
       // Return 200 if healthy
   })
   ```

2. **Metrics to Track**
   - Request latency (p50, p95, p99)
   - Error rates (4xx, 5xx)
   - Tigris GET/PUT request counts
   - Note creation rate
   - Public note views

3. **Logging**
   - Structured logging (JSON)
   - Log levels: DEBUG (dev), INFO (prod)
   - Include request IDs for tracing

### Backup Strategy

1. **SQLite Database**
   - Fly.io volumes are persistent but not backed up by default
   - Use `fly ssh console` + scp to copy database
   - Consider automated backups to Tigris

   ```go
   // Backup script
   func BackupDatabase() {
       timestamp := time.Now().Format("2006-01-02-15-04-05")
       key := fmt.Sprintf("backups/database-%s.db", timestamp)

       file, _ := os.Open("/data/agent-notes.db")
       s3Client.PutObject(ctx, &s3.PutObjectInput{
           Bucket: aws.String("agent-notes-backups"),
           Key:    aws.String(key),
           Body:   file,
       })
   }
   ```

2. **Tigris Data**
   - Tigris has built-in durability
   - Consider versioning for critical data
   - Export important data periodically

### Performance Optimization

1. **Connection Pooling**
   ```go
   db.SetMaxOpenConns(25)
   db.SetMaxIdleConns(5)
   db.SetConnMaxLifetime(5 * time.Minute)
   ```

2. **Lazy Loading**
   - Only render Markdown on demand
   - Cache rendered HTML aggressively

3. **Database Indexes**
   ```sql
   CREATE INDEX idx_notes_user_id ON notes(user_id);
   CREATE INDEX idx_notes_public ON notes(is_public, created_at);
   ```

---

## Summary & Quick Reference

### Architecture at a Glance

- **Compute**: Fly.io (Go application)
- **Storage**: Tigris (S3-compatible object storage with global CDN)
- **Database**: SQLite with SQLCipher (encrypted)
- **Local Dev**: MinIO (S3-compatible)

### Key Decisions

| Decision | Choice | Reasoning |
|----------|--------|-----------|
| **Rendering** | Server-side pre-render | SEO, performance, social sharing |
| **Caching** | Pre-render on save, serve from Tigris | Lowest latency, zero compute on view |
| **URL Structure** | `notes.domain.com/{user}/{note}` | Clean, SEO-friendly, subdomain isolation |
| **Local Dev** | MinIO via Docker | Lightweight, S3-compatible, easy setup |
| **Open Graph** | Server-side generation | Required for social media previews |

### Cost Breakdown (100K notes scenario)

- **Storage**: $0.20/month (10GB @ $0.02/GB)
- **Compute**: $2-4/month (1-2 Fly.io instances)
- **Transfer**: $0 (Tigris has no egress fees)
- **Total**: **$2.20-4.20/month**

### Essential Commands

```bash
# Deploy
fly deploy

# View logs
fly logs

# Scale
fly scale count 2

# Secrets
fly secrets set KEY=value

# SSH
fly ssh console

# Tigris dashboard
fly storage dashboard

# Local dev
docker-compose up -d && ./scripts/dev.sh
```

### Further Reading

- [Fly.io Tigris Documentation](https://fly.io/docs/tigris/)
- [Tigris vs S3 & Cloudfront](https://www.tigrisdata.com/blog/tigris-vs-s3-cloudfront/)
- [Open Graph Protocol](https://ogp.me/)
- [MinIO Documentation](https://min.io/docs/)

---

**Created**: 2026-02-02
**Updated**: 2026-02-02
**Version**: 1.0
