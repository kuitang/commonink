# Build stage
FROM golang:1.25-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev libsqlite3-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy everything and build
COPY . .
RUN CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5" CGO_LDFLAGS="-lm" \
    go build -tags fts5 -o server ./cmd/server

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libsqlite3-0 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/server ./server
COPY --from=builder /app/web/ ./web/
COPY --from=builder /app/static/ ./static/

EXPOSE 8080

CMD ["./server"]
