package mcp

import (
	"context"

	"github.com/kuitang/agent-notes/internal/apps"
	"github.com/kuitang/agent-notes/internal/notes"
)

type contextKey int

const (
	notesSvcKey contextKey = iota
	appsSvcKey
)

// WithNotesSvc returns a context carrying the given notes.Service.
func WithNotesSvc(ctx context.Context, svc *notes.Service) context.Context {
	return context.WithValue(ctx, notesSvcKey, svc)
}

// NotesSvcFromContext extracts the per-request notes.Service (may be nil).
func NotesSvcFromContext(ctx context.Context) *notes.Service {
	svc, _ := ctx.Value(notesSvcKey).(*notes.Service)
	return svc
}

// WithAppsSvc returns a context carrying the given apps.Service.
func WithAppsSvc(ctx context.Context, svc *apps.Service) context.Context {
	return context.WithValue(ctx, appsSvcKey, svc)
}

// AppsSvcFromContext extracts the per-request apps.Service (may be nil).
func AppsSvcFromContext(ctx context.Context) *apps.Service {
	svc, _ := ctx.Value(appsSvcKey).(*apps.Service)
	return svc
}
