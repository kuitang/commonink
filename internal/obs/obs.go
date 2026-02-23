package obs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

type correlationContextKey struct{}

// Correlation carries per-request correlation identifiers.
type Correlation struct {
	RequestID               string
	ConnID                  string
	TraceID                 string
	Traceparent             string
	Tracestate              string
	DatadogTraceID          string
	DatadogParentID         string
	DatadogSamplingPriority string
	DatadogTags             string
	MCPProtocolVersion      string
	MCPSessionID            string
	OpenAISession           string
	OpenAISubject           string
}

var (
	loggerMu sync.RWMutex
	logger   *slog.Logger
)

// Init configures the global structured logger.
func Init() {
	loggerMu.Lock()
	defer loggerMu.Unlock()
	if logger != nil {
		return
	}
	logger = newLogger(os.Stderr)
	slog.SetDefault(logger)
}

// SetOutputForTests overrides the global logger output for tests.
func SetOutputForTests(w io.Writer) func() {
	loggerMu.Lock()
	prev := logger
	logger = newLogger(w)
	slog.SetDefault(logger)
	loggerMu.Unlock()

	return func() {
		loggerMu.Lock()
		defer loggerMu.Unlock()
		if prev != nil {
			logger = prev
		} else {
			logger = newLogger(os.Stderr)
		}
		slog.SetDefault(logger)
	}
}

func newLogger(w io.Writer) *slog.Logger {
	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				t, ok := attr.Value.Any().(time.Time)
				if ok {
					return slog.String(slog.TimeKey, t.UTC().Format(time.RFC3339Nano))
				}
			}
			return attr
		},
	})
	return slog.New(handler)
}

func globalLogger() *slog.Logger {
	loggerMu.RLock()
	l := logger
	loggerMu.RUnlock()
	if l != nil {
		return l
	}
	Init()
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return logger
}

// Pkg returns a logger tagged with package name.
func Pkg(pkg string) *slog.Logger {
	return globalLogger().With("pkg", pkg)
}

// From returns a logger with correlation fields from context.
func From(ctx context.Context) *slog.Logger {
	l := globalLogger()
	corr := CorrelationFromContext(ctx)
	attrs := correlationAttrs(corr)
	if len(attrs) == 0 {
		return l
	}
	return l.With(attrs...)
}

// WithConnID stores conn_id in context.
func WithConnID(ctx context.Context, connID string) context.Context {
	corr := CorrelationFromContext(ctx)
	corr.ConnID = strings.TrimSpace(connID)
	return context.WithValue(ctx, correlationContextKey{}, corr)
}

// ConnIDFromContext returns conn_id from context, or "unknown".
func ConnIDFromContext(ctx context.Context) string {
	corr := CorrelationFromContext(ctx)
	if corr.ConnID == "" {
		return "unknown"
	}
	return corr.ConnID
}

// WithCorrelation stores request correlation fields in context.
func WithCorrelation(ctx context.Context, corr Correlation) context.Context {
	existing := CorrelationFromContext(ctx)
	if corr.RequestID != "" {
		existing.RequestID = corr.RequestID
	}
	if corr.ConnID != "" {
		existing.ConnID = corr.ConnID
	}
	if corr.TraceID != "" {
		existing.TraceID = corr.TraceID
	}
	if corr.Traceparent != "" {
		existing.Traceparent = corr.Traceparent
	}
	if corr.Tracestate != "" {
		existing.Tracestate = corr.Tracestate
	}
	if corr.DatadogTraceID != "" {
		existing.DatadogTraceID = corr.DatadogTraceID
	}
	if corr.DatadogParentID != "" {
		existing.DatadogParentID = corr.DatadogParentID
	}
	if corr.DatadogSamplingPriority != "" {
		existing.DatadogSamplingPriority = corr.DatadogSamplingPriority
	}
	if corr.DatadogTags != "" {
		existing.DatadogTags = corr.DatadogTags
	}
	if corr.MCPProtocolVersion != "" {
		existing.MCPProtocolVersion = corr.MCPProtocolVersion
	}
	if corr.MCPSessionID != "" {
		existing.MCPSessionID = corr.MCPSessionID
	}
	if corr.OpenAISession != "" {
		existing.OpenAISession = corr.OpenAISession
	}
	if corr.OpenAISubject != "" {
		existing.OpenAISubject = corr.OpenAISubject
	}
	return context.WithValue(ctx, correlationContextKey{}, existing)
}

// CorrelationFromContext returns request correlation fields from context.
func CorrelationFromContext(ctx context.Context) Correlation {
	if ctx == nil {
		return Correlation{}
	}
	corr, ok := ctx.Value(correlationContextKey{}).(Correlation)
	if !ok {
		return Correlation{}
	}
	return corr
}

func correlationAttrs(corr Correlation) []any {
	attrs := make([]any, 0, 24)
	if corr.RequestID != "" {
		attrs = append(attrs, "request_id", corr.RequestID)
	}
	if corr.ConnID != "" {
		attrs = append(attrs, "conn_id", corr.ConnID)
	}
	if corr.TraceID != "" {
		attrs = append(attrs, "trace_id", corr.TraceID)
	}
	if corr.Traceparent != "" {
		attrs = append(attrs, "traceparent", corr.Traceparent)
	}
	if corr.Tracestate != "" {
		attrs = append(attrs, "tracestate", corr.Tracestate)
	}
	if corr.DatadogTraceID != "" {
		attrs = append(attrs, "datadog_trace_id", corr.DatadogTraceID)
	}
	if corr.DatadogParentID != "" {
		attrs = append(attrs, "datadog_parent_id", corr.DatadogParentID)
	}
	if corr.DatadogSamplingPriority != "" {
		attrs = append(attrs, "datadog_sampling_priority", corr.DatadogSamplingPriority)
	}
	if corr.DatadogTags != "" {
		attrs = append(attrs, "datadog_tags", corr.DatadogTags)
	}
	if corr.MCPProtocolVersion != "" {
		attrs = append(attrs, "mcp_protocol_version", corr.MCPProtocolVersion)
	}
	if corr.MCPSessionID != "" {
		attrs = append(attrs, "mcp_session_id", corr.MCPSessionID)
	}
	if corr.OpenAISession != "" {
		attrs = append(attrs, "openai_session", corr.OpenAISession)
	}
	if corr.OpenAISubject != "" {
		attrs = append(attrs, "openai_subject", corr.OpenAISubject)
	}
	return attrs
}

func newRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "req-fallback"
	}
	return "req-" + hex.EncodeToString(buf)
}
