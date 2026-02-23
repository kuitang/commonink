package obs

import (
	"net/http"
	"strings"
	"time"
)

// ResponseRecorder tracks response status and bytes written.
type ResponseRecorder struct {
	http.ResponseWriter
	statusCode  int
	respBytes   int64
	wroteHeader bool
}

type responseRecorderWithFlusher struct {
	*ResponseRecorder
}

func (r *ResponseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.statusCode = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *ResponseRecorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.statusCode = http.StatusOK
		r.wroteHeader = true
	}
	n, err := r.ResponseWriter.Write(p)
	r.respBytes += int64(n)
	return n, err
}

func (r *ResponseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (r *responseRecorderWithFlusher) Flush() {
	r.ResponseWriter.(http.Flusher).Flush()
}

func (r *ResponseRecorder) StatusCode() int {
	return r.statusCode
}

func (r *ResponseRecorder) RespBytes() int64 {
	return r.respBytes
}

func (r *ResponseRecorder) WroteHeader() bool {
	return r.wroteHeader
}

// NewResponseRecorder wraps a response writer while preserving http.Flusher.
func NewResponseRecorder(w http.ResponseWriter) (http.ResponseWriter, *ResponseRecorder) {
	recorder := &ResponseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
	if _, ok := w.(http.Flusher); ok {
		return &responseRecorderWithFlusher{ResponseRecorder: recorder}, recorder
	}
	return recorder, recorder
}

// RequestContextMiddleware injects request correlation fields into context.
func RequestContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header
		traceparent := strings.TrimSpace(headers.Get("traceparent"))
		traceID := extractTraceID(traceparent)

		requestID := strings.TrimSpace(headers.Get("X-Request-Id"))
		if requestID == "" && traceID != "" {
			requestID = traceID
		}
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-Id", requestID)

		corr := Correlation{
			RequestID:               requestID,
			TraceID:                 traceID,
			Traceparent:             traceparent,
			Tracestate:              strings.TrimSpace(headers.Get("tracestate")),
			DatadogTraceID:          strings.TrimSpace(headers.Get("x-datadog-trace-id")),
			DatadogParentID:         strings.TrimSpace(headers.Get("x-datadog-parent-id")),
			DatadogSamplingPriority: strings.TrimSpace(headers.Get("x-datadog-sampling-priority")),
			DatadogTags:             strings.TrimSpace(headers.Get("x-datadog-tags")),
			MCPProtocolVersion:      strings.TrimSpace(headers.Get("mcp-protocol-version")),
			MCPSessionID:            strings.TrimSpace(headers.Get("mcp-session-id")),
			OpenAISession:           strings.TrimSpace(headers.Get("x-openai-session")),
			OpenAISubject:           strings.TrimSpace(headers.Get("x-openai-subject")),
		}
		ctx := WithCorrelation(r.Context(), corr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AccessLogMiddleware emits one structured access event per request.
func AccessLogMiddleware(pkg string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped, recorder := NewResponseRecorder(w)
		next.ServeHTTP(wrapped, r)

		reqBytes := int64(0)
		if r.ContentLength > 0 {
			reqBytes = r.ContentLength
		}

		durMS := float64(time.Since(start).Microseconds()) / 1000.0
		From(r.Context()).
			With("pkg", pkg).
			Debug(
				"http_access",
				"method", r.Method,
				"path", r.URL.Path,
				"status", recorder.StatusCode(),
				"dur_ms", durMS,
				"req_bytes", reqBytes,
				"resp_bytes", recorder.RespBytes(),
			)
	})
}

func extractTraceID(traceparent string) string {
	parts := strings.Split(strings.TrimSpace(traceparent), "-")
	if len(parts) != 4 {
		return ""
	}
	traceID := strings.ToLower(strings.TrimSpace(parts[1]))
	if len(traceID) != 32 {
		return ""
	}
	if traceID == "00000000000000000000000000000000" {
		return ""
	}
	for i := 0; i < len(traceID); i++ {
		ch := traceID[i]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return ""
		}
	}
	return traceID
}
