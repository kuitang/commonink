package appseed

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/internal/auth"
)

const seedAppPythonServer = `from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"GET {self.path}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b'<form method="POST" action="/"><input name="msg" id="msg"><button type="submit" id="send">Send</button></form>')
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode()
        params = parse_qs(raw)
        msg = params.get("msg", [""])[0]
        print(f"POST {self.path} msg={msg}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(f'<p id="echo">You said: {msg}</p>'.encode())
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
`

func callTool(t testing.TB, baseURL, sessionID, tool string, args map[string]any) json.RawMessage {
	t.Helper()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"id":      1,
		"params": map[string]any{
			"name":      tool,
			"arguments": args,
		},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("callTool: failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", strings.TrimRight(baseURL, "/")+"/mcp", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("callTool: failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sessionID,
	})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("callTool %s: request failed: %v", tool, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("callTool %s: failed to read response: %v", tool, err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callTool %s: unexpected status %d: %s", tool, resp.StatusCode, string(respBody))
	}

	var rpcResp struct {
		Result struct {
			Content []struct {
				Type string          `json:"type"`
				Text json.RawMessage `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		t.Fatalf("callTool %s: failed to parse response: %v\nBody: %s", tool, err, string(respBody))
	}
	if rpcResp.Error != nil {
		t.Fatalf("callTool %s: RPC error %d: %s", tool, rpcResp.Error.Code, rpcResp.Error.Message)
	}
	if len(rpcResp.Result.Content) == 0 {
		return json.RawMessage("{}")
	}

	var textStr string
	if err := json.Unmarshal(rpcResp.Result.Content[0].Text, &textStr); err != nil {
		return rpcResp.Result.Content[0].Text
	}
	return json.RawMessage(textStr)
}

// SeedApp creates a sprite-based app via MCP tools and waits for it to become reachable.
// It returns the public URL and registers t.Cleanup to delete the app.
func SeedApp(t testing.TB, baseURL, sessionID, appName string) string {
	t.Helper()

	createResult := callTool(t, baseURL, sessionID, "app_create", map[string]any{
		"names": []string{appName},
	})
	var createResp struct {
		PublicURL string `json:"public_url"`
	}
	if err := json.Unmarshal(createResult, &createResp); err != nil {
		t.Fatalf("SeedApp: failed to parse app_create result: %v", err)
	}

	t.Cleanup(func() {
		callTool(t, baseURL, sessionID, "app_delete", map[string]any{
			"app": appName,
		})
	})

	callTool(t, baseURL, sessionID, "app_write", map[string]any{
		"app":     appName,
		"path":    "server.py",
		"content": seedAppPythonServer,
	})
	callTool(t, baseURL, sessionID, "app_bash", map[string]any{
		"app":     appName,
		"command": "sprite-env services create web --cmd python3 --args /home/sprite/server.py --http-port 8080",
	})

	deadline := time.Now().Add(30 * time.Second)
	localReady := false
	lastLocalResult := ""
	for time.Now().Before(deadline) {
		result := callTool(t, baseURL, sessionID, "app_bash", map[string]any{
			"app":     appName,
			"command": "curl -sf http://localhost:8080",
		})
		lastLocalResult = string(result)

		var bashResult struct {
			ExitCode int    `json:"exit_code"`
			Stdout   string `json:"stdout"`
		}
		if err := json.Unmarshal(result, &bashResult); err == nil && bashResult.ExitCode == 0 && bashResult.Stdout != "" {
			localReady = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !localReady {
		servicesList := callTool(t, baseURL, sessionID, "app_bash", map[string]any{
			"app":     appName,
			"command": "sprite-env services list",
		})
		logs := callTool(t, baseURL, sessionID, "app_bash", map[string]any{
			"app":     appName,
			"command": "tail -n 200 /.sprite/logs/services/*.log 2>/dev/null || true",
		})
		t.Fatalf("SeedApp: local service never became reachable for app %s (last curl=%s services=%s logs=%s)", appName, lastLocalResult, string(servicesList), string(logs))
	}

	publicURL := strings.TrimSpace(createResp.PublicURL)
	if publicURL == "" {
		t.Fatalf("SeedApp: public URL is empty for app %s", appName)
	}

	var lastStatus int
	lastBody := ""
	httpClient := &http.Client{Timeout: 5 * time.Second}
	readyDeadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(readyDeadline) {
		resp, err := httpClient.Get(publicURL)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if readErr == nil {
				bodyText := string(body)
				lastStatus = resp.StatusCode
				lastBody = bodyText
				if resp.StatusCode == http.StatusOK && strings.Contains(bodyText, `id="msg"`) {
					return publicURL
				}
			}
		}
		time.Sleep(2 * time.Second)
	}

	if len(lastBody) > 300 {
		lastBody = lastBody[:300] + "..."
	}
	t.Fatalf("SeedApp: public URL not ready for app %s (status=%d body=%q)", appName, lastStatus, lastBody)
	return publicURL
}
