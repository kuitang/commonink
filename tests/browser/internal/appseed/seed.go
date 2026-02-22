package appseed

import (
	"bytes"
	"encoding/json"
	"fmt"
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

	result, err := callToolResult(baseURL, sessionID, tool, args)
	if err != nil {
		t.Fatalf("callTool %s: %v", tool, err)
	}
	return result
}

func callToolResult(baseURL, sessionID, tool string, args map[string]any) (json.RawMessage, error) {

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
		return nil, fmt.Errorf("%s: failed to marshal request: %w", tool, err)
	}

	req, err := http.NewRequest("POST", strings.TrimRight(baseURL, "/")+"/mcp", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create request: %w", tool, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sessionID,
	})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", tool, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read response: %w", tool, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected status %d: %s", tool, resp.StatusCode, string(respBody))
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
		return nil, fmt.Errorf("%s: failed to parse response: %w body=%s", tool, err, string(respBody))
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("%s: RPC error %d: %s", tool, rpcResp.Error.Code, rpcResp.Error.Message)
	}
	if len(rpcResp.Result.Content) == 0 {
		return json.RawMessage("{}"), nil
	}

	var textStr string
	if err := json.Unmarshal(rpcResp.Result.Content[0].Text, &textStr); err != nil {
		return rpcResp.Result.Content[0].Text, nil
	}
	return json.RawMessage(textStr), nil
}

func isTransientSpriteToolError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "failed to connect") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "resource not found")
}

func callToolWithRetry(t testing.TB, baseURL, sessionID, tool string, args map[string]any, deadline time.Time, pollInterval time.Duration) json.RawMessage {
	t.Helper()

	var lastErr error
	for time.Now().Before(deadline) {
		result, err := callToolResult(baseURL, sessionID, tool, args)
		if err == nil {
			return result
		}
		lastErr = err
		if !isTransientSpriteToolError(err) {
			t.Fatalf("callToolWithRetry %s: non-transient error: %v", tool, err)
		}
		time.Sleep(pollInterval)
	}
	if lastErr != nil {
		t.Fatalf("callToolWithRetry %s: timed out after transient errors: %v", tool, lastErr)
	}
	t.Fatalf("callToolWithRetry %s: timed out", tool)
	return nil
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

	pollInterval := 250 * time.Millisecond
	setupDeadline := time.Now().Add(30 * time.Second)

	callToolWithRetry(t, baseURL, sessionID, "app_write", map[string]any{
		"app": appName,
		"files": []map[string]any{
			{
				"path":    "server.py",
				"content": seedAppPythonServer,
			},
		},
	}, setupDeadline, pollInterval)

	fileReady := false
	lastFileCheck := ""
	for time.Now().Before(setupDeadline) {
		checkResp, err := callToolResult(baseURL, sessionID, "app_bash", map[string]any{
			"app": appName,
			"command": `if [ -f /home/sprite/server.py ]; then
  echo "present"
  exit 0
fi
echo "missing"
exit 1`,
		})
		if err != nil {
			if isTransientSpriteToolError(err) {
				lastFileCheck = err.Error()
				time.Sleep(pollInterval)
				continue
			}
			t.Fatalf("SeedApp: file check failed: %v", err)
		}

		var checkResult struct {
			ExitCode int    `json:"exit_code"`
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
		}
		if err := json.Unmarshal(checkResp, &checkResult); err != nil {
			t.Fatalf("SeedApp: failed to parse file check result: %v", err)
		}
		lastFileCheck = fmt.Sprintf("exit=%d stdout=%q stderr=%q", checkResult.ExitCode, checkResult.Stdout, checkResult.Stderr)
		if checkResult.ExitCode == 0 {
			fileReady = true
			break
		}
		time.Sleep(pollInterval)
	}
	if !fileReady {
		t.Fatalf("SeedApp: server.py never became visible in app workspace for %s (last check: %s)", appName, lastFileCheck)
	}

	createAppResp := callToolWithRetry(t, baseURL, sessionID, "app_bash", map[string]any{
		"app": appName,
		"command": `if [ ! -f /home/sprite/server.py ]; then
  echo "server.py missing at /home/sprite/server.py"
  exit 1
fi
sprite-env services create web --cmd python3 --args /home/sprite/server.py --http-port 8080`,
	}, setupDeadline, pollInterval)
	var createAppResult struct {
		ExitCode int    `json:"exit_code"`
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
	}
	if err := json.Unmarshal(createAppResp, &createAppResult); err != nil {
		t.Fatalf("SeedApp: failed to parse app_bash create command result: %v", err)
	}
	if createAppResult.ExitCode != 0 {
		t.Fatalf("SeedApp: failed to create local service for app %s: exit=%d stdout=%q stderr=%q", appName, createAppResult.ExitCode, createAppResult.Stdout, createAppResult.Stderr)
	}

	deadline := time.Now().Add(30 * time.Second)
	localReady := false
	lastLocalResult := ""
	for time.Now().Before(deadline) {
		result, err := callToolResult(baseURL, sessionID, "app_bash", map[string]any{
			"app":     appName,
			"command": "curl -sf http://localhost:8080",
		})
		if err != nil {
			if isTransientSpriteToolError(err) {
				lastLocalResult = err.Error()
				time.Sleep(pollInterval)
				continue
			}
			t.Fatalf("SeedApp: local service check failed: %v", err)
		}
		lastLocalResult = string(result)

		var bashResult struct {
			ExitCode int    `json:"exit_code"`
			Stdout   string `json:"stdout"`
		}
		if err := json.Unmarshal(result, &bashResult); err == nil && bashResult.ExitCode == 0 && bashResult.Stdout != "" {
			localReady = true
			break
		}
		time.Sleep(pollInterval)
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
		} else {
			lastStatus = http.StatusBadGateway
			lastBody = "request error: " + err.Error()
		}
		time.Sleep(pollInterval)
	}

	if len(lastBody) > 300 {
		lastBody = lastBody[:300] + "..."
	}
	t.Fatalf("SeedApp: public URL not ready for app %s (status=%d body=%q)", appName, lastStatus, lastBody)
	return publicURL
}
