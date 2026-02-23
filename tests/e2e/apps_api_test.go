// Package e2e provides end-to-end property-based tests for app management REST APIs.
// These tests hit the real authenticated /api/apps routes through the shared test server.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/kuitang/agent-notes/tests/e2e/testutil"
	"pgregory.net/rapid"
)

type appsAPIEnv struct {
	baseURL     string
	accessToken string
	client      *http.Client
	sessionID   string
}

// appsAPISharedEnv is shared across rapid iterations and test functions.
// This is safe because all property tests assert invariants that hold regardless
// of accumulated server state (e.g. "app names are non-empty", "unknown apps
// return 404"). No test depends on a specific app count or app identity.
// The shared http.Client uses Bearer token auth (no cookie state leakage).
var appsAPIEnvMu sync.Mutex
var appsAPISharedEnv *appsAPIEnv

func getAppsAPIEnv(t testing.TB) *appsAPIEnv {
	t.Helper()

	appsAPIEnvMu.Lock()
	defer appsAPIEnvMu.Unlock()

	if appsAPISharedEnv != nil {
		return appsAPISharedEnv
	}

	srv := testutil.GetServer(t)
	creds := testutil.PerformOAuthFlow(t, srv.BaseURL, "AppsAPIPropertyTests")
	appsAPISharedEnv = &appsAPIEnv{
		baseURL:     srv.BaseURL,
		accessToken: creds.AccessToken,
		client:      testutil.NewHTTPClient(),
	}
	return appsAPISharedEnv
}

func (e *appsAPIEnv) doRequest(method, path, bearerToken string) (int, http.Header, []byte, error) {
	req, err := http.NewRequest(method, e.baseURL+path, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header, data, nil
}

// doPostRequest sends a POST with an empty body to the given path.
func (e *appsAPIEnv) doPostRequest(path, bearerToken string) (int, http.Header, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, e.baseURL+path, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header, data, nil
}

// mcpCallTool sends a JSON-RPC tools/call request to POST /mcp and returns
// the parsed result content text. Returns an error if the request fails or
// the JSON-RPC response contains an error.
func (e *appsAPIEnv) mcpCallTool(toolName string, args map[string]any) (json.RawMessage, error) {
	if err := e.ensureMCPSession(); err != nil {
		return nil, err
	}

	body := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"id":      1,
		"params": map[string]any{
			"name":      toolName,
			"arguments": args,
		},
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest("POST", e.baseURL+"/mcp", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+e.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", e.sessionID)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MCP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("MCP returned %d: %s", resp.StatusCode, string(respBody))
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("decode JSON-RPC response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

func (e *appsAPIEnv) ensureMCPSession() error {
	if e.sessionID != "" {
		return nil
	}

	initReq := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "apps-api-tests",
				"version": "1.0.0",
			},
		},
	}
	initBody, err := json.Marshal(initReq)
	if err != nil {
		return fmt.Errorf("marshal initialize request: %w", err)
	}

	initHTTPReq, err := http.NewRequest(http.MethodPost, e.baseURL+"/mcp", bytes.NewReader(initBody))
	if err != nil {
		return fmt.Errorf("create initialize request: %w", err)
	}
	initHTTPReq.Header.Set("Authorization", "Bearer "+e.accessToken)
	initHTTPReq.Header.Set("Content-Type", "application/json")
	initHTTPReq.Header.Set("Accept", "application/json, text/event-stream")

	initResp, err := e.client.Do(initHTTPReq)
	if err != nil {
		return fmt.Errorf("initialize request failed: %w", err)
	}
	defer initResp.Body.Close()
	if initResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(initResp.Body)
		return fmt.Errorf("initialize returned %d: %s", initResp.StatusCode, string(respBody))
	}
	e.sessionID = strings.TrimSpace(initResp.Header.Get("Mcp-Session-Id"))
	if e.sessionID == "" {
		return fmt.Errorf("initialize did not return Mcp-Session-Id")
	}

	initializedNotif := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	notifBody, err := json.Marshal(initializedNotif)
	if err != nil {
		return fmt.Errorf("marshal initialized notification: %w", err)
	}
	notifReq, err := http.NewRequest(http.MethodPost, e.baseURL+"/mcp", bytes.NewReader(notifBody))
	if err != nil {
		return fmt.Errorf("create initialized request: %w", err)
	}
	notifReq.Header.Set("Authorization", "Bearer "+e.accessToken)
	notifReq.Header.Set("Content-Type", "application/json")
	notifReq.Header.Set("Accept", "application/json, text/event-stream")
	notifReq.Header.Set("Mcp-Session-Id", e.sessionID)

	notifResp, err := e.client.Do(notifReq)
	if err != nil {
		return fmt.Errorf("initialized notification failed: %w", err)
	}
	defer notifResp.Body.Close()
	if notifResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(notifResp.Body)
		return fmt.Errorf("initialized notification returned %d: %s", notifResp.StatusCode, string(respBody))
	}
	return nil
}

func testAppsAPI_List_Authenticated_Properties(rt *rapid.T, env *appsAPIEnv) {
	limit := rapid.IntRange(-50, 200).Draw(rt, "limit")
	offset := rapid.IntRange(-50, 200).Draw(rt, "offset")

	status, _, body, err := env.doRequest(http.MethodGet, fmt.Sprintf("/api/apps?limit=%d&offset=%d", limit, offset), env.accessToken)
	if err != nil {
		rt.Fatalf("list request failed: %v", err)
	}
	if status != http.StatusOK {
		rt.Fatalf("expected 200, got %d: %s", status, string(body))
	}

	var payload struct {
		Apps []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		rt.Fatalf("failed to decode list response: %v (%s)", err, string(body))
	}
	for _, item := range payload.Apps {
		if strings.TrimSpace(item.Name) == "" {
			rt.Fatalf("app name should not be empty: %+v", item)
		}
	}
}

func TestAppsAPI_List_Authenticated_Properties(t *testing.T) {
	t.Parallel()
	env := getAppsAPIEnv(t)
	rapid.Check(t, func(rt *rapid.T) {
		testAppsAPI_List_Authenticated_Properties(rt, env)
	})
}

func FuzzAppsAPI_List_Authenticated_Properties(f *testing.F) {
	env := getAppsAPIEnv(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testAppsAPI_List_Authenticated_Properties(rt, env)
	}))
}

func testAppsAPI_GetUnknown_NotFound_Properties(rt *rapid.T, env *appsAPIEnv) {
	suffix := rapid.StringMatching(`[a-z0-9]{6,14}`).Draw(rt, "suffix")
	appName := "prop-missing-" + suffix

	status, _, body, err := env.doRequest(http.MethodGet, "/api/apps/"+appName, env.accessToken)
	if err != nil {
		rt.Fatalf("get request failed: %v", err)
	}
	if status != http.StatusNotFound {
		rt.Fatalf("expected 404, got %d: %s", status, string(body))
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		rt.Fatalf("failed to decode error payload: %v (%s)", err, string(body))
	}
	errMsg, _ := payload["error"].(string)
	if strings.TrimSpace(errMsg) == "" {
		rt.Fatalf("expected non-empty error message: %s", string(body))
	}
}

func TestAppsAPI_GetUnknown_NotFound_Properties(t *testing.T) {
	t.Parallel()
	env := getAppsAPIEnv(t)
	rapid.Check(t, func(rt *rapid.T) {
		testAppsAPI_GetUnknown_NotFound_Properties(rt, env)
	})
}

func FuzzAppsAPI_GetUnknown_NotFound_Properties(f *testing.F) {
	env := getAppsAPIEnv(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testAppsAPI_GetUnknown_NotFound_Properties(rt, env)
	}))
}

func testAppsAPI_LogsInvalidLines_BadRequest_Properties(rt *rapid.T, env *appsAPIEnv) {
	suffix := rapid.StringMatching(`[a-z0-9]{6,14}`).Draw(rt, "suffix")
	appName := "prop-missing-" + suffix

	var invalid string
	switch rapid.IntRange(0, 2).Draw(rt, "case") {
	case 0:
		invalid = "0"
	case 1:
		invalid = "-" + strconv.Itoa(rapid.IntRange(1, 999).Draw(rt, "neg"))
	default:
		invalid = rapid.StringMatching(`[A-Za-z]{1,8}`).Draw(rt, "text")
	}

	status, _, body, err := env.doRequest(
		http.MethodGet,
		"/api/apps/"+appName+"/logs?lines="+url.QueryEscape(invalid),
		env.accessToken,
	)
	if err != nil {
		rt.Fatalf("logs request failed: %v", err)
	}
	if status != http.StatusBadRequest {
		rt.Fatalf("expected 400 for invalid lines=%q, got %d: %s", invalid, status, string(body))
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		rt.Fatalf("failed to decode bad request payload: %v (%s)", err, string(body))
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(strings.ToLower(errMsg), "invalid lines parameter") {
		rt.Fatalf("unexpected error message: %s", string(body))
	}
}

func TestAppsAPI_LogsInvalidLines_BadRequest_Properties(t *testing.T) {
	t.Parallel()
	env := getAppsAPIEnv(t)
	rapid.Check(t, func(rt *rapid.T) {
		testAppsAPI_LogsInvalidLines_BadRequest_Properties(rt, env)
	})
}

func FuzzAppsAPI_LogsInvalidLines_BadRequest_Properties(f *testing.F) {
	env := getAppsAPIEnv(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testAppsAPI_LogsInvalidLines_BadRequest_Properties(rt, env)
	}))
}

func testAppsAPI_UnauthenticatedRejected_Properties(rt *rapid.T, env *appsAPIEnv) {
	method := rapid.SampledFrom([]string{http.MethodGet, http.MethodDelete}).Draw(rt, "method")
	path := "/api/apps"
	if method == http.MethodDelete {
		path = "/api/apps/prop-missing-" + rapid.StringMatching(`[a-z0-9]{6,10}`).Draw(rt, "suffix")
	}

	status, _, body, err := env.doRequest(method, path, "")
	if err != nil {
		rt.Fatalf("unauthenticated request failed: %v", err)
	}
	if status != http.StatusUnauthorized {
		rt.Fatalf("expected 401, got %d: %s", status, string(body))
	}
}

func TestAppsAPI_UnauthenticatedRejected_Properties(t *testing.T) {
	t.Parallel()
	env := getAppsAPIEnv(t)
	rapid.Check(t, func(rt *rapid.T) {
		testAppsAPI_UnauthenticatedRejected_Properties(rt, env)
	})
}

func FuzzAppsAPI_UnauthenticatedRejected_Properties(f *testing.F) {
	env := getAppsAPIEnv(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testAppsAPI_UnauthenticatedRejected_Properties(rt, env)
	}))
}

func testAppsAPI_UnknownApp_Endpoints_DoNot500_Properties(rt *rapid.T, env *appsAPIEnv) {
	suffix := rapid.StringMatching(`[a-z0-9]{8,16}`).Draw(rt, "suffix")
	appName := "prop-missing-" + suffix

	cases := []struct {
		method string
		path   string
	}{
		{method: http.MethodDelete, path: "/api/apps/" + appName},
		{method: http.MethodGet, path: "/api/apps/" + appName + "/files"},
		{method: http.MethodGet, path: "/api/apps/" + appName + "/files/app.py"},
		{method: http.MethodGet, path: "/api/apps/" + appName + "/logs"},
	}

	for _, tc := range cases {
		status, _, body, err := env.doRequest(tc.method, tc.path, env.accessToken)
		if err != nil {
			rt.Fatalf("request failed for %s %s: %v", tc.method, tc.path, err)
		}
		if status == http.StatusInternalServerError {
			rt.Fatalf("endpoint returned 500 for %s %s: %s", tc.method, tc.path, string(body))
		}
		if status != http.StatusOK &&
			status != http.StatusNotFound &&
			status != http.StatusServiceUnavailable {
			rt.Fatalf("unexpected status %d for %s %s: %s", status, tc.method, tc.path, string(body))
		}
	}
}

func TestAppsAPI_UnknownApp_Endpoints_DoNot500_Properties(t *testing.T) {
	t.Parallel()
	env := getAppsAPIEnv(t)
	rapid.Check(t, func(rt *rapid.T) {
		testAppsAPI_UnknownApp_Endpoints_DoNot500_Properties(rt, env)
	})
}

func FuzzAppsAPI_UnknownApp_Endpoints_DoNot500_Properties(f *testing.F) {
	env := getAppsAPIEnv(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testAppsAPI_UnknownApp_Endpoints_DoNot500_Properties(rt, env)
	}))
}

// ---------------------------------------------------------------------------
// Action Endpoint Validation Property Test
// Tests that POST /api/apps/{name}/{action} returns proper errors:
// - Invalid action -> 400
// - Valid action on nonexistent app -> not 500
// ---------------------------------------------------------------------------

func testAppsAPI_ActionEndpoint_Validation_Properties(rt *rapid.T, env *appsAPIEnv) {
	// Sub-test 1: Invalid action should return 400.
	suffix := rapid.StringMatching(`[a-z0-9]{6,12}`).Draw(rt, "suffix")
	appName := "prop-action-" + suffix

	invalidAction := rapid.SampledFrom([]string{
		"invalid",
		"deploy",
		"scale",
		"migrate",
		"reboot",
	}).Draw(rt, "invalidAction")

	invalidStatus, _, invalidBody, err := env.doPostRequest(
		"/api/apps/"+appName+"/"+invalidAction,
		env.accessToken,
	)
	if err != nil {
		rt.Fatalf("invalid action request failed: %v", err)
	}
	if invalidStatus != http.StatusBadRequest {
		rt.Fatalf("expected 400 for invalid action %q, got %d: %s", invalidAction, invalidStatus, string(invalidBody))
	}

	// Verify the error message mentions the invalid action.
	var errPayload map[string]any
	if err := json.Unmarshal(invalidBody, &errPayload); err != nil {
		rt.Fatalf("failed to decode error payload: %v (%s)", err, string(invalidBody))
	}
	errMsg, _ := errPayload["error"].(string)
	if !strings.Contains(strings.ToLower(errMsg), "invalid action") {
		rt.Fatalf("error message should mention 'invalid action': %s", string(invalidBody))
	}

	// Sub-test 2: Valid actions on nonexistent app should not return 500.
	validAction := rapid.SampledFrom([]string{"start", "stop", "restart"}).Draw(rt, "validAction")
	nonexistentName := "prop-noexist-" + rapid.StringMatching(`[a-z0-9]{6,12}`).Draw(rt, "nonexistSuffix")

	validStatus, _, validBody, err := env.doPostRequest(
		"/api/apps/"+nonexistentName+"/"+validAction,
		env.accessToken,
	)
	if err != nil {
		rt.Fatalf("valid action on nonexistent app request failed: %v", err)
	}
	if validStatus == http.StatusInternalServerError {
		rt.Fatalf("endpoint returned 500 for %s on nonexistent app %q: %s", validAction, nonexistentName, string(validBody))
	}
	// Accept 400, 404, or 503 (SPRITE_TOKEN not configured).
	if validStatus != http.StatusBadRequest &&
		validStatus != http.StatusNotFound &&
		validStatus != http.StatusServiceUnavailable {
		rt.Fatalf("unexpected status %d for %s on nonexistent app %q: %s", validStatus, validAction, nonexistentName, string(validBody))
	}
}

func TestAppsAPI_ActionEndpoint_Validation_Properties(t *testing.T) {
	t.Parallel()
	env := getAppsAPIEnv(t)
	rapid.Check(t, func(rt *rapid.T) {
		testAppsAPI_ActionEndpoint_Validation_Properties(rt, env)
	})
}

func FuzzAppsAPI_ActionEndpoint_Validation_Properties(f *testing.F) {
	env := getAppsAPIEnv(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testAppsAPI_ActionEndpoint_Validation_Properties(rt, env)
	}))
}
