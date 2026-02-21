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
	"os"
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
}

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

// spriteTokenIsReal returns true if the SPRITE_TOKEN env var looks like
// a real Fly Sprites token (non-empty and does not start with "test-").
func spriteTokenIsReal() bool {
	token := strings.TrimSpace(os.Getenv("SPRITE_TOKEN"))
	if token == "" {
		return false
	}
	if strings.HasPrefix(token, "test-") {
		return false
	}
	return true
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
// Roundtrip Create-Get-Delete Property Test
// Creates an app via MCP app_create, verifies it via REST API, deletes it,
// then verifies it returns 404.
// ---------------------------------------------------------------------------

func testAppsAPI_Roundtrip_CreateGetDelete_Properties(rt *rapid.T, env *appsAPIEnv) {
	suffix := rapid.StringMatching(`[a-z0-9]{6,12}`).Draw(rt, "suffix")
	appName := "prop-rt-" + suffix

	// Cleanup: always try to delete the app at the end in case the test fails partway.
	defer func() {
		// Best-effort delete via MCP (ignores errors).
		_ = env.deleteAppViaMCP(appName)
	}()

	// Step 1: Create app via MCP app_create.
	result, err := env.mcpCallTool("app_create", map[string]any{
		"names": []any{appName},
	})
	if err != nil {
		rt.Fatalf("app_create MCP call failed: %v", err)
	}

	// Parse the MCP tool result to extract the created app name.
	var toolResult struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(result, &toolResult); err != nil {
		rt.Fatalf("failed to parse MCP result: %v (%s)", err, string(result))
	}
	if toolResult.IsError {
		// Rate limiting is expected when running many rapid iterations.
		if len(toolResult.Content) > 0 && strings.Contains(toolResult.Content[0].Text, "rate_limited") {
			rt.Skipf("sprite creation rate limited, skipping iteration")
		}
		rt.Fatalf("app_create returned isError=true: %s", string(result))
	}

	// The text content contains a JSON object with the create result.
	var createPayloadText string
	for _, c := range toolResult.Content {
		if c.Type == "text" {
			createPayloadText = c.Text
			break
		}
	}
	if createPayloadText == "" {
		rt.Fatalf("app_create returned no text content: %s", string(result))
	}

	var createResult struct {
		Created bool   `json:"created"`
		Name    string `json:"name"`
		Status  string `json:"status"`
	}
	if err := json.Unmarshal([]byte(createPayloadText), &createResult); err != nil {
		rt.Fatalf("failed to parse app_create payload: %v (%s)", err, createPayloadText)
	}
	if !createResult.Created {
		rt.Fatalf("app_create did not create the app: %s", createPayloadText)
	}
	if createResult.Name != appName {
		rt.Fatalf("app_create returned unexpected name: got %q, want %q", createResult.Name, appName)
	}

	// Step 2: GET /api/apps -> assert app appears in the list.
	listStatus, _, listBody, err := env.doRequest(http.MethodGet, "/api/apps", env.accessToken)
	if err != nil {
		rt.Fatalf("list request failed: %v", err)
	}
	if listStatus != http.StatusOK {
		rt.Fatalf("expected 200 from list, got %d: %s", listStatus, string(listBody))
	}

	var listPayload struct {
		Apps []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(listBody, &listPayload); err != nil {
		rt.Fatalf("failed to decode list response: %v (%s)", err, string(listBody))
	}

	found := false
	for _, item := range listPayload.Apps {
		if item.Name == appName {
			found = true
			break
		}
	}
	if !found {
		rt.Fatalf("app %q not found in list after create", appName)
	}

	// Step 3: GET /api/apps/{name} -> assert metadata matches.
	getStatus, _, getBody, err := env.doRequest(http.MethodGet, "/api/apps/"+appName, env.accessToken)
	if err != nil {
		rt.Fatalf("get request failed: %v", err)
	}
	if getStatus != http.StatusOK {
		rt.Fatalf("expected 200 from get, got %d: %s", getStatus, string(getBody))
	}

	var getPayload struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(getBody, &getPayload); err != nil {
		rt.Fatalf("failed to decode get response: %v (%s)", err, string(getBody))
	}
	if getPayload.Name != appName {
		rt.Fatalf("get returned wrong name: got %q, want %q", getPayload.Name, appName)
	}
	if strings.TrimSpace(getPayload.Status) == "" {
		rt.Fatalf("get returned empty status for %q", appName)
	}

	// Step 4: DELETE /api/apps/{name} -> assert 200.
	delStatus, _, delBody, err := env.doRequest(http.MethodDelete, "/api/apps/"+appName, env.accessToken)
	if err != nil {
		rt.Fatalf("delete request failed: %v", err)
	}
	if delStatus != http.StatusOK {
		rt.Fatalf("expected 200 from delete, got %d: %s", delStatus, string(delBody))
	}

	// Step 5: GET /api/apps/{name} -> assert 404.
	gone404Status, _, gone404Body, err := env.doRequest(http.MethodGet, "/api/apps/"+appName, env.accessToken)
	if err != nil {
		rt.Fatalf("get-after-delete request failed: %v", err)
	}
	if gone404Status != http.StatusNotFound {
		rt.Fatalf("expected 404 after delete, got %d: %s", gone404Status, string(gone404Body))
	}
}

// deleteAppViaMCP is a best-effort cleanup helper that deletes an app via MCP.
func (e *appsAPIEnv) deleteAppViaMCP(appName string) error {
	_, err := e.mcpCallTool("app_delete", map[string]any{
		"app": appName,
	})
	return err
}

func TestAppsAPI_Roundtrip_CreateGetDelete_Properties(t *testing.T) {
	if !spriteTokenIsReal() {
		t.Skip("SPRITE_TOKEN is not set or looks like a dummy token; skipping roundtrip test")
	}
	env := getAppsAPIEnv(t)
	rapid.Check(t, func(rt *rapid.T) {
		testAppsAPI_Roundtrip_CreateGetDelete_Properties(rt, env)
	})
}

func FuzzAppsAPI_Roundtrip_CreateGetDelete_Properties(f *testing.F) {
	if !spriteTokenIsReal() {
		f.Skip("SPRITE_TOKEN is not set or looks like a dummy token; skipping roundtrip fuzz")
	}
	env := getAppsAPIEnv(f)
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		testAppsAPI_Roundtrip_CreateGetDelete_Properties(rt, env)
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
