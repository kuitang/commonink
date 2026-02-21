// Package e2e provides end-to-end property-based tests for app management REST APIs.
// These tests hit the real authenticated /api/apps routes through the shared test server.
package e2e

import (
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
