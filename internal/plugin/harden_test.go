package plugin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// sizhe233 hardening: API-key holders must never reach auth-file routes, even
// when tracked and when quota resets are enabled, and no host call may happen.
func TestAPIKeyResourceCannotReachAuthFiles(t *testing.T) {
	app := newConfiguredApp(t)
	if _, errSync := app.store.SyncKeys([]string{accountTestKeyA}, false); errSync != nil {
		t.Fatal(errSync)
	}
	hostCalls := 0
	app.SetHostCaller(func(method string, _ any) (json.RawMessage, error) {
		hostCalls++
		return json.RawMessage(`{"files":[]}`), nil
	})
	for _, suffix := range []string{routeAuthFiles, routeAuthQuota, routeAuthQuotaReset, routeAuthFileHistory, routeAIProviders, routeUsageModels} {
		query := url.Values{"auth_index": {"codex-1"}}
		if suffix == routeUsageModels {
			query = url.Values{"credential_ref": {"ref-1"}}
		}
		for _, auth := range []string{"Bearer " + accountTestKeyA, ""} {
			headers := http.Header{}
			if auth != "" {
				headers.Set("Authorization", auth)
			}
			raw, err := app.handleManagement(mustMarshal(t, ManagementRequest{
				Method:  http.MethodGet,
				Path:    resourceBase + suffix,
				Headers: headers,
				Query:   query,
			}))
			if err != nil {
				t.Fatal(err)
			}
			var response ManagementResponse
			decodeResult(t, raw, &response)
			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("%s (auth=%t) status = %d, want 404", suffix, auth != "", response.StatusCode)
			}
		}
	}
	if hostCalls != 0 {
		t.Fatalf("blocked routes made %d host calls", hostCalls)
	}
}

func TestAPIKeyResourceOtherRoutesStillServed(t *testing.T) {
	app := newConfiguredApp(t)
	if _, errSync := app.store.SyncKeys([]string{accountTestKeyA}, false); errSync != nil {
		t.Fatal(errSync)
	}
	raw, err := app.handleManagement(mustMarshal(t, ManagementRequest{
		Method:  http.MethodGet,
		Path:    resourceBase + routeProfile,
		Headers: http.Header{"Authorization": {"Bearer " + accountTestKeyA}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	var response ManagementResponse
	decodeResult(t, raw, &response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("profile status = %d: %s", response.StatusCode, response.Body)
	}
}

// callAccountDirect exercises an account resource handler behind the sizhe233
// route block, so upstream tests keep covering the handler logic. The real
// route is asserted to return 404 first.
func callAccountDirect(t *testing.T, app *App, path, apiKey string, query url.Values) ManagementResponse {
	t.Helper()
	if !apiKeyBlockedResource(path, query) {
		t.Fatalf("%s is not a blocked resource; use callAccount", path)
	}
	if blocked := callAccount(t, app, path, apiKey, query); blocked.StatusCode != http.StatusNotFound {
		t.Fatalf("blocked route %s status = %d, want 404", path, blocked.StatusCode)
	}
	headers := http.Header{}
	if apiKey != "" {
		headers.Set("Authorization", "Bearer "+apiKey)
	}
	req := ManagementRequest{Method: http.MethodGet, Path: resourceBase + path, Headers: headers, Query: query}
	for _, endpoint := range resourceEndpoints {
		if endpoint.path == path {
			access, ok := app.apiKeyViewAccess(req)
			if !ok {
				return apiKeyUnauthorized()
			}
			return endpoint.handle(app, req, access)
		}
	}
	t.Fatalf("no resource endpoint %s", path)
	return ManagementResponse{}
}

func TestAPIKeyUsageModelsBlocksOnlyCredentialBreakdowns(t *testing.T) {
	for _, tc := range []struct {
		query   url.Values
		blocked bool
	}{
		{url.Values{"dimension": {"models"}, "value": {"gpt-5.5"}}, false},
		{url.Values{"dimension": {"sources"}, "value": {"x"}}, false},
		{url.Values{"auth_index": {"codex-1"}}, true},
		{url.Values{"credential_ref": {"ref-1"}}, true},
		{url.Values{"auth_index": {""}}, true},
	} {
		if got := apiKeyBlockedResource(routeUsageModels, tc.query); got != tc.blocked {
			t.Fatalf("apiKeyBlockedResource(%v) = %t, want %t", tc.query, got, tc.blocked)
		}
	}
}
