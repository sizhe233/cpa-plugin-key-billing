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
	for _, suffix := range []string{routeAuthFiles, routeAuthQuota, routeAuthQuotaReset} {
		for _, auth := range []string{"Bearer " + accountTestKeyA, ""} {
			headers := http.Header{}
			if auth != "" {
				headers.Set("Authorization", auth)
			}
			raw, err := app.handleManagement(mustMarshal(t, ManagementRequest{
				Method:  http.MethodGet,
				Path:    resourceBase + suffix,
				Headers: headers,
				Query:   url.Values{"auth_index": {"codex-1"}},
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
