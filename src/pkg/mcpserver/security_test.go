package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

const pingBody = `{"jsonrpc":"2.0","id":1,"method":"ping"}`

func post(h http.Handler, hdr map[string]string, body string) int {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestHTTPHandlerAuthOriginAndContentType(t *testing.T) {
	st, _ := store.New(t.TempDir())
	srv := NewServer(st)
	srv.AuthToken = strings.Repeat("t", 40)
	h := srv.NewHTTPHandler()
	ok := map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + srv.AuthToken}

	if c := post(h, map[string]string{"Content-Type": "application/json"}, pingBody); c != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", c)
	}
	if c := post(h, map[string]string{"Content-Type": "application/json", "Authorization": "Bearer wrong"}, pingBody); c != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d, want 401", c)
	}
	withOrigin := map[string]string{"Origin": "https://evil.example"}
	for k, v := range ok {
		withOrigin[k] = v
	}
	if c := post(h, withOrigin, pingBody); c != http.StatusForbidden {
		t.Errorf("Origin header: got %d, want 403", c)
	}
	if c := post(h, map[string]string{"Content-Type": "text/plain", "Authorization": ok["Authorization"]}, pingBody); c != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: got %d, want 415", c)
	}
	if c := post(h, ok, strings.Repeat(" ", maxHTTPBodyBytes+1)); c != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: got %d, want 413", c)
	}
	if c := post(h, ok, pingBody); c != http.StatusOK {
		t.Errorf("authorized ping: got %d, want 200", c)
	}
}

func TestServeHTTPRefusesUnauthenticatedOrExposedPlaintext(t *testing.T) {
	st, _ := store.New(t.TempDir())
	srv := NewServer(st)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := srv.ServeHTTP(ctx, "127.0.0.1:0", "", "", ""); err == nil || !strings.Contains(err.Error(), "without authentication") {
		t.Errorf("unauthenticated server started: %v", err)
	}
	srv.AllowInsecureNoAuth = true
	if err := srv.ServeHTTP(ctx, "0.0.0.0:0", "", "", ""); err == nil {
		t.Error("--insecure-no-auth honoured on non-loopback address")
	}
	srv.AllowInsecureNoAuth = false
	srv.AuthToken = strings.Repeat("t", 40)
	if err := srv.ServeHTTP(ctx, "0.0.0.0:0", "", "", ""); err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Errorf("plaintext bearer server allowed on non-loopback: %v", err)
	}
}

func TestProfileApplyCannotSmuggleExecHook(t *testing.T) {
	st, _ := store.New(t.TempDir())
	srv := NewServer(st)
	raw := []byte(`{"manifest_content":"{\"acme_certs\":[{\"name\":\"x\",\"domains\":[\"a.test\"],\"challenge_type\":\"dns-01\",\"dns_exec_hook\":\"touch /tmp/pwned\"}]}"}`)
	if _, err := srv.dispatchTool(context.Background(), "profile_apply", raw); err == nil || !strings.Contains(err.Error(), "disabled over MCP") {
		t.Fatalf("profile_apply ran a manifest with dns_exec_hook: %v", err)
	}
}
