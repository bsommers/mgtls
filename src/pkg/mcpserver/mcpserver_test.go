package mcpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/acme"
	"github.com/sysadmin/mgtls/src/pkg/pki"
	"github.com/sysadmin/mgtls/src/pkg/store"
)

func callRPC(t *testing.T, srv *Server, method string, params any) map[string]any {
	t.Helper()
	reqMap := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		reqMap["params"] = params
	}
	rawReq, err := json.Marshal(reqMap)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	rawResp, err := srv.HandleJSONRPC(context.Background(), rawReq)
	if err != nil {
		t.Fatalf("HandleJSONRPC(%s): %v", method, err)
	}
	var resp struct {
		JSONRPC string         `json:"jsonrpc"`
		Result  map[string]any `json:"result"`
		Error   *jsonRPCError  `json:"error"`
	}
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		t.Fatalf("unmarshal response (%s): %v\nraw: %s", method, err, string(rawResp))
	}
	if resp.Error != nil {
		t.Fatalf("unexpected RPC error for %s: %+v", method, resp.Error)
	}
	return resp.Result
}

func callToolJSON(t *testing.T, srv *Server, toolName string, args map[string]any) map[string]any {
	t.Helper()
	res := callRPC(t, srv, "tools/call", map[string]any{
		"name":      toolName,
		"arguments": args,
	})
	if isErr, _ := res["isError"].(bool); isErr {
		t.Fatalf("tool %s returned isError=true: %+v", toolName, res)
	}
	contentList, ok := res["content"].([]any)
	if !ok || len(contentList) == 0 {
		t.Fatalf("tool %s returned empty content: %+v", toolName, res)
	}
	first, _ := contentList[0].(map[string]any)
	text, _ := first["text"].(string)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("unmarshal tool %s text JSON: %v\ntext: %s", toolName, err, text)
	}
	return parsed
}

func TestMCPProtocolLifecycleAndTools(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	srv := NewServer(st)

	// 1. initialize
	initRes := callRPC(t, srv, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"clientInfo":      map[string]any{"name": "test-client", "version": "1.0"},
	})
	if initRes["protocolVersion"] != "2024-11-05" {
		t.Fatalf("unexpected protocolVersion: %v", initRes["protocolVersion"])
	}
	srvInfo, _ := initRes["serverInfo"].(map[string]any)
	if srvInfo["name"] != "mgtls" {
		t.Fatalf("unexpected serverInfo.name: %v", srvInfo["name"])
	}

	// 2. notifications/initialized & ping
	notifResp, err := srv.HandleJSONRPC(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil || notifResp != nil {
		t.Fatalf("expected nil response for notification, got %s, err=%v", string(notifResp), err)
	}
	_ = callRPC(t, srv, "ping", nil)

	// 3. tools/list
	toolsRes := callRPC(t, srv, "tools/list", nil)
	toolsSlice, ok := toolsRes["tools"].([]any)
	if !ok || len(toolsSlice) < 16 {
		t.Fatalf("expected >= 16 tools, got %d", len(toolsSlice))
	}

	// 4. resources/list & resources/read
	resList := callRPC(t, srv, "resources/list", nil)
	resources, _ := resList["resources"].([]any)
	if len(resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(resources))
	}
	for _, uri := range []string{"mgtls://store/manifest", "mgtls://targets/catalog", "mgtls://acme/providers"} {
		readRes := callRPC(t, srv, "resources/read", map[string]any{"uri": uri})
		contents, _ := readRes["contents"].([]any)
		if len(contents) != 1 {
			t.Fatalf("expected 1 content item for %s", uri)
		}
	}

	// 5. prompts/list & prompts/get
	promptsList := callRPC(t, srv, "prompts/list", nil)
	prompts, _ := promptsList["prompts"].([]any)
	if len(prompts) != 3 {
		t.Fatalf("expected 3 prompts, got %d", len(prompts))
	}
	for _, pName := range []string{"setup-mtls-service", "setup-ssh-ca", "setup-proxmox-tls"} {
		pRes := callRPC(t, srv, "prompts/get", map[string]any{
			"name":      pName,
			"arguments": map[string]string{"target_type": "fastapi", "service_name": "orders", "node_fqdn": "pve1.lan"},
		})
		msgs, _ := pRes["messages"].([]any)
		if len(msgs) == 0 {
			t.Fatalf("expected messages for prompt %s", pName)
		}
	}

	// 6. Execute tools via tools/call
	// pki_create_ca
	caOut := callToolJSON(t, srv, "pki_create_ca", map[string]any{
		"name":        "root-ca",
		"common_name": "Test Root CA",
		"algorithm":   "ecdsa-p256",
	})
	caRec, _ := caOut["record"].(map[string]any)
	if caRec["name"] != "root-ca" {
		t.Fatalf("expected root-ca, got %v", caRec["name"])
	}

	// pki_issue_cert (server + client)
	srvCertOut := callToolJSON(t, srv, "pki_issue_cert", map[string]any{
		"name":         "api-server",
		"common_name":  "api.internal",
		"ca_name":      "root-ca",
		"role":         "server",
		"dns_names":    []string{"api.internal", "localhost"},
		"ip_addresses": []string{"127.0.0.1"},
	})
	srvCertRec, _ := srvCertOut["record"].(map[string]any)
	if srvCertRec["name"] != "api-server" {
		t.Fatalf("expected api-server, got %v", srvCertRec["name"])
	}

	cliCertOut := callToolJSON(t, srv, "pki_issue_cert", map[string]any{
		"name":        "api-client",
		"common_name": "client-1",
		"ca_name":     "root-ca",
		"role":        "client",
	})
	cliCertRec, _ := cliCertOut["record"].(map[string]any)
	if cliCertRec["name"] != "api-client" {
		t.Fatalf("expected api-client, got %v", cliCertRec["name"])
	}

	// pki_self_sign
	selfOut := callToolJSON(t, srv, "pki_self_sign", map[string]any{
		"name":        "standalone-dev",
		"common_name": "dev.local",
		"role":        "mtls",
	})
	selfRec, _ := selfOut["record"].(map[string]any)
	if selfRec["self_signed"] != true {
		t.Fatalf("expected self_signed=true, got %v", selfRec["self_signed"])
	}

	// pki_inspect
	inspOut := callToolJSON(t, srv, "pki_inspect", map[string]any{
		"cert_name": "api-server",
	})
	if !strings.Contains(fmt.Sprint(inspOut["subject"]), "api.internal") {
		t.Fatalf("unexpected inspect subject: %v", inspOut["subject"])
	}

	// pki_verify
	verOut := callToolJSON(t, srv, "pki_verify", map[string]any{
		"cert_name": "api-server",
		"ca_name":   "root-ca",
		"dns_name":  "api.internal",
		"role":      "server",
	})
	if verOut["valid"] != true {
		t.Fatalf("expected valid=true, got %+v", verOut)
	}

	// pki_trust_script
	trustOut := callToolJSON(t, srv, "pki_trust_script", map[string]any{
		"ca_name": "root-ca",
	})
	if trustOut["debian"] == "" {
		t.Fatalf("expected debian trust command, got %+v", trustOut)
	}

	// ssh_create_ca & ssh_sign_cert & ssh_inspect & ssh_config_bundle
	_ = callToolJSON(t, srv, "ssh_create_ca", map[string]any{
		"name":    "ssh-user-ca",
		"ca_type": "user",
	})
	sshCertOut := callToolJSON(t, srv, "ssh_sign_cert", map[string]any{
		"name":       "alice-ssh",
		"ca_name":    "ssh-user-ca",
		"key_id":     "alice@homelab",
		"principals": []string{"alice", "admin"},
	})
	sshCertRec, _ := sshCertOut["record"].(map[string]any)
	sshCertPath, _ := sshCertRec["cert_path"].(string)

	sshInspOut := callToolJSON(t, srv, "ssh_inspect", map[string]any{
		"cert_path": sshCertPath,
	})
	if sshInspOut["key_id"] != "alice@homelab" {
		t.Fatalf("expected key_id alice@homelab, got %v", sshInspOut["key_id"])
	}

	sshBundleOut := callToolJSON(t, srv, "ssh_config_bundle", map[string]any{
		"name":           "prod-ssh",
		"user_ca_name":   "ssh-user-ca",
		"user_cert_name": "alice-ssh",
	})
	if sshBundleOut["sshd_config_path"] == "" {
		t.Fatalf("expected sshd_config_path in bundle")
	}

	// acme_providers
	acmeOut := callToolJSON(t, srv, "acme_providers", nil)
	provs, _ := acmeOut["providers"].([]any)
	if len(provs) < 4 {
		t.Fatalf("expected >= 4 ACME providers, got %d", len(provs))
	}

	// target_list & target_generate (auto-resolving store paths!)
	tListOut := callToolJSON(t, srv, "target_list", nil)
	tSpecs, _ := tListOut["targets"].([]any)
	if len(tSpecs) != 14 {
		t.Fatalf("expected 14 target specs, got %d", len(tSpecs))
	}

	tGenOut := callToolJSON(t, srv, "target_generate", map[string]any{
		"name":        "fastapi-orders",
		"target_type": "fastapi",
		"mutual_tls":  true,
		"ca_name":     "root-ca",
		"server_cert": "api-server",
		"client_cert": "api-client",
		"host":        "api.internal",
	})
	tGenRec, _ := tGenOut["record"].(map[string]any)
	if tGenRec["target_type"] != "fastapi" {
		t.Fatalf("unexpected target_type: %v", tGenRec["target_type"])
	}

	// pki_revoke & verify CRL revocation
	revOut := callToolJSON(t, srv, "pki_revoke", map[string]any{
		"ca_name":     "root-ca",
		"cert_name":   "api-client",
		"reason_code": 1,
	})
	crlPath, _ := revOut["crl_path"].(string)
	if crlPath == "" {
		t.Fatalf("expected non-empty crl_path")
	}
	verRevoked := callToolJSON(t, srv, "pki_verify", map[string]any{
		"cert_name": "api-client",
		"ca_name":   "root-ca",
		"crl_path":  crlPath,
		"role":      "client",
	})
	if verRevoked["revoked"] != true || verRevoked["valid"] != false {
		t.Fatalf("expected revoked=true & valid=false, got %+v", verRevoked)
	}

	// store_status
	manifestOut := callToolJSON(t, srv, "store_status", nil)
	casList, _ := manifestOut["cas"].([]any)
	certsList, _ := manifestOut["certs"].([]any)
	if len(casList) != 1 || len(certsList) != 3 {
		t.Fatalf("unexpected store inventory counts: CAs=%d, Certs=%d", len(casList), len(certsList))
	}
}

func TestServeStdio(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	srv := NewServer(st)

	inputLines := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"acme_providers","arguments":{}}}`,
	}, "\n") + "\n"

	var outBuf bytes.Buffer
	if err := srv.ServeStdio(context.Background(), strings.NewReader(inputLines), &outBuf); err != nil {
		t.Fatalf("ServeStdio: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 JSON-RPC responses (notification skipped), got %d:\n%s", len(lines), outBuf.String())
	}
}

func TestServeHTTPAndMutualTLS(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	srv := NewServer(st)

	// Issue CA, Server Cert, and Client Cert using mgtls pki
	caRes, err := pki.CreateCA(st, pki.CARequest{
		Name:       "mcp-ca",
		CommonName: "MCP Root CA",
		Algorithm:  "ecdsa-p256",
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	srvCert, err := pki.IssueCert(st, pki.CertRequest{
		Name:        "mcp-server",
		CommonName:  "localhost",
		CAName:      "mcp-ca",
		Role:        "server",
		DNSNames:    []string{"localhost"},
		IPAddresses: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("IssueCert server: %v", err)
	}
	cliCert, err := pki.IssueCert(st, pki.CertRequest{
		Name:       "mcp-client",
		CommonName: "agent-client",
		CAName:     "mcp-ca",
		Role:       "client",
	})
	if err != nil {
		t.Fatalf("IssueCert client: %v", err)
	}

	// Build an mTLS httptest.Server using srv.NewHTTPHandler()
	serverTLSCert, err := tls.LoadX509KeyPair(srvCert.Record.FullChainPath, srvCert.Record.KeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair server: %v", err)
	}
	caPEM, err := os.ReadFile(caRes.Record.CertPath)
	if err != nil {
		t.Fatalf("ReadFile CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	ts := httptest.NewUnstartedServer(srv.NewHTTPHandler())
	ts.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	// 1. Client WITHOUT client cert must be rejected during TLS handshake
	unauthClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}
	if _, err := unauthClient.Get(ts.URL + "/healthz"); err == nil {
		t.Fatalf("expected unauthenticated client without client certificate to fail mTLS handshake")
	}

	// 2. Client WITH mgtls-issued client cert succeeds on /healthz and POST /mcp
	clientTLSCert, err := tls.LoadX509KeyPair(cliCert.Record.CertPath, cliCert.Record.KeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair client: %v", err)
	}
	mtlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientTLSCert},
			},
		},
	}

	healthResp, err := mtlsClient.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("mTLS GET /healthz failed: %v", err)
	}
	defer healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on /healthz, got %d", healthResp.StatusCode)
	}

	rpcBody := `{"jsonrpc":"2.0","id":99,"method":"tools/list"}`
	mcpResp, err := mtlsClient.Post(ts.URL+"/mcp", "application/json", strings.NewReader(rpcBody))
	if err != nil {
		t.Fatalf("mTLS POST /mcp failed: %v", err)
	}
	defer mcpResp.Body.Close()
	rawBody, _ := io.ReadAll(mcpResp.Body)
	if mcpResp.StatusCode != http.StatusOK || !strings.Contains(string(rawBody), "pki_create_ca") {
		t.Fatalf("unexpected mTLS /mcp response (%d): %s", mcpResp.StatusCode, string(rawBody))
	}

	// 3. Also test ServeHTTP directly with mTLS listener and context cancellation
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	freeAddr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeHTTP(ctx, freeAddr, srvCert.Record.FullChainPath, srvCert.Record.KeyPath, caRes.Record.CertPath)
	}()

	time.Sleep(80 * time.Millisecond)
	resp2, err := mtlsClient.Get("https://" + freeAddr + "/healthz")
	if err != nil {
		t.Fatalf("ServeHTTP mTLS GET /healthz: %v", err)
	}
	_ = resp2.Body.Close()
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("ServeHTTP shutdown returned error: %v", err)
	}
}

func TestMCPToolsAndJSONRPCNegativePaths(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := store.New(filepath.Join(tmpDir, "store"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	srv := NewServer(st)

	// 1. profile_apply via manifest_content
	inlineYAML := `version: "1.0"
cas:
  - name: inline-ca
    common_name: Inline Root CA
`
	applyInlineOut := callToolJSON(t, srv, "profile_apply", map[string]any{
		"manifest_content": inlineYAML,
	})
	if cas, _ := applyInlineOut["cas_created"].([]any); len(cas) != 1 {
		t.Fatalf("expected 1 CA created via manifest_content, got %v", applyInlineOut)
	}

	// 2. profile_apply via manifest_path
	manifestPath := filepath.Join(tmpDir, "fleet.yaml")
	fileYAML := `version: "1.0"
certs:
  - name: file-cert
    ca_name: inline-ca
    common_name: file.internal
`
	if err := os.WriteFile(manifestPath, []byte(fileYAML), 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	applyFileOut := callToolJSON(t, srv, "profile_apply", map[string]any{
		"manifest_path": manifestPath,
	})
	if certs, _ := applyFileOut["certs_issued"].([]any); len(certs) != 1 {
		t.Fatalf("expected 1 cert issued via manifest_path, got %v", applyFileOut)
	}

	// 3. store_doctor tool
	docOut := callToolJSON(t, srv, "store_doctor", map[string]any{
		"warn_days": 30,
	})
	if docOut["healthy"] != true {
		t.Fatalf("expected store_doctor healthy=true, got %+v", docOut)
	}

	// 4. acme_obtain tool against MockACMEServer
	mockACME := acme.NewMockACMEServer()
	defer mockACME.Close()
	acmeRes := callToolJSON(t, srv, "acme_obtain", map[string]any{
		"name":             "mcp-acme-cert",
		"provider":         "custom",
		"directory_url":    mockACME.DirectoryURL(),
		"email":            "mcp@internal",
		"domains":          []string{"mcp.internal"},
		"challenge_type":   "dns-01",
		"skip_verify_tls":  true,
	})
	if rec, _ := acmeRes["record"].(map[string]any); rec["name"] != "mcp-acme-cert" {
		t.Fatalf("unexpected acme_obtain result: %+v", acmeRes)
	}

	// 5. pki_inspect on CA name
	inspCA := callToolJSON(t, srv, "pki_inspect", map[string]any{
		"cert_name": "inline-ca",
	})
	if inspCA["is_ca"] != true {
		t.Fatalf("expected is_ca=true for inline-ca, got %+v", inspCA)
	}

	// 6. Prompts with default arguments (empty map)
	for _, pName := range []string{"setup-mtls-service", "setup-ssh-ca", "setup-proxmox-tls"} {
		pRes := callRPC(t, srv, "prompts/get", map[string]any{
			"name":      pName,
			"arguments": map[string]string{},
		})
		if msgs, _ := pRes["messages"].([]any); len(msgs) == 0 {
			t.Fatalf("expected non-empty messages for prompt %s with empty args", pName)
		}
	}

	// 7. JSON-RPC negative / error code checks
	checkRPCError := func(raw string, wantCode int) {
		t.Helper()
		respBytes, err := srv.HandleJSONRPC(context.Background(), []byte(raw))
		if err != nil {
			t.Fatalf("HandleJSONRPC error: %v", err)
		}
		var r struct {
			Error *jsonRPCError `json:"error"`
		}
		if err := json.Unmarshal(respBytes, &r); err != nil {
			t.Fatalf("unmarshal error response: %v", err)
		}
		if r.Error == nil || r.Error.Code != wantCode {
			t.Fatalf("for input %s: expected error code %d, got %+v", raw, wantCode, r.Error)
		}
	}

	checkRPCError(`{bad json`, -32700)
	checkRPCError(`{"jsonrpc":"","method":""}`, -32600)
	checkRPCError(`{"jsonrpc":"2.0","id":1,"method":"unknown/method"}`, -32601)
	checkRPCError(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}`, -32602)
	checkRPCError(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{}}`, -32602)
	checkRPCError(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"mgtls://unknown/resource"}}`, -32602)
	checkRPCError(`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{}}`, -32602)
	checkRPCError(`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"unknown-prompt"}}`, -32602)

	// 8. Unknown tool name & invalid tool parameters return isError: true
	for _, tc := range []struct {
		name string
		args any
	}{
		{"nonexistent_tool", map[string]any{}},
		{"profile_apply", map[string]any{}},
		{"pki_inspect", map[string]any{}},
		{"pki_inspect", map[string]any{"cert_name": "does-not-exist"}},
		{"pki_probe", map[string]any{}},
		{"pki_ocsp_verify", map[string]any{}},
		{"pki_csr_sign", map[string]any{}},
		{"pki_csr_sign", map[string]any{"ca_name": "root-ca", "csr_pem": "not a csr"}},
	} {
		res := callRPC(t, srv, "tools/call", map[string]any{
			"name":      tc.name,
			"arguments": tc.args,
		})
		if isErr, _ := res["isError"].(bool); !isErr {
			t.Errorf("expected isError=true for tool %s (%v), got %+v", tc.name, tc.args, res)
		}
	}

	// 9. HTTP handler edge cases (GET /mcp, PUT /mcp 405, POST notification 202)
	handler := srv.NewHTTPHandler()

	recGet := httptest.NewRecorder()
	handler.ServeHTTP(recGet, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if recGet.Code != http.StatusOK || !strings.Contains(recGet.Body.String(), "ready") {
		t.Errorf("expected 200 ready on GET /mcp, got %d: %s", recGet.Code, recGet.Body.String())
	}

	recPut := httptest.NewRecorder()
	handler.ServeHTTP(recPut, httptest.NewRequest(http.MethodPut, "/mcp", nil))
	if recPut.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 on PUT /mcp, got %d", recPut.Code)
	}

	recNotif := httptest.NewRecorder()
	handler.ServeHTTP(recNotif, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)))
	if recNotif.Code != http.StatusAccepted {
		t.Errorf("expected 202 Accepted for notification over HTTP, got %d", recNotif.Code)
	}
}

