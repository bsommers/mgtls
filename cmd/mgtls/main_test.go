package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/pkg/acme"
)

func TestCLIEndToEndWorkflow(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	storeDir := filepath.Join(tmpDir, ".mgtls")

	execCLI := func(args ...string) string {
		t.Helper()
		var out, errBuf bytes.Buffer
		fullArgs := append([]string{"--store-dir", storeDir}, args...)
		if err := run(ctx, fullArgs, strings.NewReader(""), &out, &errBuf); err != nil {
			t.Fatalf("CLI %v failed: %v\nstderr: %s", args, err, errBuf.String())
		}
		return out.String()
	}

	// 1. Init with Root CA
	initOut := execCLI("init", "--with-root-ca", "--root-name", "corp-root", "--root-cn", "Corp Root CA")
	if !strings.Contains(initOut, "corp-root") {
		t.Fatalf("expected corp-root in init output: %s", initOut)
	}

	// 2. Create Intermediate CA
	interOut := execCLI("ca", "create", "--name", "corp-inter", "--cn", "Corp Intermediate CA", "--parent", "corp-root")
	if !strings.Contains(interOut, "corp-inter") {
		t.Fatalf("expected corp-inter in ca create output: %s", interOut)
	}

	// 3. Issue mTLS leaf certificate and self-signed certificate
	execCLI("cert", "issue", "--name", "fastapi-srv", "--ca", "corp-inter", "--cn", "api.corp.local", "--role", "mtls", "--dns", "api.corp.local,localhost", "--ip", "127.0.0.1")
	execCLI("cert", "self-sign", "--name", "quick-dev", "--cn", "dev.local")

	// 4. Inspect and Verify
	inspectOut := execCLI("cert", "inspect", "--name", "fastapi-srv")
	if !strings.Contains(inspectOut, "api.corp.local") {
		t.Fatalf("unexpected inspect output: %s", inspectOut)
	}
	verifyOut := execCLI("cert", "verify", "--name", "fastapi-srv", "--ca", "corp-inter", "--dns", "api.corp.local", "--role", "mtls")
	if !strings.Contains(verifyOut, `"valid": true`) {
		t.Fatalf("expected valid chain verification, got: %s", verifyOut)
	}

	// 5. OpenSSH User & Host CA + Signing + Config Bundle
	execCLI("ssh", "ca-create", "--name", "ssh-user-ca", "--type", "user")
	execCLI("ssh", "ca-create", "--name", "ssh-host-ca", "--type", "host")
	execCLI("ssh", "sign-user", "--name", "alice-cert", "--ca", "ssh-user-ca", "--key-id", "alice@corp", "--principals", "alice,admin")
	execCLI("ssh", "sign-host", "--name", "node1-cert", "--ca", "ssh-host-ca", "--key-id", "node1.corp.local", "--principals", "node1.corp.local")
	execCLI("ssh", "config", "--name", "corp-ssh-cfg", "--user-ca", "ssh-user-ca", "--host-ca", "ssh-host-ca", "--host-cert", "node1-cert", "--user-cert", "alice-cert")

	// 6. ACME v2 against mock RFC 8555 server
	mockACME := acme.NewMockACMEServer()
	defer mockACME.Close()
	acmeOut := execCLI("acme", "obtain", "--name", "acme-edge", "--provider", "custom", "--directory-url", mockACME.DirectoryURL(), "--email", "secops@corp.local", "--domains", "edge.corp.local", "--challenge", "dns-01", "--insecure-skip-verify")
	if !strings.Contains(acmeOut, "edge.corp.local") {
		t.Fatalf("unexpected acme obtain output: %s", acmeOut)
	}

	// 7. Target generation across all 7 frameworks
	for _, target := range []string{"fastapi", "springboot", "mcp", "nginx", "vite", "proxmox", "openssh"} {
		tOut := execCLI("target", "generate", target, "--name", "target-"+target, "--ca", "corp-inter")
		if !strings.Contains(tOut, target) {
			t.Fatalf("expected %s in target generate output: %s", target, tOut)
		}
	}

	// 8. Declarative Fleet Apply (`mgtls apply -f ...`)
	manifestPath := filepath.Join(tmpDir, "fleet.yaml")
	fleetYAML := `version: "1.0"
cas:
  - name: yaml-root-ca
    common_name: YAML Root CA
certs:
  - name: yaml-mcp-cert
    ca_name: yaml-root-ca
    common_name: mcp.local
    role: mtls
targets:
  - name: yaml-mcp-target
    target_type: mcp
    ca_name: yaml-root-ca
    server_cert: yaml-mcp-cert
    mutual_tls: true
`
	if err := os.WriteFile(manifestPath, []byte(fleetYAML), 0644); err != nil {
		t.Fatalf("write fleet.yaml: %v", err)
	}
	applyOut := execCLI("apply", "-f", manifestPath)
	if !strings.Contains(applyOut, "yaml-mcp-target") {
		t.Fatalf("unexpected apply output: %s", applyOut)
	}

	// 9. Doctor & Status
	docOut := execCLI("doctor")
	if !strings.Contains(docOut, `"healthy": true`) {
		t.Fatalf("expected healthy doctor output: %s", docOut)
	}

	// 10. MCP Server over stdio (`mgtls mcp serve`)
	mcpInput := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"store_doctor","arguments":{"warn_days":15}}}` + "\n"
	var mcpOut, mcpErr bytes.Buffer
	if err := run(ctx, []string{"--store-dir", storeDir, "mcp", "serve"}, strings.NewReader(mcpInput), &mcpOut, &mcpErr); err != nil {
		t.Fatalf("mcp serve failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(mcpOut.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON-RPC responses from mcp serve, got %d: %s", len(lines), mcpOut.String())
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &resp); err != nil {
		t.Fatalf("unmarshal mcp response: %v", err)
	}
	if resp["error"] != nil {
		t.Fatalf("unexpected mcp error: %v", resp["error"])
	}
}
