package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/acme"
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

	// 11. Additional subcommands: ca list, ca trust-script, cert revoke, ssh inspect, acme providers, acme renew-check, target list, status
	caListOut := execCLI("ca", "list")
	if !strings.Contains(caListOut, "corp-root") {
		t.Fatalf("expected corp-root in ca list: %s", caListOut)
	}
	trustOut := execCLI("ca", "trust-script", "--name", "corp-root")
	if !strings.Contains(trustOut, "update-ca-certificates") {
		t.Fatalf("expected update-ca-certificates in ca trust-script: %s", trustOut)
	}
	caInspectOut := execCLI("cert", "inspect", "--name", "corp-root")
	if !strings.Contains(caInspectOut, "Corp Root CA") {
		t.Fatalf("expected Corp Root CA in cert inspect: %s", caInspectOut)
	}
	revOut := execCLI("cert", "revoke", "--ca", "corp-inter", "--name", "fastapi-srv", "--reason", "1")
	if !strings.Contains(revOut, `"revoked": true`) {
		t.Fatalf("expected revoked=true in cert revoke: %s", revOut)
	}
	sshCertPath := filepath.Join(storeDir, "ssh", "certs", "alice-cert", "id_key-cert.pub")
	sshInspOut := execCLI("ssh", "inspect", "--cert", sshCertPath)
	if !strings.Contains(sshInspOut, "alice@corp") {
		t.Fatalf("expected alice@corp in ssh inspect: %s", sshInspOut)
	}
	acmeProvOut := execCLI("acme", "providers")
	if !strings.Contains(acmeProvOut, "letsencrypt") {
		t.Fatalf("expected letsencrypt in acme providers: %s", acmeProvOut)
	}
	acmeRenewOut := execCLI("acme", "renew-check", "--days", "120")
	if !strings.Contains(acmeRenewOut, "acme-edge") {
		t.Fatalf("expected acme-edge in acme renew-check: %s", acmeRenewOut)
	}
	targetListOut := execCLI("target", "list")
	if !strings.Contains(targetListOut, "proxmox") {
		t.Fatalf("expected proxmox in target list: %s", targetListOut)
	}
	statusOut := execCLI("status")
	if !strings.Contains(statusOut, "corp-root") {
		t.Fatalf("expected corp-root in status output: %s", statusOut)
	}
}

func TestCLIFlagsHelpVersionAndNegativePaths(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	storeDir := filepath.Join(tmpDir, ".mgtls")

	runArgs := func(args ...string) (string, error) {
		var out, errBuf bytes.Buffer
		err := run(ctx, args, strings.NewReader(""), &out, &errBuf)
		return out.String(), err
	}

	// Help & Version flags
	for _, helpArg := range [][]string{{}, {"--help"}, {"help"}, {"-h"}} {
		out, err := runArgs(helpArg...)
		if err != nil || !strings.Contains(out, "Usage:") {
			t.Fatalf("expected usage output for %v, got err=%v, out=%s", helpArg, err, out)
		}
	}
	for _, verArg := range []string{"version", "--version", "-v"} {
		out, err := runArgs(verArg)
		if err != nil || !strings.Contains(out, Version) {
			t.Fatalf("expected version %s for %s, got err=%v, out=%s", Version, verArg, err, out)
		}
	}

	// --store-dir=<dir> prefix flag
	out, err := runArgs("--store-dir="+storeDir, "init")
	if err != nil || !strings.Contains(out, "initialized") {
		t.Fatalf("expected init with --store-dir= prefix to succeed, got err=%v, out=%s", err, out)
	}

	// Guide command & idempotent init --with-root-ca --starter --yes
	guideOut, err := runArgs("guide")
	if err != nil || !strings.Contains(guideOut, "Onboarding & End-to-End Workflow Guide") {
		t.Fatalf("expected guide output, got err=%v, out=%s", err, guideOut)
	}

	origWD, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err == nil {
		defer func() { _ = os.Chdir(origWD) }()
		var outBuf, errBuf bytes.Buffer
		if err := run(ctx, []string{"--store-dir", storeDir, "init", "--with-root-ca", "--starter", "--yes"}, strings.NewReader(""), &outBuf, &errBuf); err != nil {
			t.Fatalf("init --with-root-ca --starter: %v", err)
		}
		if !strings.Contains(errBuf.String(), "Next steps:") {
			t.Fatalf("expected Next steps breadcrumb on stderr, got %s", errBuf.String())
		}
		// Second run is idempotent without --force
		outBuf.Reset()
		errBuf.Reset()
		if err := run(ctx, []string{"--store-dir", storeDir, "init", "--with-root-ca", "--starter", "--quiet"}, strings.NewReader(""), &outBuf, &errBuf); err != nil {
			t.Fatalf("idempotent second init: %v", err)
		}
		if errBuf.Len() != 0 {
			t.Fatalf("expected --quiet to suppress stderr Next steps, got %s", errBuf.String())
		}
		// Test watch --once and systemd generate CLI subcommands
		if _, err := runArgs("--store-dir", storeDir, "watch", "--once", "--renew-before", "1h"); err != nil {
			t.Fatalf("watch --once failed: %v", err)
		}
		sysOut, err := runArgs("--store-dir", storeDir, "systemd", "generate", "--unit-name", "mgtls-test")
		if err != nil || !strings.Contains(sysOut, "mgtls-test.service") {
			t.Fatalf("systemd generate failed: err=%v, out=%s", err, sysOut)
		}

		// Test probe CLI subcommand against a local TLS 1.3 listener
		issueOut, err := runArgs("--store-dir", storeDir, "cert", "issue", "--name", "probe-srv", "--ca", "root-ca", "--cn", "api.internal", "--dns", "api.internal,localhost", "--ip", "127.0.0.1", "--role", "server")
		if err != nil {
			t.Fatalf("cert issue probe-srv failed: %v", err)
		}
		var issued struct {
			Record struct {
				FullChainPath string `json:"full_chain_path"`
				KeyPath       string `json:"key_path"`
			} `json:"record"`
		}
		if err := json.Unmarshal([]byte(issueOut), &issued); err != nil {
			t.Fatalf("unmarshal issued cert: %v", err)
		}
		srvPair, err := tls.LoadX509KeyPair(issued.Record.FullChainPath, issued.Record.KeyPath)
		if err != nil {
			t.Fatalf("LoadX509KeyPair for probe test: %v", err)
		}
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{srvPair},
			MinVersion:   tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("tls.Listen for probe test: %v", err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					if tc, ok := conn.(*tls.Conn); ok {
						_ = tc.Handshake()
					}
				}(c)
			}
		}()

		probeOut, err := runArgs("--store-dir", storeDir, "probe", "--addr", ln.Addr().String(), "--sni", "api.internal", "--ca", "root-ca", "--strict")
		if err != nil || !strings.Contains(probeOut, `"verified": true`) {
			t.Fatalf("probe --strict failed: err=%v, out=%s", err, probeOut)
		}
		if _, err := runArgs("--store-dir", storeDir, "probe", "--sni", "wrong.internal", "--ca", "root-ca", "--strict", ln.Addr().String()); err == nil {
			t.Fatalf("expected probe --strict to fail on hostname mismatch")
		}

		// Test ocsp verify CLI subcommand
		ocspOut, err := runArgs("--store-dir", storeDir, "ocsp", "verify", "--name", "probe-srv", "--ca", "root-ca")
		if err != nil || !strings.Contains(ocspOut, `"status": "good"`) {
			t.Fatalf("ocsp verify failed: err=%v, out=%s", err, ocspOut)
		}
	}

	// CSR + vault CLI workflow
	{
		csrDir := t.TempDir()
		if _, err := runArgs("csr", "create", "--name", "ext", "--cn", "ext.internal", "--dns", "ext.internal", "--out-dir", csrDir); err != nil {
			t.Fatalf("csr create: %v", err)
		}
		if _, err := os.Stat(filepath.Join(csrDir, "ext.key.pem")); err != nil {
			t.Fatalf("csr create must write key locally: %v", err)
		}
		signOut, err := runArgs("--store-dir", storeDir, "csr", "sign", "--csr", filepath.Join(csrDir, "ext.csr.pem"), "--ca", "root-ca", "--role", "server", "--out", filepath.Join(csrDir, "ext.pem"))
		if err != nil || !strings.Contains(signOut, `"external": true`) {
			t.Fatalf("csr sign: err=%v out=%s", err, signOut)
		}
		if _, err := os.Stat(filepath.Join(csrDir, "ext.pem")); err != nil {
			t.Fatalf("csr sign --out: %v", err)
		}
		// stdin form
		csrRaw, _ := os.ReadFile(filepath.Join(csrDir, "ext.csr.pem"))
		var o, e bytes.Buffer
		if err := run(ctx, []string{"--store-dir", storeDir, "csr", "sign", "--csr", "-", "--name", "ext-stdin"}, bytes.NewReader(csrRaw), &o, &e); err != nil {
			t.Fatalf("csr sign stdin: %v", err)
		}
		if out, err := runArgs("--store-dir", storeDir, "doctor"); err != nil && strings.Contains(out, "ext.internal") {
			t.Fatalf("doctor must accept CSR-signed certs without keys: %s", out)
		}
		// SPIFFE SVID + bundle
		if _, err := runArgs("--store-dir", storeDir, "svid", "issue", "--name", "cli-svid", "--id", "spiffe://cli.test/ns/a/sa/b"); err != nil {
			t.Fatalf("svid issue: %v", err)
		}
		if out, err := runArgs("--store-dir", storeDir, "svid", "verify", "--name", "cli-svid", "--ca", "root-ca", "--trust-domain", "cli.test"); err != nil || !strings.Contains(out, `"valid": true`) {
			t.Fatalf("svid verify: err=%v out=%s", err, out)
		}
		if _, err := runArgs("--store-dir", storeDir, "svid", "verify", "--name", "cli-svid", "--ca", "root-ca", "--trust-domain", "other"); err == nil {
			t.Fatal("svid verify must fail on trust-domain mismatch")
		}
		if out, err := runArgs("--store-dir", storeDir, "bundle", "export", "--ca", "root-ca"); err != nil || !strings.Contains(out, "spiffe_sequence") {
			t.Fatalf("bundle export: err=%v out=%s", err, out)
		}
		bpath := filepath.Join(t.TempDir(), "b.pem")
		if _, err := runArgs("--store-dir", storeDir, "bundle", "export", "--ca", "root-ca", "--format", "pem", "--out", bpath); err != nil {
			t.Fatalf("bundle export pem: %v", err)
		}
		for _, bad := range [][]string{{"svid"}, {"svid", "nope"}, {"svid", "issue"}, {"bundle"}, {"bundle", "export", "--format", "x"}} {
			if _, err := runArgs(append([]string{"--store-dir", storeDir}, bad...)...); err == nil {
				t.Fatalf("expected error for %v", bad)
			}
		}
		t.Setenv("MGTLS_PASSPHRASE", "cli-pass")
		t.Setenv("MGTLS_NEW_PASSPHRASE", "cli-pass-2")
		for _, sub := range []string{"status", "seal", "rotate", "unseal"} {
			if sub == "unseal" {
				t.Setenv("MGTLS_PASSPHRASE", "cli-pass-2")
			}
			if out, err := runArgs("--store-dir", storeDir, "vault", sub); err != nil {
				t.Fatalf("vault %s: %v %s", sub, err, out)
			}
			if sub == "seal" {
				if out, _ := runArgs("--store-dir", storeDir, "vault", "status"); !strings.Contains(out, `"sealed": true`) {
					t.Fatalf("expected sealed keys: %s", out)
				}
				if _, err := runArgs("--store-dir", storeDir, "cert", "issue", "--name", "after-seal", "--ca", "root-ca", "--dns", "a.internal"); err != nil {
					t.Fatalf("issuing with sealed CA key: %v", err)
				}
			}
		}
		t.Setenv("MGTLS_PASSPHRASE", "")

		// 15. RFC 7030 EST server + cacerts + enroll + reenroll
		estLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		estAddr := estLn.Addr().String()
		_ = estLn.Close()
		estCtx, estCancel := context.WithCancel(ctx)
		estDone := make(chan error, 1)
		go func() {
			var o, e bytes.Buffer
			estDone <- run(estCtx, []string{"--store-dir", storeDir, "est", "serve", "--ca", "root-ca", "--addr", estAddr, "--token", "cli-est-tok"}, strings.NewReader(""), &o, &e)
		}()
		estURL := "https://" + estAddr
		estOutDir := t.TempDir()
		for range 40 {
			if _, cErr := runArgs("--store-dir", storeDir, "est", "cacerts", "--url", estURL, "--ca", "root-ca", "--out", filepath.Join(estOutDir, "ca.pem")); cErr == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		enrOut, err := runArgs("--store-dir", storeDir, "est", "enroll", "--url", estURL, "--ca", "root-ca", "--token", "cli-est-tok", "--name", "est-cli-node", "--cn", "est-cli.internal", "--dns", "est-cli.internal", "--out-dir", estOutDir)
		if err != nil || !strings.Contains(enrOut, "est-cli.internal") {
			t.Fatalf("est enroll CLI failed: err=%v out=%s", err, enrOut)
		}
		reenrOut, err := runArgs("--store-dir", storeDir, "est", "reenroll", "--url", estURL, "--ca", "root-ca", "--name", "est-cli-node", "--cn", "est-cli.internal", "--dns", "est-cli.internal", "--key", filepath.Join(estOutDir, "est-cli-node.key.pem"), "--client-cert", filepath.Join(estOutDir, "est-cli-node.cert.pem"), "--client-key", filepath.Join(estOutDir, "est-cli-node.key.pem"), "--out-dir", t.TempDir())
		if err != nil || !strings.Contains(reenrOut, "est-cli.internal") {
			t.Fatalf("est reenroll CLI failed: err=%v out=%s", err, reenrOut)
		}
		estCancel()
		if sErr := <-estDone; sErr != nil {
			t.Fatalf("est serve CLI error: %v", sErr)
		}
	}

	// Negative CLI error paths
	errCases := [][]string{
		{"unknown-top-cmd"},
		{"ca"},
		{"ca", "unknown-sub"},
		{"cert"},
		{"cert", "unknown-sub"},
		{"cert", "inspect"},
		{"ssh"},
		{"ssh", "unknown-sub"},
		{"acme"},
		{"acme", "unknown-sub"},
		{"target"},
		{"target", "unknown-sub"},
		{"target", "generate"},
		{"probe"},
		{"ocsp"},
		{"ocsp", "unknown-sub"},
		{"csr"},
		{"csr", "unknown-sub"},
		{"csr", "sign"},
		{"csr", "create"},
		{"vault"},
		{"vault", "unknown-sub"},
		{"est"},
		{"est", "unknown-sub"},
		{"est", "cacerts"},
		{"est", "enroll"},
		{"mcp", "serve", "--transport", "unsupported-proto"},
	}
	for _, tc := range errCases {
		full := append([]string{"--store-dir", storeDir}, tc...)
		if _, err := runArgs(full...); err == nil {
			t.Errorf("expected error for CLI args %v, got nil", tc)
		}
	}
}

