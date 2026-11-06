package targets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestSupportedTargets(t *testing.T) {
	specs := SupportedTargets()
	if len(specs) != 14 {
		t.Fatalf("expected 14 supported targets, got %d", len(specs))
	}

	expected := map[string][]string{
		"fastapi":        {"app.py", "run_server.sh", "client_mtls.py", "verify_mtls.sh"},
		"springboot":     {"application-tls.yml", "MtlsSecurityConfig.java", "MtlsRestClientConfig.java", "verify_mtls.sh"},
		"mcp":            {"mcp_server_mtls.ts", "mcp_server_mtls.py", "mcp_client_config.json", "nginx_mcp_sidecar.conf", "verify_mcp_mtls.sh"},
		"nginx":          {"nginx-mtls.conf", "verify_nginx_mtls.sh"},
		"vite":           {"vite.config.mtls.ts", "client_fetch_mtls.mjs"},
		"proxmox":        {"deploy_proxmox_cert.sh", "proxmox_pveproxy_verify.sh", "README-proxmox.md"},
		"openssh":        {"sshd_ca.conf", "ssh_client_ca.conf", "deploy_ssh_ca.sh"},
		"caddy":          {"Caddyfile", "verify_caddy_mtls.sh"},
		"traefik":        {"traefik-dynamic-tls.yml", "verify_traefik_mtls.sh"},
		"envoy":          {"envoy-mtls.yaml", "verify_envoy_mtls.sh"},
		"postgres":       {"postgresql-ssl.conf", "pg_hba_mtls.conf", "verify_postgres_mtls.sh"},
		"redis":          {"redis-tls.conf", "verify_redis_mtls.sh"},
		"grpc-go":        {"grpc_mtls.go", "verify_grpc_mtls.sh"},
		"nodejs-express": {"server_mtls.mjs", "verify_node_mtls.sh"},
	}

	for _, sp := range specs {
		wantFiles, ok := expected[sp.ID]
		if !ok {
			t.Fatalf("unexpected target ID %q", sp.ID)
		}
		if len(sp.Files) != len(wantFiles) {
			t.Fatalf("target %s: expected %d files, got %d", sp.ID, len(wantFiles), len(sp.Files))
		}
		for i, f := range wantFiles {
			if sp.Files[i] != f {
				t.Errorf("target %s file[%d]: want %q, got %q", sp.ID, i, f, sp.Files[i])
			}
		}
	}
}

func TestGenerateAllTargets(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := store.New(filepath.Join(tmpDir, "store"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	if err := s.Init(); err != nil {
		t.Fatalf("s.Init: %v", err)
	}

	srcDir := filepath.Join(tmpDir, "dummy-pki")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir dummy-pki: %v", err)
	}

	caCert := filepath.Join(srcDir, "root-ca.pem")
	srvCert := filepath.Join(srcDir, "srv-cert.pem")
	srvKey := filepath.Join(srcDir, "srv-key.pem")
	cliCert := filepath.Join(srcDir, "cli-cert.pem")
	cliKey := filepath.Join(srcDir, "cli-key.pem")

	for path, content := range map[string]string{
		caCert:  "DUMMY-CA-CERT",
		srvCert: "DUMMY-SERVER-CERT",
		srvKey:  "DUMMY-SERVER-KEY",
		cliCert: "DUMMY-CLIENT-CERT",
		cliKey:  "DUMMY-CLIENT-KEY",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write dummy file %s: %v", path, err)
		}
	}

	specs := SupportedTargets()
	for i, sp := range specs {
		targetName := fmt.Sprintf("target-%s", sp.ID)
		host := fmt.Sprintf("%s.internal.local", sp.ID)
		port := 9000 + i

		res, err := Generate(s, GenerateRequest{
			Name:           targetName,
			TargetType:     sp.ID,
			Host:           host,
			Port:           port,
			MutualTLS:      true,
			CAName:         "corp-root-ca",
			CACertPath:     caCert,
			ServerCert:     "srv-bundle",
			ServerCertPath: srvCert,
			ServerKeyPath:  srvKey,
			ClientCert:     "cli-bundle",
			ClientCertPath: cliCert,
			ClientKeyPath:  cliKey,
		})
		if err != nil {
			t.Fatalf("Generate(%s) failed: %v", sp.ID, err)
		}

		expectedOutDir := s.Path("targets", targetName)
		if res.Record.OutputDir != expectedOutDir {
			t.Errorf("target %s: expected OutputDir %q, got %q", sp.ID, expectedOutDir, res.Record.OutputDir)
		}
		if len(res.Record.Files) != len(sp.Files) {
			t.Fatalf("target %s: expected %d recorded files, got %d", sp.ID, len(sp.Files), len(res.Record.Files))
		}

		// Verify copied certs & keys in OutputDir/certs/
		copiedKeyInfo, err := os.Stat(filepath.Join(expectedOutDir, "certs", "server.key"))
		if err != nil {
			t.Fatalf("target %s: missing copied server.key: %v", sp.ID, err)
		}
		if copiedKeyInfo.Mode().Perm() != 0600 {
			t.Errorf("target %s: expected server.key mode 0600, got %o", sp.ID, copiedKeyInfo.Mode().Perm())
		}
		copiedCertInfo, err := os.Stat(filepath.Join(expectedOutDir, "certs", "ca.crt"))
		if err != nil {
			t.Fatalf("target %s: missing copied ca.crt: %v", sp.ID, err)
		}
		if copiedCertInfo.Mode().Perm() != 0644 {
			t.Errorf("target %s: expected ca.crt mode 0644, got %o", sp.ID, copiedCertInfo.Mode().Perm())
		}

		var combinedContent strings.Builder
		for _, wantFile := range sp.Files {
			fp := filepath.Join(expectedOutDir, wantFile)
			info, err := os.Stat(fp)
			if err != nil {
				t.Fatalf("target %s: expected file %s on disk: %v", sp.ID, fp, err)
			}
			if info.Size() == 0 {
				t.Errorf("target %s: file %s is empty", sp.ID, fp)
			}
			if strings.HasSuffix(wantFile, ".sh") && info.Mode().Perm() != 0755 {
				t.Errorf("target %s: expected script %s mode 0755, got %o", sp.ID, wantFile, info.Mode().Perm())
			}
			raw, err := os.ReadFile(fp)
			if err != nil {
				t.Fatalf("target %s: read %s: %v", sp.ID, fp, err)
			}
			combinedContent.Write(raw)
		}

		allText := combinedContent.String()
		portStr := fmt.Sprintf("%d", port)
		for _, needle := range []string{host, portStr, caCert, srvCert, srvKey, cliCert, cliKey} {
			if !strings.Contains(allText, needle) {
				t.Errorf("target %s: rendered files did not contain expected value %q", sp.ID, needle)
			}
		}
	}

	manifest, err := s.LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(manifest.Targets) != len(specs) {
		t.Fatalf("expected %d targets in manifest, got %d", len(specs), len(manifest.Targets))
	}

	if _, err := Generate(s, GenerateRequest{Name: "bad", TargetType: "nonexistent"}); err == nil {
		t.Errorf("expected error for unsupported target type, got nil")
	}
	if _, err := Generate(s, GenerateRequest{Name: "empty", TargetType: "   "}); err == nil {
		t.Errorf("expected error for empty target type, got nil")
	}
	if _, err := Generate(nil, GenerateRequest{TargetType: "fastapi"}); err == nil {
		t.Errorf("expected error for nil store, got nil")
	}
}

func TestGenerateDefaultsAndTLSOnlyMode(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := store.New(filepath.Join(tmpDir, "store"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	if err := s.Init(); err != nil {
		t.Fatalf("s.Init: %v", err)
	}

	if got := defaultPortForTarget("unknown-target"); got != 8443 {
		t.Errorf("expected default fallback port 8443, got %d", got)
	}

	wantPorts := map[string]int{
		"fastapi":        8443,
		"springboot":     8443,
		"mcp":            8444,
		"nginx":          443,
		"vite":           5173,
		"proxmox":        8006,
		"openssh":        22,
		"caddy":          443,
		"traefik":        443,
		"envoy":          10000,
		"postgres":       5432,
		"redis":          6379,
		"grpc-go":        50051,
		"nodejs-express": 3443,
	}

	for _, sp := range SupportedTargets() {
		customOut := filepath.Join(tmpDir, "custom-out", sp.ID)
		res, err := Generate(s, GenerateRequest{
			Name:           "", // defaults to targetType
			TargetType:     sp.ID,
			OutputDir:      customOut,
			Host:           "",    // defaults to localhost
			Port:           0,     // defaults to defaultPortForTarget
			MutualTLS:      false, // TLS-only mode
			CACertPath:     "",    // defaults to certs/ca.crt
			ServerCertPath: "/nonexistent/server.crt",
			Extra:          map[string]string{"custom_key": "custom_val"},
		})
		if err != nil {
			t.Fatalf("Generate(%s, MutualTLS=false) failed: %v", sp.ID, err)
		}
		if res.Record.Name != sp.ID {
			t.Errorf("expected defaulted Name %q, got %q", sp.ID, res.Record.Name)
		}
		wantNote := fmt.Sprintf("localhost:%d (mTLS=false)", wantPorts[sp.ID])
		foundNote := false
		for _, n := range res.Notes {
			if strings.Contains(n, wantNote) {
				foundNote = true
				break
			}
		}
		if !foundNote {
			t.Errorf("target %s: expected note containing %q, got %v", sp.ID, wantNote, res.Notes)
		}
	}
}

