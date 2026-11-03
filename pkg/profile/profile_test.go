package profile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/pkg/pki"
	"github.com/sysadmin/mgtls/pkg/store"
)

const testFleetYAML = `
version: "1.0"
cas:
  - name: root-ca
    common_name: "Test Root CA"
    organization: "Test Org"
    country: "US"
    algorithm: ed25519
    valid_days: 3650

  - name: intermediate-ca
    parent_ca: root-ca
    common_name: "Test Intermediate CA"
    organization: "Test Org"
    country: "US"
    algorithm: ecdsa-p256
    valid_days: 1825

self_signed:
  - name: local-selfsigned
    common_name: "local.dev"
    role: mtls
    algorithm: ed25519
    valid_days: 365
    dns_names:
      - local.dev
      - localhost
    ip_addresses:
      - 127.0.0.1

certs:
  - name: server-mtls
    ca_name: intermediate-ca
    common_name: "api.internal"
    role: server
    algorithm: ecdsa-p256
    valid_days: 365
    dns_names:
      - api.internal
      - "*.api.internal"
      - localhost
    ip_addresses:
      - 127.0.0.1
    uris:
      - spiffe://internal/ns/prod/sa/api-server

  - name: client-mtls
    ca_name: intermediate-ca
    common_name: "worker-client"
    role: client
    algorithm: ed25519
    valid_days: 365
    dns_names:
      - worker.internal
    uris:
      - spiffe://internal/ns/prod/sa/worker-client

ssh_cas:
  - name: ssh-user-ca
    ca_type: user
    algorithm: ed25519
    comment: "user-ca@internal"

  - name: ssh-host-ca
    ca_type: host
    algorithm: ed25519
    comment: "host-ca@internal"

ssh_certs:
  - name: alice-user-cert
    ca_name: ssh-user-ca
    cert_type: user
    key_id: "alice@internal"
    principals:
      - alice
      - admin
      - root
    valid_hours: 720
    algorithm: ed25519

  - name: bastion-host-cert
    ca_name: ssh-host-ca
    cert_type: host
    key_id: "bastion.internal"
    principals:
      - bastion.internal
      - "*.internal"
    valid_hours: 8760
    algorithm: ed25519

ssh_configs:
  - name: prod-ssh-bundle
    user_ca_name: ssh-user-ca
    host_ca_name: ssh-host-ca
    host_cert_name: bastion-host-cert
    user_cert_name: alice-user-cert
    host_patterns:
      - "*.internal"
    principals:
      - alice
      - admin
      - root

targets:
  - name: tgt-fastapi
    target_type: fastapi
    host: api.internal
    port: 8443
    mutual_tls: true
    ca_name: intermediate-ca
    server_cert: server-mtls
    client_cert: client-mtls

  - name: tgt-springboot
    target_type: springboot
    host: api.internal
    port: 8443
    mutual_tls: true
    ca_name: intermediate-ca
    server_cert: server-mtls
    client_cert: client-mtls

  - name: tgt-mcp
    target_type: mcp
    host: mcp.internal
    port: 8444
    mutual_tls: true
    ca_name: intermediate-ca
    server_cert: server-mtls
    client_cert: client-mtls

  - name: tgt-nginx
    target_type: nginx
    host: gateway.internal
    port: 443
    mutual_tls: true
    ca_name: intermediate-ca
    server_cert: server-mtls
    client_cert: client-mtls
    extra:
      upstream_url: "http://127.0.0.1:8000"

  - name: tgt-vite
    target_type: vite
    host: vite.internal
    port: 5173
    mutual_tls: true
    ca_name: intermediate-ca
    server_cert: server-mtls
    client_cert: client-mtls

  - name: tgt-proxmox
    target_type: proxmox
    host: pve01.internal
    port: 8006
    mutual_tls: false
    ca_name: intermediate-ca
    server_cert: server-mtls
    client_cert: client-mtls

  - name: tgt-openssh
    target_type: openssh
    host: bastion.internal
    port: 22
    mutual_tls: true
    ca_name: ssh-user-ca
    server_cert: bastion-host-cert
    client_cert: alice-user-cert
`

func TestParseAndApplyFleetSpec(t *testing.T) {
	tmpDir := t.TempDir()
	specPath := filepath.Join(tmpDir, "fleet.yaml")
	if err := os.WriteFile(specPath, []byte(testFleetYAML), 0644); err != nil {
		t.Fatalf("write fleet.yaml: %v", err)
	}

	spec, err := LoadFleetSpec(specPath)
	if err != nil {
		t.Fatalf("LoadFleetSpec failed: %v", err)
	}

	if spec.Version != "1.0" {
		t.Errorf("expected version 1.0, got %q", spec.Version)
	}
	if len(spec.CAs) != 2 {
		t.Fatalf("expected 2 CAs, got %d", len(spec.CAs))
	}
	if len(spec.SelfSigned) != 1 {
		t.Fatalf("expected 1 SelfSigned cert, got %d", len(spec.SelfSigned))
	}
	if len(spec.Certs) != 2 {
		t.Fatalf("expected 2 Certs, got %d", len(spec.Certs))
	}
	if len(spec.SSHCAs) != 2 {
		t.Fatalf("expected 2 SSH CAs, got %d", len(spec.SSHCAs))
	}
	if len(spec.SSHCerts) != 2 {
		t.Fatalf("expected 2 SSH Certs, got %d", len(spec.SSHCerts))
	}
	if len(spec.SSHConfigs) != 1 {
		t.Fatalf("expected 1 SSHConfig, got %d", len(spec.SSHConfigs))
	}
	if len(spec.Targets) != 7 {
		t.Fatalf("expected 7 Targets, got %d", len(spec.Targets))
	}

	s, err := store.New(filepath.Join(tmpDir, "store"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	report, err := Apply(context.Background(), s, spec)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if len(report.CAsCreated) != 2 || report.CAsCreated[0] != "root-ca" || report.CAsCreated[1] != "intermediate-ca" {
		t.Errorf("unexpected CAsCreated: %v", report.CAsCreated)
	}
	if len(report.SelfSignedCreated) != 1 || report.SelfSignedCreated[0] != "local-selfsigned" {
		t.Errorf("unexpected SelfSignedCreated: %v", report.SelfSignedCreated)
	}
	if len(report.CertsIssued) != 2 {
		t.Errorf("unexpected CertsIssued: %v", report.CertsIssued)
	}
	if len(report.SSHCAsCreated) != 2 {
		t.Errorf("unexpected SSHCAsCreated: %v", report.SSHCAsCreated)
	}
	if len(report.SSHCertsSigned) != 2 {
		t.Errorf("unexpected SSHCertsSigned: %v", report.SSHCertsSigned)
	}
	if len(report.SSHConfigsBuilt) != 1 || report.SSHConfigsBuilt[0] != "prod-ssh-bundle" {
		t.Errorf("unexpected SSHConfigsBuilt: %v", report.SSHConfigsBuilt)
	}
	if len(report.TargetsGenerated) != 7 {
		t.Errorf("expected 7 TargetsGenerated, got %d: %v", len(report.TargetsGenerated), report.TargetsGenerated)
	}

	// Verify automatic path resolution copied non-empty cert/key material into each target's certs/ dir.
	interCA, err := s.GetCA("intermediate-ca")
	if err != nil {
		t.Fatalf("GetCA(intermediate-ca): %v", err)
	}
	srvCert, err := s.GetCert("server-mtls")
	if err != nil {
		t.Fatalf("GetCert(server-mtls): %v", err)
	}
	cliCert, err := s.GetCert("client-mtls")
	if err != nil {
		t.Fatalf("GetCert(client-mtls): %v", err)
	}

	for _, targetName := range []string{"tgt-fastapi", "tgt-springboot", "tgt-mcp", "tgt-nginx", "tgt-vite", "tgt-proxmox"} {
		outDir := s.Path("targets", targetName)
		for _, certFile := range []string{"ca.crt", "server.crt", "server.key", "client.crt", "client.key"} {
			fp := filepath.Join(outDir, "certs", certFile)
			info, err := os.Stat(fp)
			if err != nil {
				t.Fatalf("target %s missing resolved artifact %s: %v", targetName, fp, err)
			}
			if info.Size() == 0 {
				t.Errorf("target %s artifact %s is empty", targetName, fp)
			}
		}

		// Verify rendered files reference the store's resolved paths.
		entries, err := os.ReadDir(outDir)
		if err != nil {
			t.Fatalf("ReadDir(%s): %v", outDir, err)
		}
		var combined strings.Builder
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(outDir, e.Name()))
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			combined.Write(raw)
		}
		text := combined.String()
		for _, wantPath := range []string{interCA.ChainPath, srvCert.FullChainPath, srvCert.KeyPath, cliCert.CertPath, cliCert.KeyPath} {
			if !strings.Contains(text, wantPath) {
				t.Errorf("target %s rendered files did not contain resolved store path %q", targetName, wantPath)
			}
		}
	}

	// Also verify openssh target resolved SSH CA and certs.
	sshOutDir := s.Path("targets", "tgt-openssh")
	for _, certFile := range []string{"ca.crt", "server.crt", "server.key", "client.crt", "client.key"} {
		fp := filepath.Join(sshOutDir, "certs", certFile)
		if info, err := os.Stat(fp); err != nil || info.Size() == 0 {
			t.Errorf("target tgt-openssh missing or empty %s: %v", fp, err)
		}
	}
}

func TestRunDoctor(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := store.New(filepath.Join(tmpDir, "store"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	spec, err := ParseFleetSpec([]byte(testFleetYAML))
	if err != nil {
		t.Fatalf("ParseFleetSpec: %v", err)
	}
	if _, err := Apply(context.Background(), s, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// 1. Healthy store check.
	doc, err := RunDoctor(s, 30)
	if err != nil {
		t.Fatalf("RunDoctor failed: %v", err)
	}
	if !doc.Healthy {
		t.Fatalf("expected store to be healthy, got findings: %+v", doc.Findings)
	}
	if len(doc.Findings) == 0 {
		t.Fatalf("expected non-empty findings for populated store")
	}

	// 2. Detect insecure private key permissions (0644 instead of 0600).
	srvCert, err := s.GetCert("server-mtls")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if err := os.Chmod(srvCert.KeyPath, 0644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	docPerm, err := RunDoctor(s, 30)
	if err != nil {
		t.Fatalf("RunDoctor after chmod: %v", err)
	}
	if docPerm.Healthy {
		t.Errorf("expected store to be unhealthy when private key has 0644 permissions")
	}
	foundPermFinding := false
	for _, f := range docPerm.Findings {
		if f.Kind == "permissions" && f.Name == "server-mtls" && f.Severity == "error" {
			foundPermFinding = true
			break
		}
	}
	if !foundPermFinding {
		t.Errorf("expected permissions error finding for server-mtls, got: %+v", docPerm.Findings)
	}

	// Restore 0600 permissions.
	if err := os.Chmod(srvCert.KeyPath, 0600); err != nil {
		t.Fatalf("Chmod restore: %v", err)
	}

	// 3. Detect expiring soon certificate.
	if _, err := pki.IssueCert(s, pki.CertRequest{
		Name:       "short-lived-cert",
		CAName:     "intermediate-ca",
		CommonName: "short.internal",
		Role:       "server",
		ValidDays:  5,
	}); err != nil {
		t.Fatalf("IssueCert short-lived: %v", err)
	}

	docExp, err := RunDoctor(s, 30)
	if err != nil {
		t.Fatalf("RunDoctor expiring: %v", err)
	}
	if docExp.Healthy {
		t.Errorf("expected store with expiring cert to report Healthy=false")
	}
	foundExpiring := false
	for _, f := range docExp.Findings {
		if f.Kind == "cert" && f.Name == "short-lived-cert" && f.Severity == "warning" {
			foundExpiring = true
			break
		}
	}
	if !foundExpiring {
		t.Errorf("expected warning finding for short-lived-cert, got: %+v", docExp.Findings)
	}
}
