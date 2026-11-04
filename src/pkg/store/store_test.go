package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreInitAndCRUD(t *testing.T) {
	tmp := t.TempDir()
	s, err := New(tmp)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := s.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	keyPath, err := s.WriteKey("ca/root/key.pem", []byte("secret-key"))
	if err != nil {
		t.Fatalf("WriteKey failed: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 key perm, got %o", info.Mode().Perm())
	}

	pubPath, err := s.WritePublic("ca/root/cert.pem", []byte("public-cert"))
	if err != nil {
		t.Fatalf("WritePublic failed: %v", err)
	}
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("stat pub: %v", err)
	}
	if pubInfo.Mode().Perm() != 0644 {
		t.Fatalf("expected 0644 pub perm, got %o", pubInfo.Mode().Perm())
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := s.UpsertCA(CARecord{
		Name:       "root-ca",
		CommonName: "Test Root CA",
		IsRoot:     true,
		Algorithm:  "ed25519",
		CertPath:   pubPath,
		KeyPath:    keyPath,
		NotBefore:  now,
		NotAfter:   now.Add(365 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("UpsertCA: %v", err)
	}

	ca, err := s.GetCA("root-ca")
	if err != nil {
		t.Fatalf("GetCA: %v", err)
	}
	if ca.CommonName != "Test Root CA" {
		t.Fatalf("unexpected CA CN: %s", ca.CommonName)
	}

	if err := s.UpsertCert(CertRecord{Name: "api-server", CommonName: "api.local", Role: "mtls"}); err != nil {
		t.Fatalf("UpsertCert: %v", err)
	}
	if err := s.UpsertSSHCA(SSHCARecord{Name: "ssh-user-ca", CAType: "user", Algorithm: "ed25519"}); err != nil {
		t.Fatalf("UpsertSSHCA: %v", err)
	}
	if err := s.UpsertSSHCert(SSHCertRecord{Name: "alice-ssh", CAName: "ssh-user-ca", CertType: "user", Principals: []string{"alice"}}); err != nil {
		t.Fatalf("UpsertSSHCert: %v", err)
	}
	if err := s.UpsertACME(ACMERecord{Name: "le-prod", Provider: "letsencrypt", Domains: []string{"example.com"}}); err != nil {
		t.Fatalf("UpsertACME: %v", err)
	}
	if err := s.UpsertTarget(TargetRecord{Name: "fastapi-mtls", TargetType: "fastapi"}); err != nil {
		t.Fatalf("UpsertTarget: %v", err)
	}

	m, err := s.LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(m.CAs) != 1 || len(m.Certs) != 1 || len(m.SSHCAs) != 1 || len(m.SSHCerts) != 1 || len(m.ACMECerts) != 1 || len(m.Targets) != 1 {
		t.Fatalf("unexpected manifest counts: %+v", m)
	}
}

func TestStoreDefaultBaseDirGettersUpsertReplaceAndCorruptedManifest(t *testing.T) {
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	tmpWD := t.TempDir()
	if err := os.Chdir(tmpWD); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()

	// 1. Test New("") default .mgtls resolution
	s, err := New("")
	if err != nil {
		t.Fatalf("New(\"\") failed: %v", err)
	}
	expectedBase := filepath.Join(tmpWD, ".mgtls")
	if s.BaseDir != expectedBase {
		t.Fatalf("expected BaseDir %q, got %q", expectedBase, s.BaseDir)
	}
	if err := s.Init(); err != nil {
		t.Fatalf("Init default store: %v", err)
	}

	// 2. Test GetCA, GetCert, GetSSHCA not-found errors
	if _, err := s.GetCA("missing-ca"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected GetCA not found error, got %v", err)
	}
	if _, err := s.GetCert("missing-cert"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected GetCert not found error, got %v", err)
	}
	if _, err := s.GetSSHCA("missing-ssh-ca"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected GetSSHCA not found error, got %v", err)
	}

	// 3. Test Upsert initial + in-place replacement for all record types
	if err := s.UpsertCA(CARecord{Name: "ca1", CommonName: "Old CN", Algorithm: "ed25519"}); err != nil {
		t.Fatalf("UpsertCA initial: %v", err)
	}
	if err := s.UpsertCA(CARecord{Name: "ca1", CommonName: "New CN", Algorithm: "ecdsa-p384"}); err != nil {
		t.Fatalf("UpsertCA update: %v", err)
	}
	caRec, err := s.GetCA("ca1")
	if err != nil || caRec.CommonName != "New CN" || caRec.Algorithm != "ecdsa-p384" {
		t.Fatalf("GetCA after replace mismatch: %+v, err=%v", caRec, err)
	}

	if err := s.UpsertCert(CertRecord{Name: "cert1", CommonName: "old.local", Role: "server"}); err != nil {
		t.Fatalf("UpsertCert initial: %v", err)
	}
	if err := s.UpsertCert(CertRecord{Name: "cert1", CommonName: "new.local", Role: "mtls", Revoked: true}); err != nil {
		t.Fatalf("UpsertCert update: %v", err)
	}
	certRec, err := s.GetCert("cert1")
	if err != nil || certRec.CommonName != "new.local" || certRec.Role != "mtls" || !certRec.Revoked {
		t.Fatalf("GetCert after replace mismatch: %+v, err=%v", certRec, err)
	}

	if err := s.UpsertSSHCA(SSHCARecord{Name: "sshca1", CAType: "user", Algorithm: "ed25519"}); err != nil {
		t.Fatalf("UpsertSSHCA initial: %v", err)
	}
	if err := s.UpsertSSHCA(SSHCARecord{Name: "sshca1", CAType: "host", Algorithm: "rsa-4096"}); err != nil {
		t.Fatalf("UpsertSSHCA update: %v", err)
	}
	sshCARec, err := s.GetSSHCA("sshca1")
	if err != nil || sshCARec.CAType != "host" || sshCARec.Algorithm != "rsa-4096" {
		t.Fatalf("GetSSHCA after replace mismatch: %+v, err=%v", sshCARec, err)
	}

	if err := s.UpsertSSHCert(SSHCertRecord{Name: "sshcert1", KeyID: "old-id", Serial: 1}); err != nil {
		t.Fatalf("UpsertSSHCert initial: %v", err)
	}
	if err := s.UpsertSSHCert(SSHCertRecord{Name: "sshcert1", KeyID: "new-id", Serial: 2}); err != nil {
		t.Fatalf("UpsertSSHCert update: %v", err)
	}

	if err := s.UpsertACME(ACMERecord{Name: "acme1", Provider: "letsencrypt", Email: "old@example.com"}); err != nil {
		t.Fatalf("UpsertACME initial: %v", err)
	}
	if err := s.UpsertACME(ACMERecord{Name: "acme1", Provider: "zerossl", Email: "new@example.com"}); err != nil {
		t.Fatalf("UpsertACME update: %v", err)
	}

	if err := s.UpsertTarget(TargetRecord{Name: "tgt1", TargetType: "nginx"}); err != nil {
		t.Fatalf("UpsertTarget initial: %v", err)
	}
	if err := s.UpsertTarget(TargetRecord{Name: "tgt1", TargetType: "envoy"}); err != nil {
		t.Fatalf("UpsertTarget update: %v", err)
	}

	m, err := s.LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest after updates: %v", err)
	}
	if len(m.CAs) != 1 || len(m.Certs) != 1 || len(m.SSHCAs) != 1 || len(m.SSHCerts) != 1 || len(m.ACMECerts) != 1 || len(m.Targets) != 1 {
		t.Fatalf("expected exactly 1 record per collection after in-place updates, got %+v", m)
	}
	if m.SSHCerts[0].KeyID != "new-id" || m.ACMECerts[0].Provider != "zerossl" || m.Targets[0].TargetType != "envoy" {
		t.Fatalf("unexpected updated fields in manifest: %+v", m)
	}

	// 4. Test corrupted manifest.json handling
	manifestPath := s.Path("manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{corrupted-json"), 0600); err != nil {
		t.Fatalf("write corrupted manifest: %v", err)
	}
	if _, err := s.LoadManifest(); err == nil || !strings.Contains(err.Error(), "unmarshal manifest") {
		t.Fatalf("expected unmarshal error from LoadManifest on corrupted manifest.json, got %v", err)
	}
	if err := s.UpsertCA(CARecord{Name: "fail"}); err == nil {
		t.Fatalf("expected UpsertCA to fail on corrupted manifest")
	}
	if err := s.UpsertCert(CertRecord{Name: "fail"}); err == nil {
		t.Fatalf("expected UpsertCert to fail on corrupted manifest")
	}
	if err := s.UpsertSSHCA(SSHCARecord{Name: "fail"}); err == nil {
		t.Fatalf("expected UpsertSSHCA to fail on corrupted manifest")
	}
	if err := s.UpsertSSHCert(SSHCertRecord{Name: "fail"}); err == nil {
		t.Fatalf("expected UpsertSSHCert to fail on corrupted manifest")
	}
	if err := s.UpsertACME(ACMERecord{Name: "fail"}); err == nil {
		t.Fatalf("expected UpsertACME to fail on corrupted manifest")
	}
	if err := s.UpsertTarget(TargetRecord{Name: "fail"}); err == nil {
		t.Fatalf("expected UpsertTarget to fail on corrupted manifest")
	}
	if _, err := s.GetCA("ca1"); err == nil {
		t.Fatalf("expected GetCA to fail on corrupted manifest")
	}
	if _, err := s.GetCert("cert1"); err == nil {
		t.Fatalf("expected GetCert to fail on corrupted manifest")
	}
	if _, err := s.GetSSHCA("sshca1"); err == nil {
		t.Fatalf("expected GetSSHCA to fail on corrupted manifest")
	}
}

