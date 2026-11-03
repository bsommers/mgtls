package store

import (
	"os"
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
