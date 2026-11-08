package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKeyfile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vault.key")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSealOpenRoundTripPassphraseAndKeyfile(t *testing.T) {
	plain := []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	kf := writeKeyfile(t, strings.Repeat("k", 48))
	for name, cred := range map[string]Credential{
		"passphrase": {Passphrase: "correct horse battery staple"},
		"keyfile":    {KeyFile: kf},
	} {
		sealed, err := Seal(plain, cred)
		if err != nil {
			t.Fatalf("%s seal: %v", name, err)
		}
		if !IsSealed(sealed) || bytes.Contains(sealed, []byte("AAAA")) {
			t.Fatalf("%s: not sealed / plaintext leaked", name)
		}
		got, err := Open(sealed, cred)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%s open: %v", name, err)
		}
		// Two seals differ (random salt/nonce).
		again, _ := Seal(plain, cred)
		if bytes.Equal(sealed, again) {
			t.Fatalf("%s: seals must be non-deterministic", name)
		}
	}
}

func TestOpenNegativePaths(t *testing.T) {
	plain := []byte("secret")
	sealed, _ := Seal(plain, Credential{Passphrase: "right"})

	if _, err := Open(sealed, Credential{Passphrase: "wrong"}); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
	if _, err := Open(sealed, Credential{}); err == nil || !strings.Contains(err.Error(), EnvPassphrase) {
		t.Fatalf("missing credential must name env var, got %v", err)
	}
	if _, err := Open(sealed, Credential{KeyFile: writeKeyfile(t, strings.Repeat("k", 40))}); err == nil {
		t.Fatal("keyfile cannot open passphrase envelope")
	}
	// Tampered header (AAD) and tampered body both fail.
	tampered := bytes.Replace(sealed, []byte("N=32768"), []byte("N=16384"), 1)
	if _, err := Open(tampered, Credential{Passphrase: "right"}); err == nil {
		t.Fatal("tampered KDF params must fail")
	}
	// Hostile scrypt params are rejected before allocation.
	hostile := bytes.Replace(sealed, []byte("N=32768"), []byte("N=1073741824"), 1)
	if _, err := Open(hostile, Credential{Passphrase: "right"}); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("hostile params must be rejected, got %v", err)
	}
	// Plaintext passes through untouched.
	if got, err := Open(plain, Credential{}); err != nil || !bytes.Equal(got, plain) {
		t.Fatal("plaintext must pass through")
	}
	// Weak / world-readable keyfiles are refused.
	if _, err := Seal(plain, Credential{KeyFile: writeKeyfile(t, "short")}); err == nil {
		t.Fatal("short keyfile must fail")
	}
	loose := writeKeyfile(t, strings.Repeat("k", 40))
	_ = os.Chmod(loose, 0o644)
	if _, err := Seal(plain, Credential{KeyFile: loose}); err == nil {
		t.Fatal("group/world-readable keyfile must fail")
	}
	if _, err := Seal(plain, Credential{}); err == nil {
		t.Fatal("seal without credential must fail")
	}
}

func TestStoreSealUnsealRotateLifecycle(t *testing.T) {
	s, _ := New(t.TempDir())
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvKeyFile, "")
	t.Setenv(EnvPassphrase, "")

	// Vault off: WriteSecret == plaintext 0600.
	p, err := s.WriteSecret("ca/x/key.pem", []byte("PLAINKEY"))
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(p); string(raw) != "PLAINKEY" {
		t.Fatal("expected plaintext when vault off")
	}
	if err := s.UpsertCA(CARecord{Name: "x", KeyPath: p}); err != nil {
		t.Fatal(err)
	}

	// Seal in place.
	t.Setenv(EnvPassphrase, "pw1")
	rep, err := s.SealAll()
	if err != nil || rep.Changed != 1 {
		t.Fatalf("seal: %v %+v", err, rep)
	}
	if raw, _ := os.ReadFile(p); !IsSealed(raw) || bytes.Contains(raw, []byte("PLAINKEY")) {
		t.Fatal("key not sealed on disk")
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", info.Mode().Perm())
	}
	if got, err := ReadSecret(p); err != nil || string(got) != "PLAINKEY" {
		t.Fatalf("ReadSecret: %v %q", err, got)
	}
	if rep, _ := s.SealAll(); rep.Changed != 0 {
		t.Fatal("seal must be idempotent")
	}

	// New writes are sealed automatically.
	p2, _ := s.WriteSecret("ca/y/key.pem", []byte("KEY2"))
	if raw, _ := os.ReadFile(p2); !IsSealed(raw) {
		t.Fatal("WriteSecret must seal when vault on")
	}

	// Rotate to a keyfile; old passphrase no longer opens it.
	kf := writeKeyfile(t, strings.Repeat("z", 64))
	t.Setenv(EnvNewKeyFile, kf)
	if rep, err := s.RotateAll(); err != nil || rep.Changed != 1 {
		t.Fatalf("rotate: %v %+v", err, rep)
	}
	if _, err := ReadSecret(p); err == nil {
		t.Fatal("old passphrase must no longer work after rotate")
	}
	t.Setenv(EnvKeyFile, kf)
	if got, err := ReadSecret(p); err != nil || string(got) != "PLAINKEY" {
		t.Fatalf("after rotate: %v %q", err, got)
	}

	// Wrong credential: unseal fails and changes nothing.
	t.Setenv(EnvKeyFile, "")
	t.Setenv(EnvPassphrase, "nope")
	before, _ := os.ReadFile(p)
	if _, err := s.UnsealAll(); err == nil {
		t.Fatal("unseal with wrong credential must fail")
	}
	if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
		t.Fatal("failed unseal must not modify files")
	}

	// Unseal with the right one.
	t.Setenv(EnvPassphrase, "")
	t.Setenv(EnvKeyFile, kf)
	if rep, err := s.UnsealAll(); err != nil || rep.Changed != 1 {
		t.Fatalf("unseal: %v %+v", err, rep)
	}
	if raw, _ := os.ReadFile(p); string(raw) != "PLAINKEY" {
		t.Fatal("unseal did not restore plaintext")
	}
	st, _ := s.VaultStatus()
	if len(st.Entries) != 1 || st.Entries[0].Status != "unsealed" {
		t.Fatalf("status: %+v", st)
	}
}
