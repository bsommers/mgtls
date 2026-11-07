package sshca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/store"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestSSHCALifecycleAndCertVerification(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := store.New(tmpDir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	if err := st.Init(); err != nil {
		t.Fatalf("st.Init: %v", err)
	}

	// 1. Create User CA (ed25519) and Host CA (ecdsa-p256) and RSA CA (rsa-4096)
	userCARes, err := CreateSSHCA(st, SSHCARequest{
		Name:      "prod-user-ca",
		CAType:    "user",
		Algorithm: "ed25519",
		Comment:   "prod-user-ca@internal",
	})
	if err != nil {
		t.Fatalf("CreateSSHCA user: %v", err)
	}
	if userCARes.Record.CAType != "user" || userCARes.Record.Algorithm != "ed25519" {
		t.Fatalf("unexpected user CA record: %+v", userCARes.Record)
	}

	hostCARes, err := CreateSSHCA(st, SSHCARequest{
		Name:      "prod-host-ca",
		CAType:    "host",
		Algorithm: "ecdsa-p256",
		Comment:   "prod-host-ca@internal",
	})
	if err != nil {
		t.Fatalf("CreateSSHCA host: %v", err)
	}
	if hostCARes.Record.CAType != "host" || hostCARes.Record.Algorithm != "ecdsa-p256" {
		t.Fatalf("unexpected host CA record: %+v", hostCARes.Record)
	}

	rsaCARes, err := CreateSSHCA(st, SSHCARequest{
		Name:      "legacy-rsa-ca",
		CAType:    "user",
		Algorithm: "rsa-4096",
	})
	if err != nil {
		t.Fatalf("CreateSSHCA rsa-4096: %v", err)
	}
	if rsaCARes.Record.Algorithm != "rsa-4096" {
		t.Fatalf("unexpected rsa CA algorithm: %s", rsaCARes.Record.Algorithm)
	}

	// Verify file permissions on CA private key (0600)
	privInfo, err := os.Stat(userCARes.Record.PrivKeyPath)
	if err != nil {
		t.Fatalf("stat user CA priv key: %v", err)
	}
	if privInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 on private key, got %o", privInfo.Mode().Perm())
	}

	// 2. Sign User Certificate with generated keypair
	userCertRes, err := SignSSHCert(st, SignSSHRequest{
		Name:       "alice-dev",
		CAName:     "prod-user-ca",
		KeyID:      "alice@example.com",
		Principals: []string{"alice", "admin"},
		ValidHours: 48,
	})
	if err != nil {
		t.Fatalf("SignSSHCert user (generated): %v", err)
	}
	if userCertRes.Record.CertType != "user" {
		t.Fatalf("expected user cert_type, got %s", userCertRes.Record.CertType)
	}

	// Sign restricted User Certificate with critical options
	restrictedCertRes, err := SignSSHCert(st, SignSSHRequest{
		Name:       "alice-restricted",
		CAName:     "prod-user-ca",
		KeyID:      "alice-restricted@example.com",
		Principals: []string{"alice"},
		CriticalOptions: map[string]string{
			"source-address": "10.0.0.0/8",
			"force-command":  "/usr/bin/id",
		},
	})
	if err != nil {
		t.Fatalf("SignSSHCert restricted: %v", err)
	}

	// 3. Sign User Certificate with an existing .pub key
	_, rawEdPub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshExistingPub, err := ssh.NewPublicKey(rawEdPub.Public())
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	existingPubFile := filepath.Join(tmpDir, "bob_existing.pub")
	if err := os.WriteFile(existingPubFile, ssh.MarshalAuthorizedKey(sshExistingPub), 0644); err != nil {
		t.Fatalf("write existing pub: %v", err)
	}

	bobCertRes, err := SignSSHCert(st, SignSSHRequest{
		Name:           "bob-existing",
		CAName:         "prod-user-ca",
		KeyID:          "bob@example.com",
		Principals:     []string{"bob"},
		ExistingPubKey: existingPubFile,
	})
	if err != nil {
		t.Fatalf("SignSSHCert user (existing pub): %v", err)
	}
	if bobCertRes.Record.PrivKeyPath != "" {
		t.Fatalf("expected empty PrivKeyPath for existing pubkey, got %s", bobCertRes.Record.PrivKeyPath)
	}

	// 4. Sign Host Certificate
	hostCertRes, err := SignSSHCert(st, SignSSHRequest{
		Name:       "node01-host",
		CAName:     "prod-host-ca",
		KeyID:      "node01.internal",
		Principals: []string{"node01.internal", "10.0.0.10"},
	})
	if err != nil {
		t.Fatalf("SignSSHCert host: %v", err)
	}
	if hostCertRes.Record.CertType != "host" {
		t.Fatalf("expected host cert_type, got %s", hostCertRes.Record.CertType)
	}

	// 5. Cryptographically verify User & Host certificates via ssh.CertChecker
	userCAPubRaw, err := os.ReadFile(userCARes.Record.PubKeyPath)
	if err != nil {
		t.Fatalf("read user CA pub: %v", err)
	}
	userCAPub, _, _, _, err := ssh.ParseAuthorizedKey(userCAPubRaw)
	if err != nil {
		t.Fatalf("parse user CA pub: %v", err)
	}

	hostCAPubRaw, err := os.ReadFile(hostCARes.Record.PubKeyPath)
	if err != nil {
		t.Fatalf("read host CA pub: %v", err)
	}
	hostCAPub, _, _, _, err := ssh.ParseAuthorizedKey(hostCAPubRaw)
	if err != nil {
		t.Fatalf("parse host CA pub: %v", err)
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), userCAPub.Marshal())
		},
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			return bytes.Equal(auth.Marshal(), hostCAPub.Marshal())
		},
	}

	// Parse Alice user cert & verify CheckCert
	aliceCertRaw, err := os.ReadFile(userCertRes.Record.CertPath)
	if err != nil {
		t.Fatalf("read alice cert: %v", err)
	}
	alicePub, _, _, _, err := ssh.ParseAuthorizedKey(aliceCertRaw)
	if err != nil {
		t.Fatalf("parse alice cert: %v", err)
	}
	aliceCert, ok := alicePub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("expected *ssh.Certificate for alice")
	}
	if !checker.IsUserAuthority(aliceCert.SignatureKey) {
		t.Fatalf("alice cert SignatureKey not recognized by IsUserAuthority")
	}
	if err := checker.CheckCert("alice", aliceCert); err != nil {
		t.Fatalf("CheckCert(alice) failed: %v", err)
	}
	if err := checker.CheckCert("unauthorized-principal", aliceCert); err == nil {
		t.Fatalf("expected CheckCert to fail for unauthorized principal")
	}

	// Parse Bob user cert & verify CheckCert
	bobCertRaw, err := os.ReadFile(bobCertRes.Record.CertPath)
	if err != nil {
		t.Fatalf("read bob cert: %v", err)
	}
	bobPub, _, _, _, err := ssh.ParseAuthorizedKey(bobCertRaw)
	if err != nil {
		t.Fatalf("parse bob cert: %v", err)
	}
	bobCert := bobPub.(*ssh.Certificate)
	if err := checker.CheckCert("bob", bobCert); err != nil {
		t.Fatalf("CheckCert(bob) failed: %v", err)
	}

	// Parse Host cert & verify CheckHostKey
	hostCertRaw, err := os.ReadFile(hostCertRes.Record.CertPath)
	if err != nil {
		t.Fatalf("read host cert: %v", err)
	}
	hostPub, _, _, _, err := ssh.ParseAuthorizedKey(hostCertRaw)
	if err != nil {
		t.Fatalf("parse host cert: %v", err)
	}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.10"), Port: 22}
	if err := checker.CheckHostKey("node01.internal:22", remoteAddr, hostPub); err != nil {
		t.Fatalf("CheckHostKey(node01.internal:22) failed: %v", err)
	}
	if err := checker.CheckHostKey("wronghost.internal:22", remoteAddr, hostPub); err == nil {
		t.Fatalf("expected CheckHostKey to fail for wrong hostname")
	}

	// 6. Test InspectSSHCert
	info, err := InspectSSHCert(userCertRes.Record.CertPath)
	if err != nil {
		t.Fatalf("InspectSSHCert: %v", err)
	}
	if info.KeyID != "alice@example.com" || info.CertType != "user" {
		t.Fatalf("unexpected InspectSSHCert info: %+v", info)
	}
	if info.CAFingerprint != userCARes.Record.Fingerprint {
		t.Fatalf("expected CAFingerprint %s, got %s", userCARes.Record.Fingerprint, info.CAFingerprint)
	}
	if _, ok := info.Extensions["permit-pty"]; !ok {
		t.Fatalf("expected default permit-pty extension in user cert: %+v", info.Extensions)
	}

	restrictedInfo, err := InspectSSHCert(restrictedCertRes.Record.CertPath)
	if err != nil {
		t.Fatalf("InspectSSHCert restricted: %v", err)
	}
	if restrictedInfo.CriticalOptions["source-address"] != "10.0.0.0/8" || restrictedInfo.CriticalOptions["force-command"] != "/usr/bin/id" {
		t.Fatalf("expected critical options, got %+v", restrictedInfo.CriticalOptions)
	}

	// 7. Test GenerateSSHConfigBundle
	bundleDir := filepath.Join(tmpDir, "bundle-out")
	bundle, err := GenerateSSHConfigBundle(st, SSHConfigRequest{
		Name:         "prod-ssh",
		UserCAName:   "prod-user-ca",
		HostCAName:   "prod-host-ca",
		HostCertName: "node01-host",
		UserCertName: "alice-dev",
		HostPatterns: []string{"*.internal", "10.0.0.*"},
		Principals:   []string{"alice", "admin", "deploy"},
		OutputDir:    bundleDir,
	})
	if err != nil {
		t.Fatalf("GenerateSSHConfigBundle: %v", err)
	}

	sshdConfBytes, err := os.ReadFile(bundle.SSHDConfigPath)
	if err != nil {
		t.Fatalf("read sshd_config: %v", err)
	}
	sshdConf := string(sshdConfBytes)
	for _, directive := range []string{"TrustedUserCAKeys", "HostKey", "HostCertificate", "AuthorizedPrincipalsFile"} {
		if !strings.Contains(sshdConf, directive) {
			t.Fatalf("sshd_config missing directive %q:\n%s", directive, sshdConf)
		}
	}

	knownHostsBytes, err := os.ReadFile(bundle.KnownHostsPath)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if !strings.HasPrefix(string(knownHostsBytes), "@cert-authority *.internal,10.0.0.* ") {
		t.Fatalf("unexpected known_hosts content: %s", string(knownHostsBytes))
	}

	authPrincBytes, err := os.ReadFile(bundle.AuthorizedPrincipals)
	if err != nil {
		t.Fatalf("read authorized_principals: %v", err)
	}
	if string(authPrincBytes) != "alice\nadmin\ndeploy\n" {
		t.Fatalf("unexpected authorized_principals content: %q", string(authPrincBytes))
	}

	clientConfBytes, err := os.ReadFile(bundle.SSHClientConfigPath)
	if err != nil {
		t.Fatalf("read ssh_client_config: %v", err)
	}
	for _, directive := range []string{"UserKnownHostsFile", "IdentityFile", "CertificateFile"} {
		if !strings.Contains(string(clientConfBytes), directive) {
			t.Fatalf("ssh_client_config missing directive %q:\n%s", directive, string(clientConfBytes))
		}
	}

	// 8. Negative & Edge Cases (Error paths, RSA-4096 cert signing, default OutputDir)
	if _, err := CreateSSHCA(st, SSHCARequest{Name: "bad-type", CAType: "invalid"}); err == nil {
		t.Fatalf("expected error for invalid CAType")
	}
	if _, err := CreateSSHCA(st, SSHCARequest{Name: "bad-algo", CAType: "user", Algorithm: "dsa-1024"}); err == nil {
		t.Fatalf("expected error for unsupported algorithm")
	}
	if _, err := SignSSHCert(st, SignSSHRequest{Name: "missing-ca", CAName: "no-such-ca", Principals: []string{"alice"}}); err == nil {
		t.Fatalf("expected error for missing CA")
	}
	if _, err := SignSSHCert(st, SignSSHRequest{Name: "bad-pub", CAName: "prod-user-ca", Principals: []string{"alice"}, ExistingPubKey: "/nonexistent/key.pub"}); err == nil {
		t.Fatalf("expected error for nonexistent ExistingPubKey")
	}
	// Sign using RSA-4096 CA and ecdsa-p256 leaf key
	if _, err := SignSSHCert(st, SignSSHRequest{
		Name:       "ecdsa-leaf",
		CAName:     "legacy-rsa-ca",
		Algorithm:  "ecdsa-p256",
		Principals: []string{"ops"},
	}); err != nil {
		t.Fatalf("SignSSHCert ecdsa-p256 leaf with RSA CA failed: %v", err)
	}
	// Inspect plain public key (not a certificate) -> error
	if _, err := InspectSSHCert(existingPubFile); err == nil {
		t.Fatalf("expected error when inspecting plain public key as SSH certificate")
	}
	// GenerateSSHConfigBundle with default OutputDir
	// Trusting a user CA without explicit principals must be refused (no silent root/admin default).
	if _, err := GenerateSSHConfigBundle(st, SSHConfigRequest{Name: "no-principals", UserCAName: "prod-user-ca"}); err == nil {
		t.Fatalf("expected error when trusting a user CA without principals")
	}
	if _, err := GenerateSSHConfigBundle(st, SSHConfigRequest{Name: "default-dir-bundle", UserCAName: "prod-user-ca", Principals: []string{"ops"}}); err != nil {
		t.Fatalf("GenerateSSHConfigBundle default dir: %v", err)
	}

	// 9. Hardware / ssh-agent Signer seam (CA private key never written to disk)
	_, hwSSHPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey hwSSHPriv: %v", err)
	}
	hwSSHSigner, err := ssh.NewSignerFromKey(hwSSHPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	hwSSHCARes, err := CreateSSHCA(st, SSHCARequest{
		Name:   "hw-ssh-ca",
		CAType: "user",
		Signer: hwSSHSigner,
	})
	if err != nil {
		t.Fatalf("CreateSSHCA with hardware Signer: %v", err)
	}
	if hwSSHCARes.Record.PrivKeyPath != "" {
		t.Fatalf("expected empty PrivKeyPath for hardware-backed SSH CA, got %q", hwSSHCARes.Record.PrivKeyPath)
	}

	// Start in-memory ssh-agent over UNIX domain socket
	sockPath := filepath.Join(tmpDir, "agent.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix agent.sock: %v", err)
	}
	defer ln.Close()
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: hwSSHPriv, Comment: "hw-ssh-ca"}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = agent.ServeAgent(keyring, c)
			}(conn)
		}
	}()

	agentSignedRes, err := SignSSHCert(st, SignSSHRequest{
		Name:        "agent-signed-user",
		CAName:      "hw-ssh-ca",
		Principals:  []string{"sre"},
		AgentSocket: sockPath,
	})
	if err != nil {
		t.Fatalf("SignSSHCert via AgentSocket failed: %v", err)
	}
	if _, err := InspectSSHCert(agentSignedRes.Record.CertPath); err != nil {
		t.Fatalf("InspectSSHCert on agent-signed cert failed: %v", err)
	}
}
