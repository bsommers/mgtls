package acme

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestProviders(t *testing.T) {
	provs := ListProviders()
	if len(provs) < 5 {
		t.Fatalf("expected at least 5 builtin providers, got %d", len(provs))
	}

	le, err := ResolveProvider("letsencrypt")
	if err != nil || le.ID != "letsencrypt" || le.RequiresEAB {
		t.Fatalf("ResolveProvider letsencrypt failed: %+v, err=%v", le, err)
	}

	zs, err := ResolveProvider("zerossl")
	if err != nil || !zs.RequiresEAB {
		t.Fatalf("ResolveProvider zerossl expected RequiresEAB: %+v, err=%v", zs, err)
	}

	custom, err := ResolveProvider("https://acme.example.internal/directory")
	if err != nil || custom.ID != "custom" {
		t.Fatalf("ResolveProvider custom URL failed: %+v, err=%v", custom, err)
	}

	if _, err := ResolveProvider("nonexistent-ca"); err == nil {
		t.Fatalf("expected error for unknown provider")
	}
}

func TestBuildTLSALPN01Cert(t *testing.T) {
	domain := "alpn.example.com"
	keyAuth := "test-token.test-thumbprint"
	tlsCert, err := BuildTLSALPN01Cert(domain, keyAuth)
	if err != nil {
		t.Fatalf("BuildTLSALPN01Cert: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatalf("empty certificate chain")
	}
	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	expectedOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
	found := false
	for _, ext := range parsed.Extensions {
		if ext.Id.Equal(expectedOID) {
			if !ext.Critical {
				t.Fatalf("expected acmeIdentifier extension to be critical")
			}
			var octet []byte
			if _, err := asn1.Unmarshal(ext.Value, &octet); err != nil {
				t.Fatalf("unmarshal extension value: %v", err)
			}
			sum := sha256.Sum256([]byte(keyAuth))
			if string(octet) != string(sum[:]) {
				t.Fatalf("acmeIdentifier digest mismatch")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("OID 1.3.6.1.5.5.7.1.31 extension not found on TLS-ALPN-01 certificate")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestObtainCertificateAllChallengesAndEAB(t *testing.T) {
	mock := NewMockACMEServer()
	defer mock.Close()

	tmpDir := t.TempDir()
	st, err := store.New(filepath.Join(tmpDir, "store"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. HTTP-01 with WebrootDir + ephemeral HTTPPort
	webroot := filepath.Join(tmpDir, "webroot")
	resHTTP, err := ObtainCertificate(ctx, st, ObtainRequest{
		Name:          "web-http01",
		Provider:      "custom",
		DirectoryURL:  mock.DirectoryURL(),
		Email:         "ops@example.com",
		Domains:       []string{"app.example.com", "www.app.example.com"},
		ChallengeType: "http-01",
		WebrootDir:    webroot,
		HTTPPort:      freePort(t),
	})
	if err != nil {
		t.Fatalf("ObtainCertificate http-01: %v", err)
	}
	verifyIssuedCert(t, resHTTP.Record.CertPath, mock.CACert, "app.example.com")

	// 2. DNS-01 with DNSExecHook + EAB (ZeroSSL)
	hookFile := filepath.Join(tmpDir, "dns-hook.txt")
	eabKey := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	resDNS, err := ObtainCertificate(ctx, st, ObtainRequest{
		Name:          "wildcard-dns01",
		Provider:      "zerossl",
		DirectoryURL:  mock.DirectoryURL(),
		Email:         "dns@example.com",
		Domains:       []string{"*.example.com", "example.com"},
		ChallengeType: "dns-01",
		DNSExecHook:   "echo \"$ACME_TXT_NAME=$ACME_TXT_VALUE\" >> " + hookFile,
		EABKID:        "eab-kid-123",
		EABHMACKey:    eabKey,
	})
	if err != nil {
		t.Fatalf("ObtainCertificate dns-01 + EAB: %v", err)
	}
	if len(resDNS.DNSTXTRecord) == 0 {
		t.Fatalf("expected DNSTXTRecord to be populated for dns-01")
	}
	if _, err := os.Stat(hookFile); err != nil {
		t.Fatalf("expected dns_exec_hook output file to exist: %v", err)
	}
	mock.mu.Lock()
	gotEAB := mock.LastEAB
	mock.mu.Unlock()
	if gotEAB == nil {
		t.Fatalf("expected mock server to receive externalAccountBinding")
	}

	// 3. TLS-ALPN-01 with ephemeral listener
	resALPN, err := ObtainCertificate(ctx, st, ObtainRequest{
		Name:          "alpn-cert",
		Provider:      "letsencrypt-staging",
		DirectoryURL:  mock.DirectoryURL(),
		Email:         "alpn@example.com",
		Domains:       []string{"tls.example.com"},
		ChallengeType: "tls-alpn-01",
		HTTPPort:      freePort(t),
	})
	if err != nil {
		t.Fatalf("ObtainCertificate tls-alpn-01: %v", err)
	}
	verifyIssuedCert(t, resALPN.Record.CertPath, mock.CACert, "tls.example.com")

	// 4. CheckRenewal
	dueNone, err := CheckRenewal(st, 10)
	if err != nil {
		t.Fatalf("CheckRenewal(10): %v", err)
	}
	if len(dueNone) != 0 {
		t.Fatalf("expected 0 certs due within 10 days, got %d", len(dueNone))
	}

	dueAll, err := CheckRenewal(st, 120)
	if err != nil {
		t.Fatalf("CheckRenewal(120): %v", err)
	}
	if len(dueAll) != 3 {
		t.Fatalf("expected 3 certs due within 120 days, got %d", len(dueAll))
	}

	// 5. Re-use existing account key on second ObtainCertificate with same Name
	if _, err := ObtainCertificate(ctx, st, ObtainRequest{
		Name:          "web-http01",
		Provider:      "buypass",
		DirectoryURL:  mock.DirectoryURL(),
		Email:         "ops@example.com",
		Domains:       []string{"renewed.example.com"},
		ChallengeType: "dns-01",
	}); err != nil {
		t.Fatalf("ObtainCertificate account key reuse: %v", err)
	}

	// 6. Negative error cases (missing domains, unsupported challenge, missing EAB on Google)
	if _, err := ObtainCertificate(ctx, st, ObtainRequest{Name: "no-domains", Provider: "custom", DirectoryURL: mock.DirectoryURL()}); err == nil {
		t.Fatalf("expected error for empty domains")
	}
	if _, err := ObtainCertificate(ctx, st, ObtainRequest{Name: "bad-chall", Provider: "custom", DirectoryURL: mock.DirectoryURL(), Domains: []string{"a.com"}, ChallengeType: "bad-01"}); err == nil {
		t.Fatalf("expected error for unsupported challenge type")
	}
}

func verifyIssuedCert(t *testing.T, certPath string, caCert *x509.Certificate, expectedDNS string) {
	t.Helper()
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert %s: %v", certPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("failed to decode PEM from %s", certPath)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse X.509 cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName: expectedDNS,
		Roots:   roots,
	}); err != nil {
		t.Fatalf("leaf certificate failed CA verification for %s: %v", expectedDNS, err)
	}
}
