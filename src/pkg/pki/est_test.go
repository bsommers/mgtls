package pki

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestPKCS7CertsOnlyRoundTrip(t *testing.T) {
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rootRes, err := CreateCA(s, CARequest{
		Name:       "root-ca",
		CommonName: "PKCS7 Root CA",
		Algorithm:  "ecdsa-p256",
	})
	if err != nil {
		t.Fatal(err)
	}
	interRes, err := CreateCA(s, CARequest{
		Name:       "inter-ca",
		CommonName: "PKCS7 Intermediate CA",
		Algorithm:  "ed25519",
		ParentCA:   "root-ca",
	})
	if err != nil {
		t.Fatal(err)
	}

	rootRaw, _ := os.ReadFile(rootRes.Record.CertPath)
	interRaw, _ := os.ReadFile(interRes.Record.CertPath)
	rootBlock, _ := pem.Decode(rootRaw)
	interBlock, _ := pem.Decode(interRaw)

	der, err := EncodePKCS7CertsOnly(interBlock.Bytes, rootBlock.Bytes)
	if err != nil {
		t.Fatalf("EncodePKCS7CertsOnly: %v", err)
	}

	// Test raw DER decode
	certs, err := DecodePKCS7CertsOnly(der)
	if err != nil {
		t.Fatalf("DecodePKCS7CertsOnly(DER): %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "PKCS7 Intermediate CA" || certs[1].Subject.CommonName != "PKCS7 Root CA" {
		t.Fatalf("unexpected certificate subjects: %v, %v", certs[0].Subject.CommonName, certs[1].Subject.CommonName)
	}

	// Test RFC 7030 base64 line-wrapped decode
	b64 := formatBase64Lines(base64.StdEncoding.EncodeToString(der))
	certsB64, err := DecodePKCS7CertsOnly([]byte(b64))
	if err != nil {
		t.Fatalf("DecodePKCS7CertsOnly(base64): %v", err)
	}
	if len(certsB64) != 2 {
		t.Fatalf("expected 2 certificates from base64, got %d", len(certsB64))
	}
}

func TestESTServerEnrollReenrollAndMTLS(t *testing.T) {
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCA(s, CARequest{
		Name:       "root-ca",
		CommonName: "EST Root CA",
		Algorithm:  "ecdsa-p256",
	}); err != nil {
		t.Fatal(err)
	}

	// Find an available localhost port for ServeEST over live TLS.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "est-bootstrap-secret-2026"
	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeEST(ctx, s, ESTServerOptions{
			CAName:      "root-ca",
			ListenAddr:  addr,
			EnrollToken: token,
			AllowMTLS:   true,
			Role:        "mtls",
			ValidDays:   90,
		})
	}()

	serverURL := "https://" + addr
	// Wait until EST server is accepting TLS connections.
	var caCertsRes *ESTCACertsResult
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		caCertsRes, err = ESTFetchCACerts(s, ESTCACertsRequest{
			ServerURL:      serverURL,
			CAName:         "root-ca",
			OutPath:        filepath.Join(t.TempDir(), "est-ca.pem"),
			RequestTimeout: 2 * time.Second,
		})
		if err == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("ESTFetchCACerts failed: %v", err)
	}
	if caCertsRes.Count != 1 || !strings.Contains(caCertsRes.Subjects[0], "EST Root CA") {
		t.Fatalf("unexpected /cacerts result: %+v", caCertsRes)
	}

	// 1. Unauthorized enrollment without token or client cert must fail with HTTP 401.
	clientOut := t.TempDir()
	_, err = ESTEnroll(s, ESTEnrollRequest{
		ServerURL:  serverURL,
		Name:       "unauth-node",
		CommonName: "unauth.internal",
		OutDir:     clientOut,
		CAName:     "root-ca",
	})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected HTTP 401 for unauthenticated enroll, got: %v", err)
	}

	// 2. Enroll with valid bootstrap token (generates local key + CSR in clientOut).
	enrollOut := t.TempDir()
	enrollRes, err := ESTEnroll(s, ESTEnrollRequest{
		ServerURL:   serverURL,
		Name:        "edge-gateway",
		CommonName:  "edge.internal",
		DNSNames:    []string{"edge.internal", "edge.local"},
		IPAddresses: []string{"127.0.0.1"},
		Algorithm:   "ecdsa-p256",
		OutDir:      enrollOut,
		Token:       token,
		CAName:      "root-ca",
	})
	if err != nil {
		t.Fatalf("ESTEnroll with token failed: %v", err)
	}
	if enrollRes.CommonName != "edge.internal" || enrollRes.CertPath == "" || enrollRes.KeyPath == "" || enrollRes.FullChainPath == "" {
		t.Fatalf("unexpected ESTEnrollResult: %+v", enrollRes)
	}
	rec, err := s.GetCert("edge-gateway")
	if err != nil {
		t.Fatalf("expected enrolled cert in store: %v", err)
	}
	if !rec.External || rec.KeyPath != "" {
		t.Fatalf("expected External=true and empty store KeyPath, got: %+v", rec)
	}

	// 3. Re-enroll (/simplereenroll) using ONLY mTLS client certificate (no token!) with matching CN and SANs.
	reenrollOut := t.TempDir()
	reenrollRes, err := ESTEnroll(s, ESTEnrollRequest{
		ServerURL:      serverURL,
		Reenroll:       true,
		Name:           "edge-gateway",
		CommonName:     "edge.internal",
		DNSNames:       []string{"edge.internal", "edge.local"},
		IPAddresses:    []string{"127.0.0.1"},
		ExistingKey:    enrollRes.KeyPath,
		OutDir:         reenrollOut,
		CAName:         "root-ca",
		ClientCertPath: enrollRes.CertPath,
		ClientKeyPath:  enrollRes.KeyPath,
	})
	if err != nil {
		t.Fatalf("mTLS /simplereenroll failed: %v", err)
	}
	if reenrollRes.SerialHex == enrollRes.SerialHex {
		t.Fatalf("expected new serial number on re-enrollment, got identical %s", reenrollRes.SerialHex)
	}

	// 4. Re-enroll via mTLS attempting to change CommonName to "admin.internal" must be rejected with HTTP 403.
	_, err = ESTEnroll(s, ESTEnrollRequest{
		ServerURL:      serverURL,
		Reenroll:       true,
		Name:           "edge-gateway-escalate",
		CommonName:     "admin.internal",
		DNSNames:       []string{"admin.internal"},
		OutDir:         t.TempDir(),
		CAName:         "root-ca",
		ClientCertPath: reenrollRes.CertPath,
		ClientKeyPath:  enrollRes.KeyPath,
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected HTTP 403 on mismatched reenroll CN, got: %v", err)
	}

	// 5. Revoke the leaf certificate and verify mTLS authentication is immediately rejected with HTTP 401.
	if _, err := RevokeCert(s, "root-ca", "edge-gateway", 1); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	_, err = ESTEnroll(s, ESTEnrollRequest{
		ServerURL:      serverURL,
		Reenroll:       true,
		Name:           "edge-gateway",
		CommonName:     "edge.internal",
		DNSNames:       []string{"edge.internal", "edge.local"},
		ExistingKey:    enrollRes.KeyPath,
		OutDir:         t.TempDir(),
		CAName:         "root-ca",
		ClientCertPath: reenrollRes.CertPath,
		ClientKeyPath:  enrollRes.KeyPath,
	})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected HTTP 401 for revoked mTLS client cert, got: %v", err)
	}

	cancel()
	if srvErr := <-errCh; srvErr != nil {
		t.Fatalf("ServeEST shutdown error: %v", srvErr)
	}
}
