package pki

import (
	"context"
	"crypto"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestOCSPResponderAndStaplingVerify(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	if err := st.Init(); err != nil {
		t.Fatalf("st.Init: %v", err)
	}

	rootCA, err := CreateCA(st, CARequest{
		Name:       "ocsp-root",
		CommonName: "OCSP Root CA",
		Algorithm:  "ed25519",
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	leafRes, err := IssueCert(st, CertRequest{
		Name:        "ocsp-leaf",
		CAName:      "ocsp-root",
		CommonName:  "localhost",
		DNSNames:    []string{"localhost"},
		IPAddresses: []string{"127.0.0.1"},
		Role:        "server",
		Algorithm:   "ed25519",
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// 1. In-store VerifyOCSP (Good)
	repGood, err := VerifyOCSP(st, VerifyOCSPRequest{
		CertName: "ocsp-leaf",
	})
	if err != nil {
		t.Fatalf("VerifyOCSP good: %v", err)
	}
	if repGood.Status != "good" || !repGood.Verified {
		t.Fatalf("expected good OCSP report, got %+v", repGood)
	}

	// 2. HTTP OCSP responder server (httptest)
	httpSrv := httptest.NewServer(NewOCSPHTTPHandler(st, "ocsp-root", 12*time.Hour))
	defer httpSrv.Close()

	// Check /healthz
	healthResp, err := http.Get(httpSrv.URL + "/healthz")
	if err != nil || healthResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /healthz, got err=%v, resp=%+v", err, healthResp)
	}
	_ = healthResp.Body.Close()

	// Check GET / returns 405
	getResp, err := http.Get(httpSrv.URL + "/")
	if err != nil || getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET /, got err=%v, resp=%+v", err, getResp)
	}
	_ = getResp.Body.Close()

	// Verify over HTTP responder URL (Good)
	repHTTPGood, err := VerifyOCSP(st, VerifyOCSPRequest{
		CertPath:     leafRes.Record.CertPath,
		CACertPath:   rootCA.Record.CertPath,
		ResponderURL: httpSrv.URL,
	})
	if err != nil {
		t.Fatalf("VerifyOCSP over HTTP good: %v", err)
	}
	if repHTTPGood.Status != "good" || !repHTTPGood.Verified || repHTTPGood.ResponderURL != httpSrv.URL {
		t.Fatalf("unexpected HTTP OCSP report: %+v", repHTTPGood)
	}

	// 3. TLS OCSP Stapling verification against a live TLS 1.3 listener
	leafCert, _, err := loadCertAndKey(leafRes.Record.CertPath, leafRes.Record.KeyPath)
	if err != nil {
		t.Fatalf("loadCertAndKey leaf: %v", err)
	}
	caCert, _, err := loadCertAndKey(rootCA.Record.CertPath, rootCA.Record.KeyPath)
	if err != nil {
		t.Fatalf("loadCertAndKey ca: %v", err)
	}
	reqDER, err := ocsp.CreateRequest(leafCert, caCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("ocsp.CreateRequest: %v", err)
	}
	stapledDER, _, err := GenerateOCSPResponse(st, "ocsp-root", reqDER, 12*time.Hour)
	if err != nil {
		t.Fatalf("GenerateOCSPResponse: %v", err)
	}

	srvPair, err := tls.LoadX509KeyPair(leafRes.Record.FullChainPath, leafRes.Record.KeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	srvPair.OCSPStaple = stapledDER

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{srvPair},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
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

	repStapled, err := VerifyOCSP(st, VerifyOCSPRequest{
		StapledAddress: ln.Addr().String(),
		CAName:         "ocsp-root",
	})
	if err != nil {
		t.Fatalf("VerifyOCSP stapled: %v", err)
	}
	if !repStapled.Stapled || !repStapled.Verified || repStapled.Status != "good" {
		t.Fatalf("unexpected stapled OCSP report: %+v", repStapled)
	}

	// 4. Revoke certificate and verify OCSP transitions to "revoked" with reason code preserved
	if _, err := RevokeCert(st, "ocsp-root", "ocsp-leaf", ocsp.KeyCompromise); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	repRevoked, err := VerifyOCSP(st, VerifyOCSPRequest{
		CertName:     "ocsp-leaf",
		ResponderURL: httpSrv.URL,
	})
	if err != nil {
		t.Fatalf("VerifyOCSP after revoke: %v", err)
	}
	if repRevoked.Status != "revoked" || repRevoked.Verified || repRevoked.RevocationReason != ocsp.KeyCompromise {
		t.Fatalf("expected revoked status with KeyCompromise (1), got %+v", repRevoked)
	}

	// 5. ServeOCSP lifecycle test with context cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if err := ServeOCSP(ctx, st, OCSPResponderOptions{CAName: "ocsp-root", ListenAddr: "127.0.0.1:0"}); err != nil {
		t.Fatalf("ServeOCSP returned unexpected error: %v", err)
	}
}
