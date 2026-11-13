package pki

import (
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestCompileTrustBundle(t *testing.T) {
	s, _ := store.New(t.TempDir())
	for _, n := range []string{"ca-a", "ca-b"} {
		if _, err := CreateCA(s, CARequest{Name: n, CommonName: n, Algorithm: "ecdsa-p256"}); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	pemRes, err := CompileTrustBundle(s, BundleCompileRequest{CANames: []string{"ca-a", "ca-b", "ca-a"}})
	if err != nil || pemRes.Certs != 2 || pemRes.Duplicates != 1 || strings.Count(pemRes.Content, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("pem: %+v %v", pemRes, err)
	}
	p7 := filepath.Join(dir, "b.p7b")
	if _, err := CompileTrustBundle(s, BundleCompileRequest{CANames: []string{"ca-a", "ca-b"}, Format: "p7b", OutPath: p7}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p7)
	if cs, err := DecodePKCS7CertsOnly(raw); err != nil || len(cs) != 2 {
		t.Fatalf("p7b roundtrip: %v %d", err, len(cs))
	}
	// p7b as input merges with a PEM input; dupes dropped.
	m, err := CompileTrustBundle(s, BundleCompileRequest{CANames: []string{"ca-a"}, Inputs: []string{p7}})
	if err != nil || m.Certs != 2 || m.Duplicates != 1 {
		t.Fatalf("merge: %+v %v", m, err)
	}
	p12 := filepath.Join(dir, "t.p12")
	r, err := CompileTrustBundle(s, BundleCompileRequest{CANames: []string{"ca-a", "ca-b"}, Format: "p12", Password: "pw123", OutPath: p12})
	if err != nil || r.OutPath != p12 {
		t.Fatal(r, err)
	}
	if _, err := exec.LookPath("openssl"); err == nil {
		out, err := exec.Command("openssl", "pkcs12", "-in", p12, "-passin", "pass:pw123", "-nokeys", "-legacy").CombinedOutput()
		if err != nil {
			out, err = exec.Command("openssl", "pkcs12", "-in", p12, "-passin", "pass:pw123", "-nokeys").CombinedOutput()
		}
		if err != nil || strings.Count(string(out), "BEGIN CERTIFICATE") != 2 {
			t.Fatalf("openssl rejected p12: %v\n%s", err, out)
		}
		if out, err := exec.Command("openssl", "pkcs12", "-in", p12, "-passin", "pass:wrong", "-nokeys").CombinedOutput(); err == nil {
			t.Fatalf("wrong password accepted: %s", out)
		}
	}
	if kt, err := exec.LookPath("keytool"); err == nil {
		out, err := exec.Command(kt, "-list", "-keystore", p12, "-storetype", "PKCS12", "-storepass", "pw123").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "trustedCertEntry") {
			t.Fatalf("keytool: %v\n%s", err, out)
		}
	}
	b64, err := CompileTrustBundle(s, BundleCompileRequest{CANames: []string{"ca-a"}, Format: "p12"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base64.StdEncoding.DecodeString(b64.Content); err != nil {
		t.Error(err)
	}
	for _, bad := range []BundleCompileRequest{{}, {CANames: []string{"nope"}}, {CANames: []string{"ca-a"}, Format: "jks"}, {Inputs: []string{"/nonexistent"}}} {
		if _, err := CompileTrustBundle(s, bad); err == nil {
			t.Errorf("expected error: %+v", bad)
		}
	}
}

func TestScanTargets(t *testing.T) {
	s, _ := store.New(t.TempDir())
	if _, err := CreateCA(s, CARequest{Name: "root-ca", CommonName: "Scan CA", Algorithm: "ecdsa-p256"}); err != nil {
		t.Fatal(err)
	}
	res, err := IssueCert(s, CertRequest{Name: "srv", CAName: "root-ca", Role: "server", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"}, ValidDays: 5})
	if err != nil {
		t.Fatal(err)
	}
	kp, err := tls.LoadX509KeyPair(res.Record.FullChainPath, res.Record.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{kp}}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()

	rep, err := ScanTargets(s, ScanRequest{Targets: []string{addr, dead, addr, " "}, CAName: "root-ca", Concurrency: 2, WarnDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Total != 2 || rep.Summary.Reachable != 1 || rep.Summary.Unreachable != 1 || rep.Summary.Verified != 1 || rep.Summary.Expiring != 1 {
		t.Fatalf("summary: %+v", rep.Summary)
	}
	if rep.Results[0].Target != addr || rep.Results[1].Target != dead || rep.Results[1].Error == "" {
		t.Fatalf("results order/err: %+v", rep.Results)
	}
	if rep.Summary.TLSVersions["TLS 1.3"] != 1 {
		t.Errorf("versions: %+v", rep.Summary.TLSVersions)
	}
	if _, err := ScanTargets(s, ScanRequest{}); err == nil {
		t.Error("expected error for no targets")
	}
}
