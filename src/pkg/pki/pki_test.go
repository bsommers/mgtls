package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestCreateCAAndIssueCertsAcrossAlgorithms(t *testing.T) {
	algs := []string{"ed25519", "ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-4096"}

	for _, alg := range algs {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			s, err := store.New(t.TempDir())
			if err != nil {
				t.Fatalf("store.New: %v", err)
			}

			rootRes, err := CreateCA(s, CARequest{
				Name:         "root-" + alg,
				CommonName:   "Root CA " + alg,
				Organization: "TestOrg",
				Country:      "US",
				Algorithm:    alg,
				ValidDays:    3650,
			})
			if err != nil {
				t.Fatalf("CreateCA root (%s): %v", alg, err)
			}
			if !rootRes.Record.IsRoot {
				t.Fatalf("expected root CA IsRoot=true")
			}

			interRes, err := CreateCA(s, CARequest{
				Name:         "inter-" + alg,
				CommonName:   "Intermediate CA " + alg,
				Organization: "TestOrg",
				ParentCA:     rootRes.Record.Name,
				Algorithm:    alg,
				ValidDays:    1825,
			})
			if err != nil {
				t.Fatalf("CreateCA intermediate (%s): %v", alg, err)
			}
			if interRes.Record.IsRoot {
				t.Fatalf("expected intermediate CA IsRoot=false")
			}

			srvRes, err := IssueCert(s, CertRequest{
				Name:        "srv-" + alg,
				CommonName:  "srv.internal",
				CAName:      interRes.Record.Name,
				Role:        "server",
				Algorithm:   alg,
				DNSNames:    []string{"srv.internal", "localhost"},
				IPAddresses: []string{"127.0.0.1"},
				URIs:        []string{"spiffe://internal/ns/default/sa/srv"},
				Emails:      []string{"admin@srv.internal"},
			})
			if err != nil {
				t.Fatalf("IssueCert server (%s): %v", alg, err)
			}

			cliRes, err := IssueCert(s, CertRequest{
				Name:       "cli-" + alg,
				CommonName: "cli.internal",
				CAName:     interRes.Record.Name,
				Role:       "client",
				Algorithm:  alg,
				URIs:       []string{"spiffe://internal/ns/default/sa/cli"},
			})
			if err != nil {
				t.Fatalf("IssueCert client (%s): %v", alg, err)
			}

			ssRes, err := IssueSelfSigned(s, SelfSignedRequest{
				Name:        "ss-" + alg,
				CommonName:  "127.0.0.1",
				Role:        "mtls",
				Algorithm:   alg,
				DNSNames:    []string{"localhost"},
				IPAddresses: []string{"127.0.0.1"},
				URIs:        []string{"spiffe://internal/ss/" + alg},
			})
			if err != nil {
				t.Fatalf("IssueSelfSigned (%s): %v", alg, err)
			}
			if !ssRes.Record.SelfSigned || ssRes.Record.Algorithm != alg {
				t.Fatalf("unexpected SelfSigned record (%s): %+v", alg, ssRes.Record)
			}

			// Verify server chain against root CA cert (fullchain includes intermediate)
			vSrv, err := VerifyChain(srvRes.Record.FullChainPath, rootRes.Record.CertPath, interRes.Record.CRLPath, "localhost", "server")
			if err != nil {
				t.Fatalf("VerifyChain server: %v", err)
			}
			if !vSrv.Valid || vSrv.Revoked || vSrv.ChainLength < 3 {
				t.Fatalf("unexpected VerifyChain server result: %+v", vSrv)
			}

			// Verify client chain
			vCli, err := VerifyChain(cliRes.Record.FullChainPath, rootRes.Record.CertPath, interRes.Record.CRLPath, "cli.internal", "client")
			if err != nil {
				t.Fatalf("VerifyChain client: %v", err)
			}
			if !vCli.Valid || vCli.Revoked {
				t.Fatalf("unexpected VerifyChain client result: %+v", vCli)
			}

			// Perform real in-memory mTLS handshake
			runMTLSHandshake(t, srvRes.Record, cliRes.Record)
		})
	}
}

func runMTLSHandshake(t *testing.T, srvRec, cliRec store.CertRecord) {
	t.Helper()

	srvCert, err := tls.LoadX509KeyPair(srvRec.FullChainPath, srvRec.KeyPath)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	cliCert, err := tls.LoadX509KeyPair(cliRec.FullChainPath, cliRec.KeyPath)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}

	caChainBytes, err := os.ReadFile(srvRec.CAChainPath)
	if err != nil {
		t.Fatalf("read ca-chain.pem: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caChainBytes) {
		t.Fatalf("failed to append ca-chain.pem to pool")
	}

	srvTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	cliTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cliCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvTLSConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			errCh <- fmt.Errorf("server handshake: %w", err)
			return
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			errCh <- fmt.Errorf("no peer certificates presented by client")
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(tlsConn, buf); err != nil {
			errCh <- fmt.Errorf("server read: %w", err)
			return
		}
		if string(buf) != "ping" {
			errCh <- fmt.Errorf("unexpected client payload %q", string(buf))
			return
		}
		if _, err := tlsConn.Write([]byte("pong")); err != nil {
			errCh <- fmt.Errorf("server write: %w", err)
			return
		}
		errCh <- nil
	}()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	cliConn, err := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), cliTLSConfig)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer cliConn.Close()

	if _, err := cliConn.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(cliConn, reply); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("expected pong, got %q", string(reply))
	}

	if srvErr := <-errCh; srvErr != nil {
		t.Fatalf("server error: %v", srvErr)
	}
}

func TestSelfSignedInspectRevokeAndTrustScripts(t *testing.T) {
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	// 1. IssueSelfSigned
	ssRes, err := IssueSelfSigned(s, SelfSignedRequest{
		Name:         "self-node",
		CommonName:   "node.local",
		Organization: "SelfOrg",
		Role:         "mtls",
		Algorithm:    "ecdsa-p384",
		DNSNames:     []string{"node.local"},
		IPAddresses:  []string{"127.0.0.1"},
		URIs:         []string{"spiffe://local/node"},
	})
	if err != nil {
		t.Fatalf("IssueSelfSigned: %v", err)
	}
	if !ssRes.Record.SelfSigned {
		t.Fatalf("expected SelfSigned=true")
	}

	// 2. InspectCert on PEM and DER
	infoPEM, err := InspectCert(ssRes.Record.CertPath)
	if err != nil {
		t.Fatalf("InspectCert PEM: %v", err)
	}
	infoDER, err := InspectCert(ssRes.Record.DERPath)
	if err != nil {
		t.Fatalf("InspectCert DER: %v", err)
	}
	if infoPEM.FingerprintSHA256 != infoDER.FingerprintSHA256 {
		t.Fatalf("PEM vs DER fingerprint mismatch: %s != %s", infoPEM.FingerprintSHA256, infoDER.FingerprintSHA256)
	}
	if infoPEM.IsCA {
		t.Fatalf("expected self-signed leaf IsCA=false")
	}
	if len(infoPEM.ExtKeyUsages) != 2 {
		t.Fatalf("expected 2 ExtKeyUsages for mtls role, got %v", infoPEM.ExtKeyUsages)
	}

	// Verify self-signed certificate using its own cert as CA bundle
	vSS, err := VerifyChain(ssRes.Record.CertPath, ssRes.Record.CertPath, "", "node.local", "mtls")
	if err != nil {
		t.Fatalf("VerifyChain self-signed: %v", err)
	}
	if !vSS.Valid {
		t.Fatalf("expected self-signed cert to verify against itself: %+v", vSS)
	}

	// 3. RevokeCert & CRL verification
	caRes, err := CreateCA(s, CARequest{
		Name:       "rev-ca",
		CommonName: "Revocation Test CA",
		Algorithm:  "ed25519",
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	leafRes, err := IssueCert(s, CertRequest{
		Name:       "rev-leaf",
		CommonName: "rev.example.com",
		CAName:     caRes.Record.Name,
		Role:       "server",
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Verify valid before revocation
	vBefore, err := VerifyChain(leafRes.Record.CertPath, caRes.Record.CertPath, caRes.Record.CRLPath, "rev.example.com", "server")
	if err != nil {
		t.Fatalf("VerifyChain before revoke: %v", err)
	}
	if !vBefore.Valid || vBefore.Revoked {
		t.Fatalf("expected valid non-revoked cert before RevokeCert: %+v", vBefore)
	}

	// Role mismatch check (server cert checked for client role)
	vWrongRole, err := VerifyChain(leafRes.Record.CertPath, caRes.Record.CertPath, "", "rev.example.com", "client")
	if err != nil {
		t.Fatalf("VerifyChain wrong role: %v", err)
	}
	if vWrongRole.Valid {
		t.Fatalf("expected VerifyChain to fail when checking server cert for client role")
	}

	// Revoke
	crlPath, err := RevokeCert(s, caRes.Record.Name, leafRes.Record.Name, 1)
	if err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	vAfter, err := VerifyChain(leafRes.Record.CertPath, caRes.Record.CertPath, crlPath, "rev.example.com", "server")
	if err != nil {
		t.Fatalf("VerifyChain after revoke: %v", err)
	}
	if vAfter.Valid || !vAfter.Revoked {
		t.Fatalf("expected VerifyChain to detect revoked cert: %+v", vAfter)
	}

	// 4. GenerateTrustScript
	scripts, err := GenerateTrustScript(caRes.Record.CertPath, caRes.Record.Name)
	if err != nil {
		t.Fatalf("GenerateTrustScript: %v", err)
	}
	for _, osKey := range []string{"debian", "rhel", "arch", "macos", "windows"} {
		cmd, ok := scripts[osKey]
		if !ok || !strings.Contains(cmd, caRes.Record.CertPath) {
			t.Fatalf("missing or invalid trust script for %s: %q", osKey, cmd)
		}
	}
}

func TestPKINegativeAndEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := store.New(tmpDir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	// 1. CreateCA negative & default paths
	if _, err := CreateCA(nil, CARequest{Name: "ca"}); err == nil {
		t.Fatalf("expected error for nil store in CreateCA")
	}
	if _, err := CreateCA(s, CARequest{Name: "   "}); err == nil {
		t.Fatalf("expected error for empty CA name")
	}
	if _, err := CreateCA(s, CARequest{Name: "bad-alg-ca", Algorithm: "dsa-1024"}); err == nil {
		t.Fatalf("expected error for unsupported algorithm in CreateCA")
	}
	if _, err := CreateCA(s, CARequest{Name: "orphan-inter", ParentCA: "nonexistent-parent"}); err == nil {
		t.Fatalf("expected error for nonexistent ParentCA")
	}

	// Root CA with empty CommonName and default algorithm/validDays
	ca1, err := CreateCA(s, CARequest{Name: "ca-defaults"})
	if err != nil || ca1.Record.CommonName != "ca-defaults" || ca1.Record.Algorithm != "ed25519" {
		t.Fatalf("CreateCA defaults failed: %+v, err=%v", ca1, err)
	}
	ca2, err := CreateCA(s, CARequest{Name: "ca-other", Algorithm: "p384"})
	if err != nil || ca2.Record.Algorithm != "ecdsa-p384" {
		t.Fatalf("CreateCA p384 shorthand failed: %+v, err=%v", ca2, err)
	}

	// 2. IssueCert & IssueSelfSigned negative and SAN edge cases
	if _, err := IssueCert(nil, CertRequest{Name: "c", CAName: "ca-defaults"}); err == nil {
		t.Fatalf("expected error for nil store in IssueCert")
	}
	if _, err := IssueCert(s, CertRequest{Name: "", CAName: "ca-defaults"}); err == nil {
		t.Fatalf("expected error for empty cert name in IssueCert")
	}
	if _, err := IssueCert(s, CertRequest{Name: "c", CAName: ""}); err == nil {
		t.Fatalf("expected error for empty CAName in IssueCert")
	}
	if _, err := IssueCert(s, CertRequest{Name: "c", CAName: "missing-ca"}); err == nil {
		t.Fatalf("expected error for missing CA in IssueCert")
	}
	if _, err := IssueCert(s, CertRequest{Name: "c", CAName: "ca-defaults", Role: "invalid-role"}); err == nil {
		t.Fatalf("expected error for invalid role in IssueCert")
	}
	if _, err := IssueCert(s, CertRequest{Name: "c", CAName: "ca-defaults", Algorithm: "unknown-alg"}); err == nil {
		t.Fatalf("expected error for unsupported algorithm in IssueCert")
	}
	if _, err := IssueCert(s, CertRequest{Name: "c", CAName: "ca-defaults", IPAddresses: []string{"999.999.999.999"}}); err == nil {
		t.Fatalf("expected error for invalid IP in IssueCert")
	}
	if _, err := IssueCert(s, CertRequest{Name: "c", CAName: "ca-defaults", URIs: []string{"not-a-uri-without-scheme"}}); err == nil {
		t.Fatalf("expected error for invalid URI without scheme in IssueCert")
	}

	// IssueCert with IP as CommonName, URIs, Emails, empty CommonName fallback
	ipCertRes, err := IssueCert(s, CertRequest{
		Name:        "ip-cn-cert",
		CommonName:  "10.20.30.40",
		CAName:      "ca-defaults",
		Role:        "client",
		Algorithm:   "p256",
		IPAddresses: []string{"", "10.20.30.40", "192.168.1.1"},
		URIs:        []string{"", "spiffe://cluster.local/ns/prod/sa/app", "https://app.internal/id"},
		Emails:      []string{"sec@app.internal"},
	})
	if err != nil {
		t.Fatalf("IssueCert with IP CN and SANs: %v", err)
	}
	if len(ipCertRes.Record.IPAddresses) != 2 || len(ipCertRes.Record.URIs) != 2 {
		t.Fatalf("unexpected SAN counts on ip-cn-cert: %+v", ipCertRes.Record)
	}

	// IssueSelfSigned negative paths
	if _, err := IssueSelfSigned(nil, SelfSignedRequest{Name: "ss"}); err == nil {
		t.Fatalf("expected error for nil store in IssueSelfSigned")
	}
	if _, err := IssueSelfSigned(s, SelfSignedRequest{Name: ""}); err == nil {
		t.Fatalf("expected error for empty name in IssueSelfSigned")
	}
	if _, err := IssueSelfSigned(s, SelfSignedRequest{Name: "ss", Role: "badrole"}); err == nil {
		t.Fatalf("expected error for invalid role in IssueSelfSigned")
	}
	if _, err := IssueSelfSigned(s, SelfSignedRequest{Name: "ss", Algorithm: "badalg"}); err == nil {
		t.Fatalf("expected error for invalid algorithm in IssueSelfSigned")
	}
	if _, err := IssueSelfSigned(s, SelfSignedRequest{Name: "ss", IPAddresses: []string{"bad-ip"}}); err == nil {
		t.Fatalf("expected error for invalid IP in IssueSelfSigned")
	}
	if _, err := IssueSelfSigned(s, SelfSignedRequest{Name: "ss", URIs: []string{"bad-uri"}}); err == nil {
		t.Fatalf("expected error for invalid URI in IssueSelfSigned")
	}

	// 3. VerifyChain negative paths: role mismatches, wrong DNS name, untrusted CA, DER CRL
	srvOnlyRes, err := IssueCert(s, CertRequest{
		Name:       "srv-only",
		CommonName: "srv-only.internal",
		CAName:     "ca-defaults",
		Role:       "server",
	})
	if err != nil {
		t.Fatalf("IssueCert srv-only: %v", err)
	}

	// Client-only cert verified as "server" and "mtls"
	vCliAsSrv, err := VerifyChain(ipCertRes.Record.CertPath, ca1.Record.CertPath, "", "", "server")
	if err != nil || vCliAsSrv.Valid {
		t.Fatalf("expected client-only cert to fail server role verification: %+v, err=%v", vCliAsSrv, err)
	}
	vCliAsMTLS, err := VerifyChain(ipCertRes.Record.CertPath, ca1.Record.CertPath, "", "", "mtls")
	if err != nil || vCliAsMTLS.Valid {
		t.Fatalf("expected client-only cert to fail mtls role verification: %+v, err=%v", vCliAsMTLS, err)
	}

	// Server-only cert verified as "mtls" and with empty role ""
	vSrvAsMTLS, err := VerifyChain(srvOnlyRes.Record.CertPath, ca1.Record.CertPath, "", "srv-only.internal", "mtls")
	if err != nil || vSrvAsMTLS.Valid {
		t.Fatalf("expected server-only cert to fail mtls role verification: %+v, err=%v", vSrvAsMTLS, err)
	}
	vSrvAnyRole, err := VerifyChain(srvOnlyRes.Record.CertPath, ca1.Record.CertPath, "", "srv-only.internal", "")
	if err != nil || !vSrvAnyRole.Valid {
		t.Fatalf("expected server-only cert to succeed with empty role: %+v, err=%v", vSrvAnyRole, err)
	}

	// Wrong DNS name failure
	vWrongDNS, err := VerifyChain(srvOnlyRes.Record.CertPath, ca1.Record.CertPath, "", "wrong.example.com", "server")
	if err != nil || vWrongDNS.Valid {
		t.Fatalf("expected VerifyChain to fail on wrong DNS name: %+v, err=%v", vWrongDNS, err)
	}

	// Untrusted CA failure (signed by ca1, verified against ca2)
	vUntrusted, err := VerifyChain(srvOnlyRes.Record.CertPath, ca2.Record.CertPath, "", "srv-only.internal", "server")
	if err != nil || vUntrusted.Valid {
		t.Fatalf("expected VerifyChain to fail against untrusted CA: %+v, err=%v", vUntrusted, err)
	}

	// System root pool fallback (caBundlePath == "")
	vSysPool, err := VerifyChain(srvOnlyRes.Record.CertPath, "", "", "srv-only.internal", "server")
	if err != nil || vSysPool.Valid {
		t.Fatalf("expected private CA cert to fail against system cert pool: %+v, err=%v", vSysPool, err)
	}

	// Unsupported role error in VerifyChain
	if _, err := VerifyChain(srvOnlyRes.Record.CertPath, ca1.Record.CertPath, "", "", "invalid-role"); err == nil {
		t.Fatalf("expected error for unsupported role in VerifyChain")
	}

	// DER CRL fallback in VerifyChain
	crlPEMBytes, err := os.ReadFile(ca1.Record.CRLPath)
	if err != nil {
		t.Fatalf("read CRL PEM: %v", err)
	}
	crlBlock, _ := pem.Decode(crlPEMBytes)
	derCRLPath := filepath.Join(tmpDir, "crl.der")
	if err := os.WriteFile(derCRLPath, crlBlock.Bytes, 0644); err != nil {
		t.Fatalf("write DER CRL: %v", err)
	}
	vDERCRL, err := VerifyChain(srvOnlyRes.Record.CertPath, ca1.Record.CertPath, derCRLPath, "srv-only.internal", "server")
	if err != nil || !vDERCRL.Valid {
		t.Fatalf("expected VerifyChain with DER CRL to succeed: %+v, err=%v", vDERCRL, err)
	}

	// InspectCert error paths
	if _, err := InspectCert(filepath.Join(tmpDir, "missing.pem")); err == nil {
		t.Fatalf("expected error for missing cert in InspectCert")
	}
	badCertPath := filepath.Join(tmpDir, "garbage.pem")
	if err := os.WriteFile(badCertPath, []byte("not-a-cert"), 0644); err != nil {
		t.Fatalf("write garbage cert: %v", err)
	}
	if _, err := InspectCert(badCertPath); err == nil {
		t.Fatalf("expected error for invalid cert bytes in InspectCert")
	}

	// 4. RevokeCert negative paths
	if _, err := RevokeCert(nil, "ca-defaults", "srv-only", 0); err == nil {
		t.Fatalf("expected error for nil store in RevokeCert")
	}
	if _, err := RevokeCert(s, "nonexistent-ca", "srv-only", 0); err == nil {
		t.Fatalf("expected error for nonexistent CA in RevokeCert")
	}
	if _, err := RevokeCert(s, "ca-defaults", "nonexistent-cert", 0); err == nil {
		t.Fatalf("expected error for nonexistent cert in RevokeCert")
	}
	if _, err := RevokeCert(s, "ca-other", "srv-only", 0); err == nil || !strings.Contains(err.Error(), "was issued by") {
		t.Fatalf("expected wrong CA error in RevokeCert, got %v", err)
	}

	// 5. GenerateTrustScript negative, default name, and shell-metacharacter sanitization paths
	if _, err := GenerateTrustScript("", "ca"); err == nil {
		t.Fatalf("expected error for empty caCertPath in GenerateTrustScript")
	}
	scriptsDefault, err := GenerateTrustScript(ca1.Record.CertPath, "")
	if err != nil || !strings.Contains(scriptsDefault["debian"], "mgtls-ca.crt") {
		t.Fatalf("expected default mgtls-ca name in GenerateTrustScript: %+v, err=%v", scriptsDefault, err)
	}
	scriptsUnsafe, err := GenerateTrustScript(ca1.Record.CertPath, "../../evil; rm -rf /")
	if err != nil || !strings.Contains(scriptsUnsafe["debian"], "/evilrm-rf.crt") {
		t.Fatalf("expected sanitized anchor name in GenerateTrustScript, got %+v, err=%v", scriptsUnsafe, err)
	}

	// 6. Multi-cert revocation preserves distinct per-certificate reason codes in CRL
	cRev1, err := IssueCert(s, CertRequest{Name: "rev-cert-1", CommonName: "rev1.local", CAName: "ca-defaults"})
	if err != nil {
		t.Fatalf("IssueCert rev-cert-1: %v", err)
	}
	cRev2, err := IssueCert(s, CertRequest{Name: "rev-cert-2", CommonName: "rev2.local", CAName: "ca-defaults"})
	if err != nil {
		t.Fatalf("IssueCert rev-cert-2: %v", err)
	}
	if _, err := RevokeCert(s, "ca-defaults", cRev1.Record.Name, 1); err != nil {
		t.Fatalf("RevokeCert rev-cert-1 (reason 1): %v", err)
	}
	crlMultiPath, err := RevokeCert(s, "ca-defaults", cRev2.Record.Name, 4)
	if err != nil {
		t.Fatalf("RevokeCert rev-cert-2 (reason 4): %v", err)
	}
	rec1After, err := s.GetCert("rev-cert-1")
	if err != nil || rec1After.RevokeReason != 1 {
		t.Fatalf("expected rev-cert-1 RevokeReason=1, got %+v, err=%v", rec1After, err)
	}
	rec2After, err := s.GetCert("rev-cert-2")
	if err != nil || rec2After.RevokeReason != 4 {
		t.Fatalf("expected rev-cert-2 RevokeReason=4, got %+v, err=%v", rec2After, err)
	}
	crlMultiRaw, err := os.ReadFile(crlMultiPath)
	if err != nil {
		t.Fatalf("read multi CRL: %v", err)
	}
	parsedCRL, err := parseCRLFromBytes(crlMultiRaw)
	if err != nil || len(parsedCRL.RevokedCertificateEntries) < 2 {
		t.Fatalf("parse multi CRL: %+v, err=%v", parsedCRL, err)
	}
}

