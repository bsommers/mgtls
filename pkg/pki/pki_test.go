package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sysadmin/mgtls/pkg/store"
)

func TestCreateCAAndIssueCertsAcrossAlgorithms(t *testing.T) {
	algs := []string{"ed25519", "ecdsa-p256", "rsa-2048"}

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
