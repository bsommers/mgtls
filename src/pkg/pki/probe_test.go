package pki

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestProbeEndpointTLSAndMutualTLS(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	if err := st.Init(); err != nil {
		t.Fatalf("st.Init: %v", err)
	}

	rootCA, err := CreateCA(st, CARequest{
		Name:       "probe-root",
		CommonName: "Probe Root CA",
		Algorithm:  "ed25519",
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	srvCert, err := IssueCert(st, CertRequest{
		Name:        "probe-srv",
		CAName:      "probe-root",
		CommonName:  "localhost",
		DNSNames:    []string{"localhost"},
		IPAddresses: []string{"127.0.0.1"},
		Role:        "server",
		Algorithm:   "ed25519",
	})
	if err != nil {
		t.Fatalf("IssueCert server: %v", err)
	}

	cliCert, err := IssueCert(st, CertRequest{
		Name:       "probe-cli",
		CAName:     "probe-root",
		CommonName: "probe-client",
		Role:       "client",
		Algorithm:  "ed25519",
	})
	if err != nil {
		t.Fatalf("IssueCert client: %v", err)
	}

	srvPair, err := tls.LoadX509KeyPair(srvCert.Record.FullChainPath, srvCert.Record.KeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	rawCA, err := os.ReadFile(rootCA.Record.CertPath)
	if err != nil {
		t.Fatalf("ReadFile CA: %v", err)
	}
	clientCAPool := x509.NewCertPool()
	clientCAPool.AppendCertsFromPEM(rawCA)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{srvPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
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

	addr := ln.Addr().String()

	// 1. Valid mTLS probe using store names
	rep, err := ProbeEndpoint(st, ProbeRequest{
		Address:        addr,
		ServerName:     "localhost",
		CAName:         "probe-root",
		ClientCertName: "probe-cli",
		ALPN:           []string{"h2"},
		Timeout:        3 * time.Second,
	})
	if err != nil {
		t.Fatalf("ProbeEndpoint valid mTLS: %v", err)
	}
	if !rep.Reachable || !rep.HandshakeOK || !rep.Verified || !rep.HostnameMatch || !rep.MutualTLSUsed {
		t.Fatalf("unexpected probe report: %+v", rep)
	}
	if rep.TLSVersion != "TLS 1.3" || rep.NegotiatedProtocol != "h2" {
		t.Fatalf("unexpected protocol negotiation: version=%s alpn=%s", rep.TLSVersion, rep.NegotiatedProtocol)
	}
	if len(rep.PeerCertificates) == 0 || rep.PeerCertificates[0].SHA256Fingerprint == "" {
		t.Fatalf("expected peer certificate summary with SHA256 fingerprint, got %+v", rep.PeerCertificates)
	}

	// 2. Probe with hostname mismatch & missing CA trust (reports Verified=false & HostnameMatch=false)
	repUntrusted, err := ProbeEndpoint(st, ProbeRequest{
		Address:        addr,
		ServerName:     "wrong.internal",
		ClientCertPath: cliCert.Record.FullChainPath,
		ClientKeyPath:  cliCert.Record.KeyPath,
	})
	if err != nil {
		t.Fatalf("ProbeEndpoint untrusted: %v", err)
	}
	if repUntrusted.Verified || repUntrusted.HostnameMatch || len(repUntrusted.Warnings) == 0 {
		t.Fatalf("expected unverified report with warnings, got %+v", repUntrusted)
	}

	// 3. Validation error cases
	if _, err := ProbeEndpoint(st, ProbeRequest{}); err == nil {
		t.Fatalf("expected error for empty address")
	}
	if _, err := ProbeEndpoint(st, ProbeRequest{Address: addr, ClientCertPath: cliCert.Record.CertPath}); err == nil {
		t.Fatalf("expected error when client_key_path is omitted")
	}
}
