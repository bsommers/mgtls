package pki

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

// ProbeRequest specifies parameters for probing a live TLS or Mutual TLS endpoint.
type ProbeRequest struct {
	Address        string        `json:"address"`
	ServerName     string        `json:"server_name,omitempty"`
	CAName         string        `json:"ca_name,omitempty"`
	CACertPath     string        `json:"ca_cert_path,omitempty"`
	ClientCertName string        `json:"client_cert_name,omitempty"`
	ClientCertPath string        `json:"client_cert_path,omitempty"`
	ClientKeyPath  string        `json:"client_key_path,omitempty"`
	ALPN           []string      `json:"alpn,omitempty"`
	Timeout        time.Duration `json:"timeout,omitempty"`
}

// ProbeCertSummary describes a single X.509 certificate presented by a remote peer.
type ProbeCertSummary struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	URIs               []string  `json:"uris,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysRemaining      int       `json:"days_remaining"`
	IsCA               bool      `json:"is_ca"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SHA256Fingerprint  string    `json:"sha256_fingerprint"`
}

// ProbeReport captures the result of probing a live TLS or Mutual TLS endpoint.
type ProbeReport struct {
	Address            string             `json:"address"`
	ServerName         string             `json:"server_name"`
	Reachable          bool               `json:"reachable"`
	HandshakeOK        bool               `json:"handshake_ok"`
	TLSVersion         string             `json:"tls_version"`
	CipherSuite        string             `json:"cipher_suite"`
	NegotiatedProtocol string             `json:"negotiated_protocol,omitempty"`
	MutualTLSUsed      bool               `json:"mutual_tls_used"`
	Verified           bool               `json:"verified"`
	HostnameMatch      bool               `json:"hostname_match"`
	VerificationError  string             `json:"verification_error,omitempty"`
	PeerCertificates   []ProbeCertSummary `json:"peer_certificates,omitempty"`
	Warnings           []string           `json:"warnings,omitempty"`
	LatencyMs          int64              `json:"latency_ms"`
}

// ProbeEndpoint connects to a live TLS/mTLS endpoint, inspects the negotiated protocol,
// cipher suite, and peer certificate chain, and validates trust against a local CA or system roots.
func ProbeEndpoint(s *store.Store, req ProbeRequest) (*ProbeReport, error) {
	addr := strings.TrimSpace(req.Address)
	if addr == "" {
		return nil, errors.New("probe address (host:port) is required")
	}
	if !strings.Contains(addr, ":") {
		addr = addr + ":443"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", req.Address, err)
	}

	serverName := strings.TrimSpace(req.ServerName)
	if serverName == "" {
		serverName = host
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var rootPool *x509.CertPool
	caCertPath := strings.TrimSpace(req.CACertPath)
	if caCertPath == "" && req.CAName != "" && s != nil {
		caRec, err := s.GetCA(req.CAName)
		if err != nil {
			return nil, fmt.Errorf("resolve ca %q: %w", req.CAName, err)
		}
		if caRec.ChainPath != "" {
			caCertPath = caRec.ChainPath
		} else {
			caCertPath = caRec.CertPath
		}
	}
	if caCertPath != "" {
		rawCA, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read ca cert %q: %w", caCertPath, err)
		}
		rootPool = x509.NewCertPool()
		if !rootPool.AppendCertsFromPEM(rawCA) {
			return nil, fmt.Errorf("no valid PEM certificates found in %q", caCertPath)
		}
	}

	var clientCerts []tls.Certificate
	clientCertPath := strings.TrimSpace(req.ClientCertPath)
	clientKeyPath := strings.TrimSpace(req.ClientKeyPath)
	if clientCertPath == "" && req.ClientCertName != "" && s != nil {
		certRec, err := s.GetCert(req.ClientCertName)
		if err != nil {
			return nil, fmt.Errorf("resolve client cert %q: %w", req.ClientCertName, err)
		}
		clientCertPath = certRec.FullChainPath
		if clientCertPath == "" {
			clientCertPath = certRec.CertPath
		}
		clientKeyPath = certRec.KeyPath
	}
	if clientCertPath != "" || clientKeyPath != "" {
		if clientCertPath == "" || clientKeyPath == "" {
			return nil, errors.New("both client_cert_path and client_key_path are required when specifying explicit client certificate paths")
		}
		pair, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client certificate keypair: %w", err)
		}
		clientCerts = []tls.Certificate{pair}
	}

	// Use InsecureSkipVerify during handshake so we can still inspect expired or untrusted
	// peer certificates and perform explicit x509.Certificate.Verify diagnostics below.
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // intentional: verified explicitly below
		Certificates:       clientCerts,
		NextProtos:         req.ALPN,
	}

	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("tls probe %s failed: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	report := &ProbeReport{
		Address:            addr,
		ServerName:         serverName,
		Reachable:          true,
		HandshakeOK:        state.HandshakeComplete,
		TLSVersion:         tlsVersionName(state.Version),
		CipherSuite:        tls.CipherSuiteName(state.CipherSuite),
		NegotiatedProtocol: state.NegotiatedProtocol,
		MutualTLSUsed:      len(clientCerts) > 0,
		LatencyMs:          latencyMs,
	}

	if state.Version < tls.VersionTLS13 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("negotiated %s instead of TLS 1.3", report.TLSVersion))
	}

	now := time.Now().UTC()
	interPool := x509.NewCertPool()
	for i, cert := range state.PeerCertificates {
		if i > 0 {
			interPool.AddCert(cert)
		}
		sum := sha256.Sum256(cert.Raw)
		var ips []string
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		var uris []string
		for _, u := range cert.URIs {
			uris = append(uris, u.String())
		}
		daysRem := int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24))
		report.PeerCertificates = append(report.PeerCertificates, ProbeCertSummary{
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			Serial:             cert.SerialNumber.Text(16),
			DNSNames:           cert.DNSNames,
			IPAddresses:        ips,
			URIs:               uris,
			NotBefore:          cert.NotBefore.UTC(),
			NotAfter:           cert.NotAfter.UTC(),
			DaysRemaining:      daysRem,
			IsCA:               cert.IsCA,
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			SHA256Fingerprint:  hex.EncodeToString(sum[:]),
		})
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		if err := leaf.VerifyHostname(serverName); err == nil {
			report.HostnameMatch = true
		} else {
			report.Warnings = append(report.Warnings, fmt.Sprintf("hostname mismatch for %q: %v", serverName, err))
		}

		daysRem := int(math.Floor(leaf.NotAfter.Sub(now).Hours() / 24))
		if now.After(leaf.NotAfter) {
			report.Warnings = append(report.Warnings, fmt.Sprintf("leaf certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339)))
		} else if daysRem <= 30 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("leaf certificate expires in %d days (%s)", daysRem, leaf.NotAfter.UTC().Format(time.RFC3339)))
		}

		verifyOpts := x509.VerifyOptions{
			DNSName:       serverName,
			Roots:         rootPool,
			Intermediates: interPool,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if _, err := leaf.Verify(verifyOpts); err != nil {
			report.Verified = false
			report.VerificationError = err.Error()
			report.Warnings = append(report.Warnings, fmt.Sprintf("chain verification failed: %v", err))
		} else {
			report.Verified = true
		}
	}

	return report, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
