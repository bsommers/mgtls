package pki

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

const (
	estMaxBodyBytes   = 64 << 10
	estPKCS7MediaType = "application/pkcs7-mime; smime-type=certs-only"
	estCSRMediaType   = "application/pkcs10"
)

var (
	oidPKCS7Data       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type pkcs7EncapContentInfo struct {
	EContentType asn1.ObjectIdentifier
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      pkcs7EncapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      asn1.RawValue
}

// EncodePKCS7CertsOnly encodes one or more DER X.509 certificates into an RFC 7030 §4.1.3
// degenerate PKCS#7 / CMS SignedData (certs-only) DER structure.
func EncodePKCS7CertsOnly(certsDER ...[]byte) ([]byte, error) {
	var concatCerts []byte
	for _, der := range certsDER {
		if len(der) == 0 {
			continue
		}
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("invalid certificate DER for PKCS#7: %w", err)
		}
		concatCerts = append(concatCerts, der...)
	}
	if len(concatCerts) == 0 {
		return nil, errors.New("at least one certificate is required for PKCS#7 certs-only")
	}

	sd := pkcs7SignedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: []byte{}},
		ContentInfo:      pkcs7EncapContentInfo{EContentType: oidPKCS7Data},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: concatCerts},
		SignerInfos:      asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: []byte{}},
	}
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#7 SignedData: %w", err)
	}
	ci := pkcs7ContentInfo{
		ContentType: oidPKCS7SignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdBytes},
	}
	return asn1.Marshal(ci)
}

// DecodePKCS7CertsOnly parses an RFC 7030 PKCS#7 / CMS SignedData certs-only payload
// (either raw DER or base64-encoded DER) and returns the embedded X.509 certificates.
func DecodePKCS7CertsOnly(raw []byte) ([]*x509.Certificate, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("empty PKCS#7 payload")
	}
	// Support PEM if caller passed PEM certificates.
	if bytes.Contains(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
		return parseCertsFromBytes(trimmed)
	}
	der := trimmed
	// If payload is base64 (RFC 7030 Content-Transfer-Encoding: base64), decode it first.
	if trimmed[0] != 0x30 {
		cleaned := strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, string(trimmed))
		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("base64 decode PKCS#7 payload: %w", err)
		}
		der = decoded
	}

	var ci pkcs7ContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("unmarshal PKCS#7 ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidPKCS7SignedData) {
		return nil, fmt.Errorf("unexpected PKCS#7 ContentType %v (expected SignedData)", ci.ContentType)
	}
	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("unmarshal PKCS#7 SignedData: %w", err)
	}
	if len(sd.Certificates.Bytes) == 0 {
		return nil, errors.New("PKCS#7 SignedData contains no certificates")
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificates from PKCS#7: %w", err)
	}
	return certs, nil
}

// ESTServerOptions configures the RFC 7030 Enrollment over Secure Transport (EST) server.
type ESTServerOptions struct {
	CAName       string `json:"ca_name"`
	ListenAddr   string `json:"listen_addr"`
	EnrollToken  string `json:"enroll_token,omitempty"`  // Bearer or Basic password bootstrap token
	AllowMTLS    bool   `json:"allow_mtls,omitempty"`    // Allow client-cert authentication verified against CA
	Role         string `json:"role,omitempty"`          // Leaf role to issue: server, client, mtls (default: mtls)
	ValidDays    int    `json:"valid_days,omitempty"`    // Validity days for enrolled certs (default: 365)
	TLSCertName  string `json:"tls_cert_name,omitempty"` // .mgtls cert name for HTTPS listener (auto-issued if empty)
	TLSCertPath  string `json:"tls_cert_path,omitempty"`
	TLSKeyPath   string `json:"tls_key_path,omitempty"`
	InsecureHTTP bool   `json:"insecure_http,omitempty"` // Serve plain HTTP (for unit tests or behind TLS reverse proxy)
}

// NewESTHTTPHandler returns an http.Handler implementing RFC 7030 EST endpoints:
//   - GET  /.well-known/est/cacerts           (and /.well-known/est/<ca>/cacerts)
//   - POST /.well-known/est/simpleenroll      (and /.well-known/est/<ca>/simpleenroll)
//   - POST /.well-known/est/simplereenroll    (and /.well-known/est/<ca>/simplereenroll)
//   - GET  /healthz
func NewESTHTTPHandler(s *store.Store, opts ESTServerOptions) http.Handler {
	defaultCA := strings.TrimSpace(opts.CAName)
	if defaultCA == "" {
		defaultCA = "root-ca"
	}
	role := strings.TrimSpace(opts.Role)
	if role == "" {
		role = "mtls"
	}
	validDays := opts.ValidDays
	if validDays <= 0 {
		validDays = 365
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","ca":%q,"protocol":"RFC7030-EST"}`, defaultCA)
	})

	mux.HandleFunc("/.well-known/est/", func(w http.ResponseWriter, r *http.Request) {
		caName, action, ok := parseESTPath(r.URL.Path, defaultCA)
		if !ok {
			http.Error(w, `{"error":"invalid RFC 7030 EST endpoint path"}`, http.StatusNotFound)
			return
		}
		switch action {
		case "cacerts":
			if r.Method != http.MethodGet {
				http.Error(w, `{"error":"GET required for /cacerts"}`, http.StatusMethodNotAllowed)
				return
			}
			handleESTCACerts(w, r, s, caName)
		case "simpleenroll":
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"POST required for /simpleenroll"}`, http.StatusMethodNotAllowed)
				return
			}
			handleESTEnroll(w, r, s, caName, role, validDays, opts, false)
		case "simplereenroll":
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"POST required for /simplereenroll"}`, http.StatusMethodNotAllowed)
				return
			}
			handleESTEnroll(w, r, s, caName, role, validDays, opts, true)
		default:
			http.Error(w, `{"error":"unsupported EST operation"}`, http.StatusNotFound)
		}
	})
	return mux
}

func parseESTPath(urlPath, defaultCA string) (caName, action string, ok bool) {
	const prefix = "/.well-known/est/"
	if !strings.HasPrefix(urlPath, prefix) {
		return "", "", false
	}
	rest := strings.Trim(strings.TrimPrefix(urlPath, prefix), "/")
	parts := strings.Split(rest, "/")
	switch len(parts) {
	case 1:
		return defaultCA, parts[0], parts[0] != ""
	case 2:
		if parts[0] == "" || parts[1] == "" || strings.Contains(parts[0], "..") {
			return "", "", false
		}
		return parts[0], parts[1], true
	default:
		return "", "", false
	}
}

func handleESTCACerts(w http.ResponseWriter, r *http.Request, s *store.Store, caName string) {
	if s == nil {
		http.Error(w, `{"error":"store not configured"}`, http.StatusInternalServerError)
		return
	}
	caRec, err := s.GetCA(caName)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	chainPath := caRec.ChainPath
	if chainPath == "" {
		chainPath = caRec.CertPath
	}
	chainPEM, err := os.ReadFile(chainPath)
	if err != nil {
		if chainPEM, err = os.ReadFile(caRec.CertPath); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}
	}
	if strings.Contains(r.Header.Get("Accept"), "application/x-pem-file") {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("X-MGTLS-CA-Name", caName)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(chainPEM)
		return
	}

	certs, err := parseCertsFromBytes(chainPEM)
	if err != nil || len(certs) == 0 {
		http.Error(w, `{"error":"failed to parse CA chain"}`, http.StatusInternalServerError)
		return
	}
	var ders [][]byte
	for _, c := range certs {
		ders = append(ders, c.Raw)
	}
	p7DER, err := EncodePKCS7CertsOnly(ders...)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	b64 := formatBase64Lines(base64.StdEncoding.EncodeToString(p7DER))
	w.Header().Set("Content-Type", estPKCS7MediaType)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.Header().Set("X-MGTLS-CA-Name", caName)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b64))
}

func handleESTEnroll(
	w http.ResponseWriter,
	r *http.Request,
	s *store.Store,
	caName, role string,
	validDays int,
	opts ESTServerOptions,
	isReenroll bool,
) {
	if s == nil {
		http.Error(w, `{"error":"store not configured"}`, http.StatusInternalServerError)
		return
	}

	tokenAuthenticated := false
	expectedToken := strings.TrimSpace(opts.EnrollToken)
	if expectedToken != "" {
		if provided := extractRequestToken(r); provided != "" {
			if subtle.ConstantTimeCompare([]byte(provided), []byte(expectedToken)) == 1 {
				tokenAuthenticated = true
			}
		}
	}

	var mTLSPeer *x509.Certificate
	if (opts.AllowMTLS || isReenroll) && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		peer := r.TLS.PeerCertificates[0]
		if verifyPeerCertAgainstCA(s, caName, peer, r.TLS.PeerCertificates[1:]) == nil {
			mTLSPeer = peer
		}
	}

	if !tokenAuthenticated && mTLSPeer == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mgtls-est"`)
		http.Error(w, `{"error":"unauthorized: valid EST bootstrap token or mTLS client certificate required"}`, http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, estMaxBodyBytes+1))
	if err != nil || len(body) == 0 {
		http.Error(w, `{"error":"empty or unreadable CSR body"}`, http.StatusBadRequest)
		return
	}
	if len(body) > estMaxBodyBytes {
		http.Error(w, `{"error":"CSR exceeds maximum size"}`, http.StatusRequestEntityTooLarge)
		return
	}

	csrPEM, csr, err := decodeESTCSRToPEM(body)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	// RFC 7030 §4.2.2: On /simplereenroll authenticated solely via mTLS (without an override bootstrap token),
	// the CSR's Subject CN and SANs must match the existing client certificate.
	if isReenroll && !tokenAuthenticated && mTLSPeer != nil {
		if err := verifyReenrollSubjectMatch(mTLSPeer, csr); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusForbidden)
			return
		}
	}

	reqRole := role
	if qRole := strings.TrimSpace(r.URL.Query().Get("role")); qRole != "" {
		reqRole = qRole
	}
	certName := strings.TrimSpace(r.URL.Query().Get("name"))

	res, err := SignCSR(s, SignCSRRequest{
		Name:      certName,
		CAName:    caName,
		CSRPEM:    csrPEM,
		Role:      reqRole,
		ValidDays: validDays,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/x-pem-file") {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("X-MGTLS-Serial", res.Record.SerialHex)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(res.ChainPEM))
		return
	}

	issuedCerts, err := parseCertsFromBytes([]byte(res.CertPEM))
	if err != nil || len(issuedCerts) == 0 {
		http.Error(w, `{"error":"failed to parse issued certificate"}`, http.StatusInternalServerError)
		return
	}
	p7DER, err := EncodePKCS7CertsOnly(issuedCerts[0].Raw)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	b64 := formatBase64Lines(base64.StdEncoding.EncodeToString(p7DER))
	w.Header().Set("Content-Type", estPKCS7MediaType)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.Header().Set("X-MGTLS-Serial", res.Record.SerialHex)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b64))
}

func extractRequestToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if _, pass, ok := r.BasicAuth(); ok && pass != "" {
		return pass
	}
	return ""
}

func verifyPeerCertAgainstCA(s *store.Store, caName string, leaf *x509.Certificate, intermediates []*x509.Certificate) error {
	caRec, err := s.GetCA(caName)
	if err != nil {
		return err
	}
	chainPath := caRec.ChainPath
	if chainPath == "" {
		chainPath = caRec.CertPath
	}
	caPEM, err := os.ReadFile(chainPath)
	if err != nil {
		if caPEM, err = os.ReadFile(caRec.CertPath); err != nil {
			return err
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("failed to load CA certificate pool")
	}
	interPool := x509.NewCertPool()
	for _, ic := range intermediates {
		interPool.AddCert(ic)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: interPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	})
	if err != nil {
		return err
	}
	// Check store manifest to ensure the peer certificate is not revoked.
	if m, mErr := s.LoadManifest(); mErr == nil {
		serialHex := fmt.Sprintf("%x", leaf.SerialNumber.Bytes())
		for _, c := range m.Certs {
			if c.CAName == caName && strings.EqualFold(c.SerialHex, serialHex) && c.Revoked {
				return errors.New("client certificate is revoked")
			}
		}
	}
	return nil
}

func verifyReenrollSubjectMatch(peer *x509.Certificate, csr *x509.CertificateRequest) error {
	if peer.Subject.CommonName != csr.Subject.CommonName {
		return fmt.Errorf("reenroll CSR CommonName %q does not match client certificate CommonName %q", csr.Subject.CommonName, peer.Subject.CommonName)
	}
	peerDNS := slices.Clone(peer.DNSNames)
	csrDNS := slices.Clone(csr.DNSNames)
	slices.Sort(peerDNS)
	slices.Sort(csrDNS)
	if !slices.Equal(peerDNS, csrDNS) {
		return fmt.Errorf("reenroll CSR DNS SANs %v do not match client certificate DNS SANs %v", csr.DNSNames, peer.DNSNames)
	}
	return nil
}

func decodeESTCSRToPEM(raw []byte) (string, *x509.CertificateRequest, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", nil, errors.New("empty CSR payload")
	}
	var der []byte
	if block, _ := pem.Decode(trimmed); block != nil && (block.Type == "CERTIFICATE REQUEST" || block.Type == "NEW CERTIFICATE REQUEST") {
		der = block.Bytes
	} else if trimmed[0] == 0x30 {
		der = trimmed
	} else {
		cleaned := strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, string(trimmed))
		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return "", nil, fmt.Errorf("decode PKCS#10 CSR (expected PEM or base64 DER): %w", err)
		}
		der = decoded
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return "", nil, fmt.Errorf("parse PKCS#10 CSR: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return string(pemBytes), csr, nil
}

func formatBase64Lines(b64 string) string {
	var sb strings.Builder
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}
	return sb.String()
}

// ServeEST runs an RFC 7030 EST server over TLS (or HTTP if InsecureHTTP is set) until ctx is canceled.
func ServeEST(ctx context.Context, s *store.Store, opts ESTServerOptions) error {
	if s == nil {
		return errors.New("store is required for EST server")
	}
	caName := strings.TrimSpace(opts.CAName)
	if caName == "" {
		caName = "root-ca"
	}
	opts.CAName = caName
	if strings.TrimSpace(opts.EnrollToken) == "" && !opts.AllowMTLS {
		return errors.New("EST server requires --token or --allow-mtls for authentication")
	}

	addr := strings.TrimSpace(opts.ListenAddr)
	if addr == "" {
		addr = "127.0.0.1:8445"
	}
	handler := NewESTHTTPHandler(s, opts)
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if !opts.InsecureHTTP {
		tlsCfg, err := buildESTServerTLSConfig(s, opts, addr)
		if err != nil {
			return err
		}
		srv.TLSConfig = tlsCfg
	}

	errCh := make(chan error, 1)
	go func() {
		var err error
		if opts.InsecureHTTP {
			err = srv.ListenAndServe()
		} else {
			err = srv.ListenAndServeTLS("", "")
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func buildESTServerTLSConfig(s *store.Store, opts ESTServerOptions, addr string) (*tls.Config, error) {
	caRec, err := s.GetCA(opts.CAName)
	if err != nil {
		return nil, fmt.Errorf("load CA %q for EST server: %w", opts.CAName, err)
	}
	certPath := strings.TrimSpace(opts.TLSCertPath)
	keyPath := strings.TrimSpace(opts.TLSKeyPath)
	if certPath == "" && opts.TLSCertName != "" {
		rec, gErr := s.GetCert(opts.TLSCertName)
		if gErr != nil {
			return nil, fmt.Errorf("load TLS cert %q: %w", opts.TLSCertName, gErr)
		}
		certPath = rec.FullChainPath
		keyPath = rec.KeyPath
	}
	if certPath == "" {
		// Auto-issue or reuse "est-server" certificate under opts.CAName.
		srvCertName := opts.CAName + "-est-server"
		rec, gErr := s.GetCert(srvCertName)
		if gErr != nil {
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr != nil || host == "" {
				host = "localhost"
			}
			dns := []string{"localhost"}
			ips := []string{"127.0.0.1"}
			if ip := net.ParseIP(host); ip != nil {
				if !slices.Contains(ips, ip.String()) {
					ips = append(ips, ip.String())
				}
			} else if host != "localhost" {
				dns = append(dns, host)
			}
			issued, iErr := IssueCert(s, CertRequest{
				Name:        srvCertName,
				CommonName:  host,
				CAName:      opts.CAName,
				Role:        "server",
				DNSNames:    dns,
				IPAddresses: ips,
			})
			if iErr != nil {
				return nil, fmt.Errorf("auto-issue EST server TLS cert: %w", iErr)
			}
			rec = &issued.Record
		}
		certPath = rec.FullChainPath
		keyPath = rec.KeyPath
	}

	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load EST server TLS keypair: %w", err)
	}

	chainPath := caRec.ChainPath
	if chainPath == "" {
		chainPath = caRec.CertPath
	}
	caPEM, err := os.ReadFile(chainPath)
	if err != nil {
		caPEM, err = os.ReadFile(caRec.CertPath)
		if err != nil {
			return nil, err
		}
	}
	clientPool := x509.NewCertPool()
	clientPool.AppendCertsFromPEM(caPEM)

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    clientPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}, nil
}

// ESTCACertsRequest configures fetching CA certificates from an RFC 7030 EST server.
type ESTCACertsRequest struct {
	ServerURL      string        `json:"server_url"`
	CALabel        string        `json:"ca_label,omitempty"`
	CAName         string        `json:"ca_name,omitempty"`      // Optional local CA name for TLS verification
	CACertPath     string        `json:"ca_cert_path,omitempty"` // Optional CA PEM path for TLS verification
	InsecureSkip   bool          `json:"insecure_skip_verify,omitempty"`
	OutPath        string        `json:"out_path,omitempty"`
	RequestTimeout time.Duration `json:"timeout,omitempty"`
}

// ESTCACertsResult returns the CA certificates retrieved from /.well-known/est/cacerts.
type ESTCACertsResult struct {
	ServerURL    string   `json:"server_url"`
	CALabel      string   `json:"ca_label,omitempty"`
	Count        int      `json:"count"`
	Subjects     []string `json:"subjects"`
	Fingerprints []string `json:"fingerprints"`
	CAChainPEM   string   `json:"ca_chain_pem"`
	OutPath      string   `json:"out_path,omitempty"`
}

// ESTFetchCACerts queries GET /.well-known/est[/<label>]/cacerts, decodes the RFC 7030 PKCS#7 certs-only
// response, and returns the PEM-encoded CA certificate chain.
func ESTFetchCACerts(s *store.Store, req ESTCACertsRequest) (*ESTCACertsResult, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(req.ServerURL), "/")
	if baseURL == "" {
		return nil, errors.New("server_url is required")
	}
	endpoint := buildESTEndpointURL(baseURL, req.CALabel, "cacerts")
	client, err := buildESTHTTPClient(s, req.CAName, req.CACertPath, "", "", "", req.InsecureSkip, req.RequestTimeout)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", estPKCS7MediaType)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, estMaxBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EST /cacerts returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	certs, err := DecodePKCS7CertsOnly(body)
	if err != nil {
		return nil, fmt.Errorf("decode EST /cacerts response: %w", err)
	}
	var pemBuf bytes.Buffer
	var subjects, fps []string
	for _, c := range certs {
		_ = pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		subjects = append(subjects, c.Subject.String())
		fps = append(fps, certFingerprintSHA256(c.Raw))
	}
	chainPEM := pemBuf.String()
	if req.OutPath != "" {
		if err := os.MkdirAll(filepath.Dir(req.OutPath), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(req.OutPath, []byte(chainPEM), 0o644); err != nil {
			return nil, fmt.Errorf("write CA chain to %s: %w", req.OutPath, err)
		}
	}
	return &ESTCACertsResult{
		ServerURL:    baseURL,
		CALabel:      req.CALabel,
		Count:        len(certs),
		Subjects:     subjects,
		Fingerprints: fps,
		CAChainPEM:   chainPEM,
		OutPath:      req.OutPath,
	}, nil
}

// ESTEnrollRequest configures RFC 7030 client enrollment (/simpleenroll or /simplereenroll).
type ESTEnrollRequest struct {
	ServerURL      string        `json:"server_url"`
	CALabel        string        `json:"ca_label,omitempty"`
	Reenroll       bool          `json:"reenroll,omitempty"`
	Name           string        `json:"name,omitempty"`
	CommonName     string        `json:"common_name,omitempty"`
	Organization   string        `json:"organization,omitempty"`
	Algorithm      string        `json:"algorithm,omitempty"`
	DNSNames       []string      `json:"dns_names,omitempty"`
	IPAddresses    []string      `json:"ip_addresses,omitempty"`
	URIs           []string      `json:"uris,omitempty"`
	Role           string        `json:"role,omitempty"`
	CSRPEM         string        `json:"csr_pem,omitempty"`
	CSRPath        string        `json:"csr_path,omitempty"`
	ExistingKey    string        `json:"existing_key,omitempty"`
	OutDir         string        `json:"out_dir,omitempty"`
	Token          string        `json:"token,omitempty"`
	CAName         string        `json:"ca_name,omitempty"`
	CACertPath     string        `json:"ca_cert_path,omitempty"`
	ClientCertName string        `json:"client_cert_name,omitempty"`
	ClientCertPath string        `json:"client_cert_path,omitempty"`
	ClientKeyPath  string        `json:"client_key_path,omitempty"`
	InsecureSkip   bool          `json:"insecure_skip_verify,omitempty"`
	RequestTimeout time.Duration `json:"timeout,omitempty"`
}

// ESTEnrollResult reports the enrolled certificate and output artifact paths.
type ESTEnrollResult struct {
	Name          string    `json:"name"`
	CommonName    string    `json:"common_name"`
	SerialHex     string    `json:"serial_hex"`
	Fingerprint   string    `json:"fingerprint"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	CertPath      string    `json:"cert_path,omitempty"`
	FullChainPath string    `json:"fullchain_path,omitempty"`
	KeyPath       string    `json:"key_path,omitempty"`
	CSRPath       string    `json:"csr_path,omitempty"`
	CertPEM       string    `json:"cert_pem"`
}

// ESTEnroll performs RFC 7030 /simpleenroll (or /simplereenroll) against an EST server.
// If neither CSRPEM nor CSRPath is supplied, it generates a private key and PKCS#10 CSR locally in OutDir
// so the private key never leaves the client.
func ESTEnroll(s *store.Store, req ESTEnrollRequest) (*ESTEnrollResult, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(req.ServerURL), "/")
	if baseURL == "" {
		return nil, errors.New("server_url is required")
	}
	outDir := strings.TrimSpace(req.OutDir)
	if outDir == "" {
		outDir = "."
	}

	var (
		csrDER  []byte
		keyPath string
		csrPath string
		name    = strings.TrimSpace(req.Name)
	)

	if strings.TrimSpace(req.CSRPEM) != "" || strings.TrimSpace(req.CSRPath) != "" {
		raw := []byte(req.CSRPEM)
		if len(raw) == 0 {
			var err error
			raw, err = os.ReadFile(req.CSRPath)
			if err != nil {
				return nil, fmt.Errorf("read CSR %s: %w", req.CSRPath, err)
			}
			csrPath = req.CSRPath
		}
		_, parsedCSR, err := decodeESTCSRToPEM(raw)
		if err != nil {
			return nil, err
		}
		csrDER = parsedCSR.Raw
		if name == "" {
			name = parsedCSR.Subject.CommonName
		}
	} else {
		if name == "" {
			name = strings.TrimSpace(req.CommonName)
		}
		if name == "" {
			return nil, errors.New("name, common_name, csr_path, or csr_pem is required for EST enrollment")
		}
		csrRes, err := CreateCSR(CSRRequest{
			Name:         name,
			CommonName:   req.CommonName,
			Organization: req.Organization,
			Algorithm:    req.Algorithm,
			DNSNames:     req.DNSNames,
			IPAddresses:  req.IPAddresses,
			URIs:         req.URIs,
			OutDir:       outDir,
			ExistingKey:  req.ExistingKey,
		})
		if err != nil {
			return nil, err
		}
		keyPath = csrRes.KeyPath
		csrPath = csrRes.CSRPath
		block, _ := pem.Decode([]byte(csrRes.CSRPEM))
		if block == nil {
			return nil, errors.New("failed to decode generated CSR PEM")
		}
		csrDER = block.Bytes
	}

	action := "simpleenroll"
	if req.Reenroll {
		action = "simplereenroll"
	}
	endpoint := buildESTEndpointURL(baseURL, req.CALabel, action)
	query := url.Values{}
	if req.Role != "" {
		query.Set("role", req.Role)
	}
	if name != "" {
		query.Set("name", name)
	}
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	client, err := buildESTHTTPClient(
		s,
		req.CAName,
		req.CACertPath,
		req.ClientCertName,
		req.ClientCertPath,
		req.ClientKeyPath,
		req.InsecureSkip,
		req.RequestTimeout,
	)
	if err != nil {
		return nil, err
	}

	b64Body := formatBase64Lines(base64.StdEncoding.EncodeToString(csrDER))
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(b64Body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", estCSRMediaType)
	httpReq.Header.Set("Content-Transfer-Encoding", "base64")
	httpReq.Header.Set("Accept", estPKCS7MediaType)
	if strings.TrimSpace(req.Token) != "" {
		httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(req.Token))
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, estMaxBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EST %s returned HTTP %d: %s", action, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	certs, err := DecodePKCS7CertsOnly(respBody)
	if err != nil {
		return nil, fmt.Errorf("decode EST %s response: %w", action, err)
	}
	leaf := certs[0]
	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	if name == "" {
		name = leaf.Subject.CommonName
	}
	var certPath, fullChainPath string
	if outDir != "" && name != "" && name == filepath.Base(name) {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return nil, err
		}
		certPath = filepath.Join(outDir, name+".cert.pem")
		if err := os.WriteFile(certPath, certPEMBytes, 0o644); err != nil {
			return nil, fmt.Errorf("write enrolled cert: %w", err)
		}
		// Best-effort fetch of /cacerts to write <name>.fullchain.pem alongside <name>.cert.pem
		if caRes, cErr := ESTFetchCACerts(s, ESTCACertsRequest{
			ServerURL:      baseURL,
			CALabel:        req.CALabel,
			CAName:         req.CAName,
			CACertPath:     req.CACertPath,
			InsecureSkip:   req.InsecureSkip,
			RequestTimeout: req.RequestTimeout,
		}); cErr == nil && caRes.CAChainPEM != "" {
			fullChainPath = filepath.Join(outDir, name+".fullchain.pem")
			fullBytes := append(append([]byte{}, certPEMBytes...), []byte(caRes.CAChainPEM)...)
			_ = os.WriteFile(fullChainPath, fullBytes, 0o644)
		}
	}

	return &ESTEnrollResult{
		Name:          name,
		CommonName:    leaf.Subject.CommonName,
		SerialHex:     fmt.Sprintf("%x", leaf.SerialNumber.Bytes()),
		Fingerprint:   certFingerprintSHA256(leaf.Raw),
		NotBefore:     leaf.NotBefore.UTC(),
		NotAfter:      leaf.NotAfter.UTC(),
		CertPath:      certPath,
		FullChainPath: fullChainPath,
		KeyPath:       keyPath,
		CSRPath:       csrPath,
		CertPEM:       string(certPEMBytes),
	}, nil
}

func buildESTEndpointURL(baseURL, caLabel, action string) string {
	label := strings.Trim(strings.TrimSpace(caLabel), "/")
	if label != "" {
		return fmt.Sprintf("%s/.well-known/est/%s/%s", baseURL, url.PathEscape(label), action)
	}
	return fmt.Sprintf("%s/.well-known/est/%s", baseURL, action)
}

func buildESTHTTPClient(
	s *store.Store,
	caName, caCertPath, clientCertName, clientCertPath, clientKeyPath string,
	insecureSkip bool,
	timeout time.Duration,
) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkip, //nolint:gosec // user-controlled flag for bootstrap/testing
	}

	if caCertPath == "" && caName != "" && s != nil {
		if caRec, err := s.GetCA(caName); err == nil {
			if caRec.ChainPath != "" {
				caCertPath = caRec.ChainPath
			} else {
				caCertPath = caRec.CertPath
			}
		}
	}
	if caCertPath != "" {
		raw, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate %s: %w", caCertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("no valid PEM certificates in %s", caCertPath)
		}
		tlsCfg.RootCAs = pool
	}

	if clientCertPath == "" && clientCertName != "" && s != nil {
		rec, err := s.GetCert(clientCertName)
		if err != nil {
			return nil, fmt.Errorf("load client cert %q: %w", clientCertName, err)
		}
		clientCertPath = rec.CertPath
		clientKeyPath = rec.KeyPath
	}
	if clientCertPath != "" || clientKeyPath != "" {
		if clientCertPath == "" || clientKeyPath == "" {
			return nil, errors.New("both client_cert_path and client_key_path are required for mTLS EST authentication")
		}
		kp, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load EST client TLS keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{kp}
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}
