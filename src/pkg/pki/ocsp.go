package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

// OCSPResponderOptions configures the RFC 6960 HTTP OCSP responder.
type OCSPResponderOptions struct {
	CAName             string        `json:"ca_name"`
	ListenAddr         string        `json:"listen_addr"`
	NextUpdateDuration time.Duration `json:"next_update_duration,omitempty"`
}

// VerifyOCSPRequest specifies parameters for verifying a certificate's OCSP status.
type VerifyOCSPRequest struct {
	CertName       string        `json:"cert_name,omitempty"`
	CertPath       string        `json:"cert_path,omitempty"`
	CAName         string        `json:"ca_name,omitempty"`
	CACertPath     string        `json:"ca_cert_path,omitempty"`
	ResponderURL   string        `json:"responder_url,omitempty"`
	StapledAddress string        `json:"stapled_address,omitempty"`
	Timeout        time.Duration `json:"timeout,omitempty"`
}

// OCSPStatusReport describes the RFC 6960 OCSP verification result for a certificate.
type OCSPStatusReport struct {
	SerialHex        string    `json:"serial_hex"`
	Status           string    `json:"status"` // good, revoked, unknown
	RevokedAt        string    `json:"revoked_at,omitempty"`
	RevocationReason int       `json:"revocation_reason,omitempty"`
	ThisUpdate       time.Time `json:"this_update"`
	NextUpdate       time.Time `json:"next_update"`
	ResponderURL     string    `json:"responder_url,omitempty"`
	Stapled          bool      `json:"stapled,omitempty"`
	Verified         bool      `json:"verified"`
}

// GenerateOCSPResponse parses a DER-encoded RFC 6960 OCSP request, evaluates the certificate serial
// against the .mgtls store manifest for caName, and returns a signed DER OCSP response.
func GenerateOCSPResponse(s *store.Store, caName string, reqDER []byte, nextUpdateDur time.Duration) ([]byte, *OCSPStatusReport, error) {
	if s == nil {
		return nil, nil, errors.New("store is required for OCSP responder")
	}
	caName = strings.TrimSpace(caName)
	if caName == "" {
		return nil, nil, errors.New("ca_name is required for OCSP responder")
	}
	ocspReq, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse OCSP request: %w", err)
	}

	caRec, err := s.GetCA(caName)
	if err != nil {
		return nil, nil, fmt.Errorf("load CA %q: %w", caName, err)
	}
	caCert, caSigner, err := loadCertAndKey(caRec.CertPath, caRec.KeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load CA %q keypair for OCSP signing: %w", caName, err)
	}

	if nextUpdateDur <= 0 {
		nextUpdateDur = 24 * time.Hour
	}
	now := time.Now().UTC().Truncate(time.Second)
	nextUpdate := now.Add(nextUpdateDur)

	manifest, err := s.LoadManifest()
	if err != nil {
		return nil, nil, err
	}

	template := ocsp.Response{
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   now.Add(-1 * time.Minute),
		NextUpdate:   nextUpdate,
		Status:       ocsp.Unknown,
	}
	statusStr := "unknown"
	var revokedAtStr string

	for _, c := range manifest.Certs {
		if c.CAName != caName {
			continue
		}
		serialBytes, err := hex.DecodeString(c.SerialHex)
		if err != nil {
			continue
		}
		certSerial := new(big.Int).SetBytes(serialBytes)
		if certSerial.Cmp(ocspReq.SerialNumber) == 0 {
			if c.Revoked {
				template.Status = ocsp.Revoked
				revTime := c.RevokedAt.UTC()
				if revTime.IsZero() {
					revTime = now
				}
				template.RevokedAt = revTime
				template.RevocationReason = c.RevokeReason
				statusStr = "revoked"
				revokedAtStr = revTime.Format(time.RFC3339)
			} else {
				template.Status = ocsp.Good
				statusStr = "good"
			}
			break
		}
	}

	responderCert := caCert
	responderSigner := caSigner
	if _, isEd := caCert.PublicKey.(ed25519.PublicKey); isEd {
		// golang.org/x/crypto/ocsp only supports ECDSA/RSA response signatures directly,
		// so for Ed25519 CAs we issue an RFC 6960 §4.2.2.2 delegated OCSP responder certificate
		// (ECDSA P-256 with ExtKeyUsageOCSPSigning) signed by the Ed25519 CA.
		delCert, delSigner, err := createDelegatedOCSPResponder(caCert, caSigner, now, nextUpdate)
		if err != nil {
			return nil, nil, fmt.Errorf("create delegated OCSP responder for Ed25519 CA: %w", err)
		}
		responderCert = delCert
		responderSigner = delSigner
		template.Certificate = delCert
	}

	respDER, err := ocsp.CreateResponse(caCert, responderCert, template, responderSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("create OCSP response: %w", err)
	}

	report := &OCSPStatusReport{
		SerialHex:        fmt.Sprintf("%x", ocspReq.SerialNumber.Bytes()),
		Status:           statusStr,
		RevokedAt:        revokedAtStr,
		RevocationReason: template.RevocationReason,
		ThisUpdate:       template.ThisUpdate,
		NextUpdate:       template.NextUpdate,
		Verified:         true,
	}
	return respDER, report, nil
}

// NewOCSPHTTPHandler returns an http.Handler serving RFC 6960 OCSP responses over POST (application/ocsp-request)
// and a /healthz endpoint.
func NewOCSPHTTPHandler(s *store.Store, caName string, nextUpdateDur time.Duration) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","ca":%q}`, caName)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`{"error":"POST with application/ocsp-request required"}`))
			return
		}
		reqDER, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil || len(reqDER) == 0 {
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(ocsp.MalformedRequestErrorResponse)
			return
		}
		respDER, _, err := GenerateOCSPResponse(s, caName, reqDER, nextUpdateDur)
		if err != nil {
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(ocsp.MalformedRequestErrorResponse)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respDER)
	})
	return mux
}

// ServeOCSP runs an HTTP RFC 6960 OCSP responder until ctx is canceled.
func ServeOCSP(ctx context.Context, s *store.Store, opts OCSPResponderOptions) error {
	addr := strings.TrimSpace(opts.ListenAddr)
	if addr == "" {
		addr = "127.0.0.1:8888"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           NewOCSPHTTPHandler(s, opts.CAName, opts.NextUpdateDuration),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// VerifyOCSP verifies the RFC 6960 OCSP status of a certificate via:
//  1. A live TLS server's stapled OCSP response (when StapledAddress is set),
//  2. A live HTTP OCSP responder URL (when ResponderURL is set), or
//  3. Local in-store OCSP signing and verification against the issuing CA in .mgtls.
func VerifyOCSP(s *store.Store, req VerifyOCSPRequest) (*OCSPStatusReport, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Mode 1: Verify stapled OCSP response from a live TLS endpoint
	if strings.TrimSpace(req.StapledAddress) != "" {
		addr := strings.TrimSpace(req.StapledAddress)
		if !strings.Contains(addr, ":") {
			addr += ":443"
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid stapled_address %q: %w", req.StapledAddress, err)
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // verified against issuer cert below
		})
		if err != nil {
			return nil, fmt.Errorf("dial %s for OCSP stapling check: %w", addr, err)
		}
		defer conn.Close()

		state := conn.ConnectionState()
		if len(state.OCSPResponse) == 0 {
			return nil, fmt.Errorf("peer %s did not present a stapled OCSP response", addr)
		}
		if len(state.PeerCertificates) == 0 {
			return nil, fmt.Errorf("peer %s presented no certificates", addr)
		}
		leaf := state.PeerCertificates[0]
		issuer, err := resolveIssuerCert(s, req.CAName, req.CACertPath, state.PeerCertificates)
		if err != nil {
			return nil, err
		}
		parsed, err := ocsp.ParseResponseForCert(state.OCSPResponse, leaf, issuer)
		if err != nil {
			return nil, fmt.Errorf("verify stapled OCSP response: %w", err)
		}
		rep := buildOCSPReportFromParsed(parsed)
		rep.Stapled = true
		return rep, nil
	}

	// Resolve target leaf certificate and issuer CA
	certPath := strings.TrimSpace(req.CertPath)
	caName := strings.TrimSpace(req.CAName)
	if certPath == "" && req.CertName != "" && s != nil {
		rec, err := s.GetCert(req.CertName)
		if err != nil {
			return nil, fmt.Errorf("resolve cert %q: %w", req.CertName, err)
		}
		certPath = rec.CertPath
		if caName == "" {
			caName = rec.CAName
		}
	}
	if certPath == "" {
		return nil, errors.New("cert_name, cert_path, or stapled_address is required")
	}
	certRaw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", certPath, err)
	}
	certs, err := parseCertsFromBytes(certRaw)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("parse certificate %s: %w", certPath, err)
	}
	leaf := certs[0]

	issuer, err := resolveIssuerCert(s, caName, req.CACertPath, certs)
	if err != nil {
		return nil, err
	}

	reqDER, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, fmt.Errorf("create OCSP request: %w", err)
	}

	var respDER []byte
	responderURL := strings.TrimSpace(req.ResponderURL)
	if responderURL != "" {
		httpClient := &http.Client{Timeout: timeout}
		httpReq, err := http.NewRequest(http.MethodPost, responderURL, bytes.NewReader(reqDER))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/ocsp-request")
		httpReq.Header.Set("Accept", "application/ocsp-response")
		httpResp, err := httpClient.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("query OCSP responder %s: %w", responderURL, err)
		}
		defer httpResp.Body.Close()
		if httpResp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OCSP responder %s returned HTTP %d", responderURL, httpResp.StatusCode)
		}
		respDER, err = io.ReadAll(io.LimitReader(httpResp.Body, 64*1024))
		if err != nil {
			return nil, fmt.Errorf("read OCSP response body: %w", err)
		}
	} else {
		if caName == "" {
			return nil, errors.New("ca_name or responder_url is required to verify OCSP status")
		}
		respDER, _, err = GenerateOCSPResponse(s, caName, reqDER, 24*time.Hour)
		if err != nil {
			return nil, err
		}
	}

	parsed, err := ocsp.ParseResponseForCert(respDER, leaf, issuer)
	if err != nil {
		return nil, fmt.Errorf("verify OCSP response signature/cert: %w", err)
	}
	rep := buildOCSPReportFromParsed(parsed)
	rep.ResponderURL = responderURL
	return rep, nil
}

func resolveIssuerCert(s *store.Store, caName, caCertPath string, chain []*x509.Certificate) (*x509.Certificate, error) {
	if strings.TrimSpace(caCertPath) == "" && strings.TrimSpace(caName) != "" && s != nil {
		caRec, err := s.GetCA(strings.TrimSpace(caName))
		if err != nil {
			return nil, fmt.Errorf("resolve CA %q: %w", caName, err)
		}
		caCertPath = caRec.CertPath
	}
	if strings.TrimSpace(caCertPath) != "" {
		raw, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate %s: %w", caCertPath, err)
		}
		caCerts, err := parseCertsFromBytes(raw)
		if err != nil || len(caCerts) == 0 {
			return nil, fmt.Errorf("parse CA certificate %s: %w", caCertPath, err)
		}
		return caCerts[0], nil
	}
	if len(chain) >= 2 {
		return chain[1], nil
	}
	return nil, errors.New("unable to resolve issuer CA certificate (specify --ca or --ca-cert)")
}

func buildOCSPReportFromParsed(parsed *ocsp.Response) *OCSPStatusReport {
	statusStr := "unknown"
	var revokedAtStr string
	switch parsed.Status {
	case ocsp.Good:
		statusStr = "good"
	case ocsp.Revoked:
		statusStr = "revoked"
		revokedAtStr = parsed.RevokedAt.UTC().Format(time.RFC3339)
	case ocsp.Unknown:
		statusStr = "unknown"
	}
	return &OCSPStatusReport{
		SerialHex:        fmt.Sprintf("%x", parsed.SerialNumber.Bytes()),
		Status:           statusStr,
		RevokedAt:        revokedAtStr,
		RevocationReason: parsed.RevocationReason,
		ThisUpdate:       parsed.ThisUpdate.UTC(),
		NextUpdate:       parsed.NextUpdate.UTC(),
		Verified:         statusStr == "good",
	}
}

// MarshalJSON ensures clean JSON output when embedded.
func (r *OCSPStatusReport) String() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func createDelegatedOCSPResponder(caCert *x509.Certificate, caSigner crypto.Signer, now, nextUpdate time.Time) (*x509.Certificate, crypto.Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   caCert.Subject.CommonName + " Delegated OCSP Responder",
			Organization: caCert.Subject.Organization,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              nextUpdate.Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caSigner)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

