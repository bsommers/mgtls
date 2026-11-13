package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

// SPIFFEBundleMediaType is the media type of a SPIFFE trust bundle document.
const SPIFFEBundleMediaType = "application/spiffe-bundle+json"

// ValidateSPIFFEID enforces spiffe://<trust-domain>/<workload-path> syntax
// (SPIFFE-ID spec): lowercase trust domain, no userinfo/port/query/fragment,
// non-empty path without empty, "." or ".." segments or a trailing slash.
func ValidateSPIFFEID(raw string) (trustDomain, workloadPath string, err error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "spiffe://") {
		return "", "", fmt.Errorf("SPIFFE ID %q must start with spiffe://", raw)
	}
	if strings.ContainsAny(raw, "?#") {
		return "", "", errors.New("SPIFFE ID must not contain a query or fragment")
	}
	rest := strings.TrimPrefix(raw, "spiffe://")
	td, path, found := strings.Cut(rest, "/")
	if td == "" {
		return "", "", errors.New("SPIFFE ID trust domain is empty")
	}
	if strings.ContainsAny(td, "@:") {
		return "", "", errors.New("SPIFFE ID trust domain must not contain userinfo or port")
	}
	for _, c := range td {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return "", "", fmt.Errorf("SPIFFE ID trust domain %q has invalid character %q (lowercase letters, digits, '.', '-', '_' only)", td, c)
		}
	}
	if !found || path == "" {
		return "", "", errors.New("SPIFFE ID workload path is required")
	}
	if strings.HasSuffix(path, "/") {
		return "", "", errors.New("SPIFFE ID path must not end with '/'")
	}
	for _, seg := range strings.Split(path, "/") {
		switch seg {
		case "", ".", "..":
			return "", "", fmt.Errorf("SPIFFE ID path has invalid segment %q", seg)
		}
		for _, c := range seg {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
				return "", "", fmt.Errorf("SPIFFE ID path segment %q has invalid character %q", seg, c)
			}
		}
	}
	return td, "/" + path, nil
}

// SVIDRequest issues an X.509-SVID.
type SVIDRequest struct {
	Name      string   `json:"name"`
	SPIFFEID  string   `json:"spiffe_id"`
	CAName    string   `json:"ca_name"`
	Algorithm string   `json:"algorithm,omitempty"`
	ValidDays int      `json:"valid_days,omitempty"` // default 1
	DNSNames  []string `json:"dns_names,omitempty"`
}

// IssueSVID issues a leaf with exactly one spiffe:// URI SAN, mTLS EKUs and no CA capability.
func IssueSVID(s *store.Store, req SVIDRequest) (*CertResult, error) {
	if _, _, err := ValidateSPIFFEID(req.SPIFFEID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errors.New("SVID name is required")
	}
	if req.ValidDays <= 0 {
		req.ValidDays = 1
	}
	if strings.TrimSpace(req.CAName) == "" {
		req.CAName = "root-ca"
	}
	res, err := IssueCert(s, CertRequest{
		Name:       req.Name,
		CommonName: "SVID " + req.Name, // contains a space: no implicit DNS SAN from the CN
		CAName:     req.CAName,
		Role:       "mtls",
		Algorithm:  req.Algorithm,
		ValidDays:  req.ValidDays,
		DNSNames:   req.DNSNames,
		URIs:       []string{strings.TrimSpace(req.SPIFFEID)},
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// VerifySVIDRequest verifies an X.509-SVID.
type VerifySVIDRequest struct {
	CertName    string `json:"cert_name,omitempty"`
	CertPath    string `json:"cert_path,omitempty"`
	CAName      string `json:"ca_name,omitempty"`
	BundlePath  string `json:"bundle_path,omitempty"`
	TrustDomain string `json:"trust_domain,omitempty"` // optional expected trust domain
	ExpectedID  string `json:"expected_id,omitempty"`  // optional exact SPIFFE ID
	CRLPath     string `json:"crl_path,omitempty"`     // default: CA's CRL
}

// SVIDVerifyReport is the result of VerifySVID.
type SVIDVerifyReport struct {
	Valid       bool     `json:"valid"`
	SPIFFEID    string   `json:"spiffe_id,omitempty"`
	TrustDomain string   `json:"trust_domain,omitempty"`
	Path        string   `json:"path,omitempty"`
	Revoked     bool     `json:"revoked"`
	ChainLength int      `json:"chain_length"`
	NotAfter    string   `json:"not_after,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

// VerifySVID validates chain, SPIFFE URI SAN, leaf constraints and revocation.
func VerifySVID(s *store.Store, req VerifySVIDRequest) (*SVIDVerifyReport, error) {
	certPath, bundle, crl := req.CertPath, req.BundlePath, req.CRLPath
	if certPath == "" && req.CertName != "" {
		if s == nil {
			return nil, errors.New("store is nil")
		}
		rec, err := s.GetCert(req.CertName)
		if err != nil {
			return nil, err
		}
		certPath = rec.CertPath
		if rec.FullChainPath != "" {
			certPath = rec.FullChainPath
		}
	}
	if certPath == "" {
		return nil, errors.New("cert_name or cert_path is required")
	}
	if req.CAName != "" {
		if s == nil {
			return nil, errors.New("store is nil")
		}
		ca, err := s.GetCA(req.CAName)
		if err != nil {
			return nil, err
		}
		if bundle == "" {
			bundle = ca.ChainPath
			if _, err := os.Stat(bundle); err != nil {
				bundle = ca.CertPath
			}
		}
		if crl == "" && ca.CRLPath != "" {
			crl = ca.CRLPath
		}
	}
	if bundle == "" {
		return nil, errors.New("ca_name or bundle_path is required (SVIDs are never verified against system roots)")
	}
	vr, err := VerifyChain(certPath, bundle, crl, "", "")
	if err != nil {
		return nil, err
	}
	rep := &SVIDVerifyReport{Valid: vr.Valid, Revoked: vr.Revoked, ChainLength: vr.ChainLength, Errors: vr.Errors}
	raw, _ := os.ReadFile(certPath)
	certs, err := parseCertsFromBytes(raw)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("parse SVID %s: %v", certPath, err)
	}
	leaf := certs[0]
	rep.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	fail := func(f string, a ...any) { rep.Valid = false; rep.Errors = append(rep.Errors, fmt.Sprintf(f, a...)) }

	if len(leaf.URIs) != 1 {
		fail("X.509-SVID must contain exactly one URI SAN, found %d", len(leaf.URIs))
	} else {
		id := leaf.URIs[0].String()
		td, path, vErr := ValidateSPIFFEID(id)
		if vErr != nil {
			fail("invalid SPIFFE ID: %v", vErr)
		} else {
			rep.SPIFFEID, rep.TrustDomain, rep.Path = id, td, path
			if want := strings.TrimSpace(req.TrustDomain); want != "" && !strings.EqualFold(want, td) {
				fail("trust domain %q does not match expected %q", td, want)
			}
			if want := strings.TrimSpace(req.ExpectedID); want != "" && want != id {
				fail("SPIFFE ID %q does not match expected %q", id, want)
			}
		}
	}
	if leaf.IsCA {
		fail("X.509-SVID leaf must not be a CA")
	}
	if leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		fail("X.509-SVID leaf must not set keyCertSign or cRLSign")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		fail("X.509-SVID leaf must set digitalSignature")
	}
	return rep, nil
}

// TrustBundleRequest exports a CA's trust bundle.
type TrustBundleRequest struct {
	CAName      string `json:"ca_name"`
	Format      string `json:"format,omitempty"` // spiffe (default) | pem
	Sequence    uint64 `json:"sequence,omitempty"`
	RefreshHint int    `json:"refresh_hint,omitempty"` // seconds, default 300
	OutPath     string `json:"out_path,omitempty"`
}

// TrustBundleResult holds an exported bundle.
type TrustBundleResult struct {
	Format    string `json:"format"`
	MediaType string `json:"media_type"`
	Content   string `json:"content"`
	Certs     int    `json:"certs"`
	OutPath   string `json:"out_path,omitempty"`
}

type jwk struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Crv string   `json:"crv,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	X5C []string `json:"x5c"`
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func certToJWK(c *x509.Certificate) (jwk, error) {
	k := jwk{Use: "x509-svid", X5C: []string{base64.StdEncoding.EncodeToString(c.Raw)}}
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		k.Kty, k.N, k.E = "RSA", b64u(pub.N.Bytes()), b64u(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		size := (pub.Curve.Params().BitSize + 7) / 8
		k.Kty, k.Crv = "EC", pub.Curve.Params().Name
		k.X, k.Y = b64u(pub.X.FillBytes(make([]byte, size))), b64u(pub.Y.FillBytes(make([]byte, size)))
	case ed25519.PublicKey:
		k.Kty, k.Crv, k.X = "OKP", "Ed25519", b64u(pub)
	default:
		return k, fmt.Errorf("unsupported public key type %T", c.PublicKey)
	}
	return k, nil
}

// ExportTrustBundle emits a CA's chain as a SPIFFE bundle JSON document or PEM.
func ExportTrustBundle(s *store.Store, req TrustBundleRequest) (*TrustBundleResult, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	ca, err := s.GetCA(req.CAName)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(ca.ChainPath)
	if err != nil {
		if raw, err = os.ReadFile(ca.CertPath); err != nil {
			return nil, fmt.Errorf("read CA bundle: %w", err)
		}
	}
	certs, err := parseCertsFromBytes(raw)
	if err != nil {
		return nil, err
	}
	res := &TrustBundleResult{Certs: len(certs)}
	switch f := strings.ToLower(strings.TrimSpace(req.Format)); f {
	case "pem":
		res.Format, res.MediaType, res.Content = "pem", "application/x-pem-file", string(raw)
	case "", "spiffe":
		seq, hint := req.Sequence, req.RefreshHint
		if seq == 0 {
			seq = uint64(time.Now().Unix())
		}
		if hint <= 0 {
			hint = 300
		}
		keys := make([]jwk, 0, len(certs))
		for _, c := range certs {
			k, kErr := certToJWK(c)
			if kErr != nil {
				return nil, kErr
			}
			keys = append(keys, k)
		}
		doc, _ := json.MarshalIndent(map[string]any{
			"spiffe_sequence": seq, "spiffe_refresh_hint": hint, "keys": keys,
		}, "", "  ")
		res.Format, res.MediaType, res.Content = "spiffe", SPIFFEBundleMediaType, string(doc)
	default:
		return nil, fmt.Errorf("unsupported bundle format %q (expected spiffe or pem)", f)
	}
	if req.OutPath != "" {
		if err := os.WriteFile(req.OutPath, []byte(res.Content), 0o644); err != nil {
			return nil, fmt.Errorf("write bundle: %w", err)
		}
		res.OutPath = req.OutPath
	}
	return res, nil
}
