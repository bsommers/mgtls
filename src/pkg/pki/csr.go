package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

// maxCSRBytes bounds CSR input size (untrusted).
const maxCSRBytes = 64 << 10

// CSRRequest describes a PKCS#10 certificate signing request to create locally.
// The private key is generated (or loaded) on the machine running this call and never
// enters the mgtls store or manifest.
type CSRRequest struct {
	Name         string   `json:"name" yaml:"name"`
	CommonName   string   `json:"common_name,omitempty" yaml:"common_name,omitempty"`
	Organization string   `json:"organization,omitempty" yaml:"organization,omitempty"`
	Algorithm    string   `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	DNSNames     []string `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	IPAddresses  []string `json:"ip_addresses,omitempty" yaml:"ip_addresses,omitempty"`
	URIs         []string `json:"uris,omitempty" yaml:"uris,omitempty"`
	Emails       []string `json:"emails,omitempty" yaml:"emails,omitempty"`
	OutDir       string   `json:"out_dir,omitempty" yaml:"out_dir,omitempty"`           // default "."
	ExistingKey  string   `json:"existing_key,omitempty" yaml:"existing_key,omitempty"` // reuse this PEM private key (e.g. for renewal)
}

// CSRResult reports where the CSR (and a newly generated key) were written.
type CSRResult struct {
	Name         string   `json:"name"`
	CSRPath      string   `json:"csr_path"`
	KeyPath      string   `json:"key_path"`
	KeyGenerated bool     `json:"key_generated"`
	Algorithm    string   `json:"algorithm"`
	CommonName   string   `json:"common_name"`
	DNSNames     []string `json:"dns_names,omitempty"`
	IPAddresses  []string `json:"ip_addresses,omitempty"`
	URIs         []string `json:"uris,omitempty"`
	Emails       []string `json:"emails,omitempty"`
	CSRPEM       string   `json:"csr_pem"`
}

// CreateCSR generates a PKCS#10 CSR. It does not touch the mgtls store.
func CreateCSR(req CSRRequest) (*CSRResult, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return nil, errors.New("CSR name is required and must be a plain file name (no path separators)")
	}
	cn := strings.TrimSpace(req.CommonName)
	if cn == "" {
		cn = name
	}
	dnsNames, ips, ipStrs, uris, uriStrs, err := parseSANs(cn, req.DNSNames, req.IPAddresses, req.URIs)
	if err != nil {
		return nil, err
	}
	outDir := req.OutDir
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	var (
		signer       crypto.Signer
		keyPEM       []byte
		normAlg      string
		keyPath      string
		keyGenerated bool
	)
	if req.ExistingKey != "" {
		raw, err := os.ReadFile(req.ExistingKey)
		if err != nil {
			return nil, fmt.Errorf("read existing key: %w", err)
		}
		if signer, err = parsePrivateKeyPEM(raw); err != nil {
			return nil, fmt.Errorf("existing key %s: %w", req.ExistingKey, err)
		}
		keyPath = req.ExistingKey
		normAlg = describeKeyAlg(signer.Public())
	} else {
		if signer, keyPEM, normAlg, err = generateKeyPair(req.Algorithm); err != nil {
			return nil, err
		}
		keyGenerated = true
		keyPath = filepath.Join(outDir, name+".key.pem")
	}

	subject := pkix.Name{CommonName: cn}
	if org := strings.TrimSpace(req.Organization); org != "" {
		subject.Organization = []string{org}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        subject,
		DNSNames:       dnsNames,
		IPAddresses:    ips,
		URIs:           uris,
		EmailAddresses: req.Emails,
	}, signer)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csrPath := filepath.Join(outDir, name+".csr.pem")

	// Never clobber an existing private key.
	if keyGenerated {
		if err := writeExclusive(keyPath, keyPEM, 0o600); err != nil {
			return nil, fmt.Errorf("write key (refusing to overwrite existing file): %w", err)
		}
	}
	if err := os.WriteFile(csrPath, csrPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write CSR: %w", err)
	}
	return &CSRResult{
		Name: name, CSRPath: csrPath, KeyPath: keyPath, KeyGenerated: keyGenerated, Algorithm: normAlg,
		CommonName: cn, DNSNames: dnsNames, IPAddresses: ipStrs, URIs: uriStrs, Emails: req.Emails,
		CSRPEM: string(csrPEM),
	}, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

func parsePrivateKeyPEM(raw []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if store.IsSealed(raw) {
		return nil, errors.New("key is an mgtls vault envelope; decrypt it first")
	}
	var parsed any
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		parsed = k
	} else if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		parsed = k
	} else if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		parsed = k
	} else {
		return nil, errors.New("unable to parse private key")
	}
	s, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer")
	}
	return s, nil
}

func describeKeyAlg(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return "ed25519"
	case *ecdsa.PublicKey:
		return "ecdsa-p" + strings.TrimPrefix(k.Curve.Params().Name, "P-")
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", k.N.BitLen())
	}
	return "unknown"
}

// SignCSRRequest asks a mgtls CA to sign an externally generated PKCS#10 CSR.
type SignCSRRequest struct {
	Name      string        `json:"name" yaml:"name"`                                 // store name for the issued certificate (default: CSR common name)
	CAName    string        `json:"ca_name" yaml:"ca_name"`                           // issuing CA
	CSRPEM    string        `json:"csr_pem,omitempty" yaml:"csr_pem,omitempty"`       // inline PEM
	CSRPath   string        `json:"csr_path,omitempty" yaml:"csr_path,omitempty"`     // or path to a .csr.pem
	Role      string        `json:"role,omitempty" yaml:"role,omitempty"`             // server, client, mtls (default: mtls)
	ValidDays int           `json:"valid_days,omitempty" yaml:"valid_days,omitempty"` // default 365
	CASigner  crypto.Signer `json:"-" yaml:"-"`                                       // optional hardware/KMS/HSM signer seam
}

// SignCSRResult is the signed certificate (the leaf private key is never held by mgtls).
type SignCSRResult struct {
	Record   store.CertRecord `json:"record"`
	CertPEM  string           `json:"cert_pem"`
	ChainPEM string           `json:"fullchain_pem"`
}

// SignCSR validates a CSR (proof-of-possession signature, key strength, requested names) and
// issues a leaf certificate. Only the subject CN and SANs are taken from the CSR; every
// extension it requests (CA:TRUE, EKUs, key usage, ...) is ignored and replaced by the
// role policy, so a CSR can never escalate itself into a CA or a wrong-purpose cert.
func SignCSR(s *store.Store, req SignCSRRequest) (*SignCSRResult, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if strings.TrimSpace(req.CAName) == "" {
		return nil, errors.New("CA name is required")
	}
	raw := []byte(req.CSRPEM)
	if len(raw) == 0 {
		if req.CSRPath == "" {
			return nil, errors.New("csr_pem or csr_path is required")
		}
		f, err := os.Open(req.CSRPath)
		if err != nil {
			return nil, fmt.Errorf("read CSR: %w", err)
		}
		defer f.Close()
		if raw, err = io.ReadAll(io.LimitReader(f, maxCSRBytes+1)); err != nil {
			return nil, fmt.Errorf("read CSR: %w", err)
		}
	}
	if len(raw) > maxCSRBytes {
		return nil, fmt.Errorf("CSR too large (max %d bytes)", maxCSRBytes)
	}
	block, _ := pem.Decode(raw)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, errors.New("input is not a PEM PKCS#10 CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature (proof of possession) invalid: %w", err)
	}
	if err := checkPublicKeyStrength(csr.PublicKey); err != nil {
		return nil, err
	}

	cn := strings.TrimSpace(csr.Subject.CommonName)
	var uriIn []string
	for _, u := range csr.URIs {
		uriIn = append(uriIn, u.String())
	}
	var ipIn []string
	for _, ip := range csr.IPAddresses {
		ipIn = append(ipIn, ip.String())
	}
	dnsNames, ips, ipStrs, uris, uriStrs, err := parseSANs(cn, csr.DNSNames, ipIn, uriIn)
	if err != nil {
		return nil, err
	}
	if len(dnsNames)+len(ips)+len(uris)+len(csr.EmailAddresses) == 0 {
		return nil, errors.New("CSR has no usable subject names: need a common name or at least one SAN")
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = cn
	}
	if name == "" {
		return nil, errors.New("certificate name is required (CSR has no common name)")
	}
	if cn == "" {
		cn = name
	}
	normRole, ekus, err := resolveRoleAndEKU(req.Role)
	if err != nil {
		return nil, err
	}

	caRec, err := s.GetCA(req.CAName)
	if err != nil {
		return nil, err
	}
	var caCert *x509.Certificate
	var caSigner crypto.Signer
	if req.CASigner != nil {
		certRaw, rErr := os.ReadFile(caRec.CertPath)
		if rErr != nil {
			return nil, fmt.Errorf("read signing CA cert %q: %w", req.CAName, rErr)
		}
		certs, pErr := parseCertsFromBytes(certRaw)
		if pErr != nil || len(certs) == 0 {
			return nil, fmt.Errorf("parse signing CA cert %q: %w", req.CAName, pErr)
		}
		caCert, caSigner = certs[0], req.CASigner
	} else if caCert, caSigner, err = loadCertAndKey(caRec.CertPath, caRec.KeyPath); err != nil {
		return nil, fmt.Errorf("load signing CA %q: %w", req.CAName, err)
	}
	caChainPEM, err := os.ReadFile(caRec.ChainPath)
	if err != nil {
		if caChainPEM, err = os.ReadFile(caRec.CertPath); err != nil {
			return nil, fmt.Errorf("read CA chain: %w", err)
		}
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	validDays := req.ValidDays
	if validDays <= 0 {
		validDays = 365
	}
	now := time.Now().UTC()
	notAfter := now.AddDate(0, 0, validDays)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              leafKeyUsage(describeKeyAlg(csr.PublicKey)),
		ExtKeyUsage:           ekus,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		AuthorityKeyId:        caCert.SubjectKeyId,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		URIs:                  uris,
		EmailAddresses:        csr.EmailAddresses,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse signed certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	fullChain := append(append([]byte{}, certPEM...), caChainPEM...)

	relDir := filepath.Join("certs", name)
	certPath, err := s.WritePublic(filepath.Join(relDir, "cert.pem"), certPEM)
	if err != nil {
		return nil, err
	}
	fullChainPath, err := s.WritePublic(filepath.Join(relDir, "fullchain.pem"), fullChain)
	if err != nil {
		return nil, err
	}
	caChainPath, err := s.WritePublic(filepath.Join(relDir, "ca-chain.pem"), caChainPEM)
	if err != nil {
		return nil, err
	}
	derPath, err := s.WritePublic(filepath.Join(relDir, "cert.der"), certDER)
	if err != nil {
		return nil, err
	}
	if _, err := s.WritePublic(filepath.Join(relDir, "request.csr.pem"), pem.EncodeToMemory(block)); err != nil {
		return nil, err
	}

	rec := store.CertRecord{
		Name: name, CommonName: cn, CAName: req.CAName, Role: normRole,
		Algorithm: describeKeyAlg(csr.PublicKey), SerialHex: hex.EncodeToString(serial.Bytes()),
		DNSNames: dnsNames, IPAddresses: ipStrs, URIs: uriStrs,
		CertPath: certPath, FullChainPath: fullChainPath, CAChainPath: caChainPath, DERPath: derPath,
		NotBefore: parsed.NotBefore, NotAfter: parsed.NotAfter,
		Fingerprint: certFingerprintSHA256(certDER),
		External:    true, // leaf private key is held by the requester, not by mgtls
	}
	if err := s.UpsertCert(rec); err != nil {
		return nil, err
	}
	return &SignCSRResult{Record: rec, CertPEM: string(certPEM), ChainPEM: string(fullChain)}, nil
}

func checkPublicKeyStrength(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return nil
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			return fmt.Errorf("CSR ECDSA key too weak (%d-bit); need P-256 or stronger", k.Curve.Params().BitSize)
		}
		return nil
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("CSR RSA key too weak (%d-bit); need >= 2048", k.N.BitLen())
		}
		return nil
	}
	return fmt.Errorf("unsupported CSR public key type %T", pub)
}
