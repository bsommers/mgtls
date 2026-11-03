package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

type CARequest struct {
	Name         string `json:"name" yaml:"name"`
	CommonName   string `json:"common_name" yaml:"common_name"`
	Organization string `json:"organization,omitempty" yaml:"organization,omitempty"`
	Country      string `json:"country,omitempty" yaml:"country,omitempty"`
	ParentCA     string `json:"parent_ca,omitempty" yaml:"parent_ca,omitempty"` // empty = Root CA, non-empty = Intermediate CA signed by ParentCA
	Algorithm    string `json:"algorithm,omitempty" yaml:"algorithm,omitempty"` // ed25519 (default), ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096
	ValidDays    int    `json:"valid_days,omitempty" yaml:"valid_days,omitempty"` // default 3650 for root, 1825 for intermediate
}

type CAResult struct {
	Record store.CARecord `json:"record"`
}

type CertRequest struct {
	Name        string   `json:"name" yaml:"name"`
	CommonName  string   `json:"common_name" yaml:"common_name"`
	CAName      string   `json:"ca_name" yaml:"ca_name"`
	Role        string   `json:"role,omitempty" yaml:"role,omitempty"`             // server, client, mtls (default: mtls)
	Algorithm   string   `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`   // ed25519 (default), ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096
	ValidDays   int      `json:"valid_days,omitempty" yaml:"valid_days,omitempty"` // default 365
	DNSNames    []string `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty" yaml:"ip_addresses,omitempty"`
	URIs        []string `json:"uris,omitempty" yaml:"uris,omitempty"`
	Emails      []string `json:"emails,omitempty" yaml:"emails,omitempty"`
}

type SelfSignedRequest struct {
	Name         string   `json:"name" yaml:"name"`
	CommonName   string   `json:"common_name" yaml:"common_name"`
	Organization string   `json:"organization,omitempty" yaml:"organization,omitempty"`
	Role         string   `json:"role,omitempty" yaml:"role,omitempty"` // server, client, mtls (default: mtls)
	Algorithm    string   `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	ValidDays    int      `json:"valid_days,omitempty" yaml:"valid_days,omitempty"` // default 365
	DNSNames     []string `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	IPAddresses  []string `json:"ip_addresses,omitempty" yaml:"ip_addresses,omitempty"`
	URIs         []string `json:"uris,omitempty" yaml:"uris,omitempty"`
}

type CertResult struct {
	Record store.CertRecord `json:"record"`
}

type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialHex          string    `json:"serial_hex"`
	IsCA               bool      `json:"is_ca"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	URIs               []string  `json:"uris,omitempty"`
	ExtKeyUsages       []string  `json:"ext_key_usages,omitempty"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
}

type VerifyResult struct {
	Valid       bool     `json:"valid"`
	ChainLength int      `json:"chain_length"`
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	Revoked     bool     `json:"revoked"`
	Errors      []string `json:"errors,omitempty"`
}

func normalizeAlgorithm(alg string) string {
	a := strings.ToLower(strings.TrimSpace(alg))
	if a == "" {
		return "ed25519"
	}
	return a
}

func generateKeyPair(alg string) (crypto.Signer, []byte, string, error) {
	norm := normalizeAlgorithm(alg)
	var signer crypto.Signer
	var err error

	switch norm {
	case "ed25519":
		_, priv, errGen := ed25519.GenerateKey(rand.Reader)
		signer, err = priv, errGen
	case "ecdsa-p256", "p256", "ecdsa":
		norm = "ecdsa-p256"
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384", "p384":
		norm = "ecdsa-p384"
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa-2048", "rsa":
		norm = "rsa-2048"
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-4096":
		signer, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, nil, "", fmt.Errorf("unsupported algorithm %q", alg)
	}
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate key (%s): %w", norm, err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshal private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	return signer, pemBytes, norm, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	if s.Sign() <= 0 {
		s.SetInt64(1)
	}
	return s, nil
}

func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiASN1, &spki); err != nil {
		return nil, err
	}
	h := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return h[:], nil
}

func certFingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func loadCertAndKey(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certRaw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert %s: %w", certPath, err)
	}
	certs, err := parseCertsFromBytes(certRaw)
	if err != nil || len(certs) == 0 {
		return nil, nil, fmt.Errorf("parse cert %s: %w", certPath, err)
	}

	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read key %s: %w", keyPath, err)
	}
	block, _ := pem.Decode(keyRaw)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block in key %s", keyPath)
	}

	var parsedKey any
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		parsedKey = k
	} else if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		parsedKey = k
	} else if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		parsedKey = k
	} else {
		return nil, nil, fmt.Errorf("unable to parse private key %s", keyPath)
	}

	signer, ok := parsedKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key in %s does not implement crypto.Signer", keyPath)
	}
	return certs[0], signer, nil
}

func parseCertsFromBytes(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) > 0 {
		return certs, nil
	}
	if c, err := x509.ParseCertificate(data); err == nil {
		return []*x509.Certificate{c}, nil
	}
	c, err := x509.ParseCertificate(bytes.TrimSpace(data))
	if err != nil {
		return nil, errors.New("no valid PEM or DER certificate found")
	}
	return []*x509.Certificate{c}, nil
}

func buildCRL(caCert *x509.Certificate, caKey crypto.Signer, revokedEntries []x509.RevocationListEntry) ([]byte, error) {
	num, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: revokedEntries,
		Number:                    num,
		ThisUpdate:                now.Add(-5 * time.Minute),
		NextUpdate:                now.AddDate(0, 0, 30),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CRL: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: der,
	}), nil
}

func CreateCA(s *store.Store, req CARequest) (*CAResult, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errors.New("CA name is required")
	}
	if strings.TrimSpace(req.CommonName) == "" {
		req.CommonName = req.Name
	}

	isRoot := strings.TrimSpace(req.ParentCA) == ""
	validDays := req.ValidDays
	if validDays <= 0 {
		if isRoot {
			validDays = 3650
		} else {
			validDays = 1825
		}
	}

	signer, keyPEM, normAlg, err := generateKeyPair(req.Algorithm)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	ski, err := subjectKeyID(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("compute SKI: %w", err)
	}

	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.AddDate(0, 0, validDays)

	subj := pkix.Name{
		CommonName: req.CommonName,
	}
	if req.Organization != "" {
		subj.Organization = []string{req.Organization}
	}
	if req.Country != "" {
		subj.Country = []string{req.Country}
	}

	maxPath := 2
	if !isRoot {
		maxPath = 1
	}

	keyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPath,
		MaxPathLenZero:        false,
		SubjectKeyId:          ski,
	}

	var certDER []byte
	var parentChainPEM []byte

	if isRoot {
		tmpl.AuthorityKeyId = ski
		certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
		if err != nil {
			return nil, fmt.Errorf("create root CA cert: %w", err)
		}
	} else {
		parentRec, err := s.GetCA(req.ParentCA)
		if err != nil {
			return nil, fmt.Errorf("get parent CA %q: %w", req.ParentCA, err)
		}
		parentCert, parentSigner, err := loadCertAndKey(parentRec.CertPath, parentRec.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("load parent CA %q: %w", req.ParentCA, err)
		}
		tmpl.AuthorityKeyId = parentCert.SubjectKeyId
		certDER, err = x509.CreateCertificate(rand.Reader, tmpl, parentCert, signer.Public(), parentSigner)
		if err != nil {
			return nil, fmt.Errorf("create intermediate CA cert: %w", err)
		}
		parentChainBytes, err := os.ReadFile(parentRec.ChainPath)
		if err != nil {
			parentChainBytes, err = os.ReadFile(parentRec.CertPath)
			if err != nil {
				return nil, fmt.Errorf("read parent chain: %w", err)
			}
		}
		parentChainPEM = parentChainBytes
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	var chainPEM []byte
	if isRoot {
		chainPEM = certPEM
	} else {
		chainPEM = append(append([]byte{}, certPEM...), parentChainPEM...)
	}

	parsedCA, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse created CA cert: %w", err)
	}

	crlPEM, err := buildCRL(parsedCA, signer, nil)
	if err != nil {
		return nil, err
	}

	relDir := filepath.Join("ca", req.Name)
	certPath, err := s.WritePublic(filepath.Join(relDir, "cert.pem"), certPEM)
	if err != nil {
		return nil, err
	}
	keyPath, err := s.WriteKey(filepath.Join(relDir, "key.pem"), keyPEM)
	if err != nil {
		return nil, err
	}
	chainPath, err := s.WritePublic(filepath.Join(relDir, "chain.pem"), chainPEM)
	if err != nil {
		return nil, err
	}
	crlPath, err := s.WritePublic(filepath.Join(relDir, "crl.pem"), crlPEM)
	if err != nil {
		return nil, err
	}

	rec := store.CARecord{
		Name:        req.Name,
		CommonName:  req.CommonName,
		IsRoot:      isRoot,
		ParentCA:    req.ParentCA,
		Algorithm:   normAlg,
		SerialHex:   hex.EncodeToString(serial.Bytes()),
		CertPath:    certPath,
		KeyPath:     keyPath,
		ChainPath:   chainPath,
		CRLPath:     crlPath,
		NotBefore:   parsedCA.NotBefore,
		NotAfter:    parsedCA.NotAfter,
		Fingerprint: certFingerprintSHA256(certDER),
	}

	if err := s.UpsertCA(rec); err != nil {
		return nil, err
	}

	return &CAResult{Record: rec}, nil
}

func resolveRoleAndEKU(role string) (string, []x509.ExtKeyUsage, error) {
	r := strings.ToLower(strings.TrimSpace(role))
	switch r {
	case "", "mtls", "dual":
		return "mtls", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, nil
	case "server":
		return "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil
	case "client":
		return "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil
	default:
		return "", nil, fmt.Errorf("invalid role %q", role)
	}
}

func parseSANs(commonName string, dnsIn, ipIn, uriIn []string) ([]string, []net.IP, []string, []*url.URL, []string, error) {
	dnsSet := make(map[string]bool)
	var dnsNames []string
	for _, d := range dnsIn {
		d = strings.TrimSpace(d)
		if d != "" && !dnsSet[d] {
			dnsSet[d] = true
			dnsNames = append(dnsNames, d)
		}
	}

	ipSet := make(map[string]bool)
	var ips []net.IP
	var ipStrs []string
	for _, rawIP := range ipIn {
		rawIP = strings.TrimSpace(rawIP)
		if rawIP == "" {
			continue
		}
		parsed := net.ParseIP(rawIP)
		if parsed == nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid IP address %q", rawIP)
		}
		canon := parsed.String()
		if !ipSet[canon] {
			ipSet[canon] = true
			ips = append(ips, parsed)
			ipStrs = append(ipStrs, canon)
		}
	}

	cn := strings.TrimSpace(commonName)
	if cn != "" {
		if parsedIP := net.ParseIP(cn); parsedIP != nil {
			canon := parsedIP.String()
			if !ipSet[canon] {
				ipSet[canon] = true
				ips = append(ips, parsedIP)
				ipStrs = append(ipStrs, canon)
			}
		} else if !strings.Contains(cn, " ") {
			if !dnsSet[cn] {
				dnsSet[cn] = true
				dnsNames = append(dnsNames, cn)
			}
		}
	}

	var uris []*url.URL
	var uriStrs []string
	uriSet := make(map[string]bool)
	for _, rawURI := range uriIn {
		rawURI = strings.TrimSpace(rawURI)
		if rawURI == "" {
			continue
		}
		u, err := url.Parse(rawURI)
		if err != nil || u.Scheme == "" {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid URI %q", rawURI)
		}
		s := u.String()
		if !uriSet[s] {
			uriSet[s] = true
			uris = append(uris, u)
			uriStrs = append(uriStrs, s)
		}
	}

	return dnsNames, ips, ipStrs, uris, uriStrs, nil
}

func leafKeyUsage(alg string) x509.KeyUsage {
	ku := x509.KeyUsageDigitalSignature
	if strings.HasPrefix(alg, "rsa") {
		ku |= x509.KeyUsageKeyEncipherment
	}
	return ku
}

func IssueCert(s *store.Store, req CertRequest) (*CertResult, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errors.New("certificate name is required")
	}
	if strings.TrimSpace(req.CAName) == "" {
		return nil, errors.New("CA name is required")
	}
	if strings.TrimSpace(req.CommonName) == "" {
		req.CommonName = req.Name
	}

	caRec, err := s.GetCA(req.CAName)
	if err != nil {
		return nil, err
	}
	caCert, caSigner, err := loadCertAndKey(caRec.CertPath, caRec.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load signing CA %q: %w", req.CAName, err)
	}
	caChainPEM, err := os.ReadFile(caRec.ChainPath)
	if err != nil {
		caChainPEM, err = os.ReadFile(caRec.CertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA chain: %w", err)
		}
	}

	normRole, ekus, err := resolveRoleAndEKU(req.Role)
	if err != nil {
		return nil, err
	}

	dnsNames, ips, ipStrs, uris, uriStrs, err := parseSANs(req.CommonName, req.DNSNames, req.IPAddresses, req.URIs)
	if err != nil {
		return nil, err
	}

	signer, keyPEM, normAlg, err := generateKeyPair(req.Algorithm)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(signer.Public())
	if err != nil {
		return nil, err
	}

	validDays := req.ValidDays
	if validDays <= 0 {
		validDays = 365
	}
	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.AddDate(0, 0, validDays)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: req.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              leafKeyUsage(normAlg),
		ExtKeyUsage:           ekus,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		AuthorityKeyId:        caCert.SubjectKeyId,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		URIs:                  uris,
		EmailAddresses:        req.Emails,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, signer.Public(), caSigner)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse signed certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	fullChainPEM := append(append([]byte{}, certPEM...), caChainPEM...)
	bundlePEM := append(append([]byte{}, fullChainPEM...), keyPEM...)

	relDir := filepath.Join("certs", req.Name)
	certPath, err := s.WritePublic(filepath.Join(relDir, "cert.pem"), certPEM)
	if err != nil {
		return nil, err
	}
	keyPath, err := s.WriteKey(filepath.Join(relDir, "key.pem"), keyPEM)
	if err != nil {
		return nil, err
	}
	fullChainPath, err := s.WritePublic(filepath.Join(relDir, "fullchain.pem"), fullChainPEM)
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
	bundlePath, err := s.WriteKey(filepath.Join(relDir, "bundle.pem"), bundlePEM)
	if err != nil {
		return nil, err
	}

	rec := store.CertRecord{
		Name:          req.Name,
		CommonName:    req.CommonName,
		CAName:        req.CAName,
		SelfSigned:    false,
		Role:          normRole,
		Algorithm:     normAlg,
		SerialHex:     hex.EncodeToString(serial.Bytes()),
		DNSNames:      dnsNames,
		IPAddresses:   ipStrs,
		URIs:          uriStrs,
		CertPath:      certPath,
		KeyPath:       keyPath,
		FullChainPath: fullChainPath,
		CAChainPath:   caChainPath,
		DERPath:       derPath,
		BundlePath:    bundlePath,
		NotBefore:     parsedCert.NotBefore,
		NotAfter:      parsedCert.NotAfter,
		Revoked:       false,
		Fingerprint:   certFingerprintSHA256(certDER),
	}

	if err := s.UpsertCert(rec); err != nil {
		return nil, err
	}
	return &CertResult{Record: rec}, nil
}

func IssueSelfSigned(s *store.Store, req SelfSignedRequest) (*CertResult, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errors.New("certificate name is required")
	}
	if strings.TrimSpace(req.CommonName) == "" {
		req.CommonName = req.Name
	}

	normRole, ekus, err := resolveRoleAndEKU(req.Role)
	if err != nil {
		return nil, err
	}

	dnsNames, ips, ipStrs, uris, uriStrs, err := parseSANs(req.CommonName, req.DNSNames, req.IPAddresses, req.URIs)
	if err != nil {
		return nil, err
	}

	signer, keyPEM, normAlg, err := generateKeyPair(req.Algorithm)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(signer.Public())
	if err != nil {
		return nil, err
	}

	validDays := req.ValidDays
	if validDays <= 0 {
		validDays = 365
	}
	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.AddDate(0, 0, validDays)

	subj := pkix.Name{CommonName: req.CommonName}
	if req.Organization != "" {
		subj.Organization = []string{req.Organization}
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              leafKeyUsage(normAlg),
		ExtKeyUsage:           ekus,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		AuthorityKeyId:        ski,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		URIs:                  uris,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("create self-signed certificate: %w", err)
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse self-signed certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	bundlePEM := append(append([]byte{}, certPEM...), keyPEM...)

	relDir := filepath.Join("certs", req.Name)
	certPath, err := s.WritePublic(filepath.Join(relDir, "cert.pem"), certPEM)
	if err != nil {
		return nil, err
	}
	keyPath, err := s.WriteKey(filepath.Join(relDir, "key.pem"), keyPEM)
	if err != nil {
		return nil, err
	}
	fullChainPath, err := s.WritePublic(filepath.Join(relDir, "fullchain.pem"), certPEM)
	if err != nil {
		return nil, err
	}
	caChainPath, err := s.WritePublic(filepath.Join(relDir, "ca-chain.pem"), certPEM)
	if err != nil {
		return nil, err
	}
	derPath, err := s.WritePublic(filepath.Join(relDir, "cert.der"), certDER)
	if err != nil {
		return nil, err
	}
	bundlePath, err := s.WriteKey(filepath.Join(relDir, "bundle.pem"), bundlePEM)
	if err != nil {
		return nil, err
	}

	rec := store.CertRecord{
		Name:          req.Name,
		CommonName:    req.CommonName,
		SelfSigned:    true,
		Role:          normRole,
		Algorithm:     normAlg,
		SerialHex:     hex.EncodeToString(serial.Bytes()),
		DNSNames:      dnsNames,
		IPAddresses:   ipStrs,
		URIs:          uriStrs,
		CertPath:      certPath,
		KeyPath:       keyPath,
		FullChainPath: fullChainPath,
		CAChainPath:   caChainPath,
		DERPath:       derPath,
		BundlePath:    bundlePath,
		NotBefore:     parsedCert.NotBefore,
		NotAfter:      parsedCert.NotAfter,
		Revoked:       false,
		Fingerprint:   certFingerprintSHA256(certDER),
	}

	if err := s.UpsertCert(rec); err != nil {
		return nil, err
	}
	return &CertResult{Record: rec}, nil
}

func InspectCert(certPath string) (*CertInfo, error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", certPath, err)
	}
	certs, err := parseCertsFromBytes(raw)
	if err != nil {
		return nil, err
	}
	c := certs[0]

	var ipStrs []string
	for _, ip := range c.IPAddresses {
		ipStrs = append(ipStrs, ip.String())
	}
	var uriStrs []string
	for _, u := range c.URIs {
		uriStrs = append(uriStrs, u.String())
	}
	var ekus []string
	for _, eku := range c.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			ekus = append(ekus, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			ekus = append(ekus, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			ekus = append(ekus, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			ekus = append(ekus, "EmailProtection")
		case x509.ExtKeyUsageOCSPSigning:
			ekus = append(ekus, "OCSPSigning")
		case x509.ExtKeyUsageAny:
			ekus = append(ekus, "Any")
		default:
			ekus = append(ekus, fmt.Sprintf("ExtKeyUsage(%d)", int(eku)))
		}
	}

	return &CertInfo{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SerialHex:          hex.EncodeToString(c.SerialNumber.Bytes()),
		IsCA:               c.IsCA,
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		DNSNames:           c.DNSNames,
		IPAddresses:        ipStrs,
		URIs:               uriStrs,
		ExtKeyUsages:       ekus,
		FingerprintSHA256:  certFingerprintSHA256(c.Raw),
	}, nil
}

func hasExtKeyUsage(cert *x509.Certificate, target x509.ExtKeyUsage) bool {
	for _, u := range cert.ExtKeyUsage {
		if u == target || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func parseCRLFromBytes(data []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseRevocationList(block.Bytes)
	}
	if crl, err := x509.ParseRevocationList(data); err == nil {
		return crl, nil
	}
	return x509.ParseRevocationList(bytes.TrimSpace(data))
}

func VerifyChain(certPath, caBundlePath, crlPath, dnsName, role string) (*VerifyResult, error) {
	certRaw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert %s: %w", certPath, err)
	}
	certs, err := parseCertsFromBytes(certRaw)
	if err != nil {
		return nil, fmt.Errorf("parse cert %s: %w", certPath, err)
	}
	leaf := certs[0]

	res := &VerifyResult{
		Valid:   true,
		Subject: leaf.Subject.String(),
		Issuer:  leaf.Issuer.String(),
	}

	intermediates := x509.NewCertPool()
	for _, ic := range certs[1:] {
		intermediates.AddCert(ic)
	}

	roots := x509.NewCertPool()
	var bundleCerts []*x509.Certificate
	if strings.TrimSpace(caBundlePath) != "" {
		caRaw, err := os.ReadFile(caBundlePath)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle %s: %w", caBundlePath, err)
		}
		bundleCerts, err = parseCertsFromBytes(caRaw)
		if err != nil {
			return nil, fmt.Errorf("parse CA bundle %s: %w", caBundlePath, err)
		}
		for _, bc := range bundleCerts {
			roots.AddCert(bc)
			if bc.Subject.String() != bc.Issuer.String() {
				intermediates.AddCert(bc)
			}
		}
	} else {
		sysRoots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system cert pool: %w", err)
		}
		roots = sysRoots
	}

	var keyUsages []x509.ExtKeyUsage
	r := strings.ToLower(strings.TrimSpace(role))
	switch r {
	case "":
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	case "server":
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
			res.Valid = false
			res.Errors = append(res.Errors, "certificate missing ServerAuth extended key usage")
		}
	case "client":
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if !hasExtKeyUsage(leaf, x509.ExtKeyUsageClientAuth) {
			res.Valid = false
			res.Errors = append(res.Errors, "certificate missing ClientAuth extended key usage")
		}
	case "mtls", "dual":
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) || !hasExtKeyUsage(leaf, x509.ExtKeyUsageClientAuth) {
			res.Valid = false
			res.Errors = append(res.Errors, "certificate missing mTLS (ServerAuth+ClientAuth) extended key usage")
		}
	default:
		return nil, fmt.Errorf("unsupported role %q", role)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       strings.TrimSpace(dnsName),
		KeyUsages:     keyUsages,
	}

	chains, verifyErr := leaf.Verify(opts)
	if verifyErr != nil {
		res.Valid = false
		res.Errors = append(res.Errors, verifyErr.Error())
	} else if len(chains) > 0 {
		res.ChainLength = len(chains[0])
	}

	if strings.TrimSpace(crlPath) != "" {
		crlRaw, err := os.ReadFile(crlPath)
		if err != nil {
			return nil, fmt.Errorf("read CRL %s: %w", crlPath, err)
		}
		crl, err := parseCRLFromBytes(crlRaw)
		if err != nil {
			return nil, fmt.Errorf("parse CRL %s: %w", crlPath, err)
		}

		// Optionally check CRL signature against known CA certs if available
		var crlIssuers []*x509.Certificate
		crlIssuers = append(crlIssuers, certs[1:]...)
		crlIssuers = append(crlIssuers, bundleCerts...)
		for _, issuer := range crlIssuers {
			if issuer.Subject.String() == crl.Issuer.String() {
				if err := crl.CheckSignatureFrom(issuer); err != nil {
					res.Valid = false
					res.Errors = append(res.Errors, fmt.Sprintf("CRL signature check failed: %v", err))
				}
				break
			}
		}

		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				res.Revoked = true
				res.Valid = false
				res.Errors = append(res.Errors, fmt.Sprintf("certificate serial %x is revoked in CRL", leaf.SerialNumber))
				break
			}
		}
	}

	return res, nil
}

func RevokeCert(s *store.Store, caName, certName string, reasonCode int) (string, error) {
	if s == nil {
		return "", errors.New("store is nil")
	}
	caRec, err := s.GetCA(caName)
	if err != nil {
		return "", err
	}
	certRec, err := s.GetCert(certName)
	if err != nil {
		return "", err
	}
	if certRec.CAName != caName {
		return "", fmt.Errorf("certificate %q was issued by %q, not %q", certName, certRec.CAName, caName)
	}

	now := time.Now().UTC()
	certRec.Revoked = true
	certRec.RevokedAt = now
	if err := s.UpsertCert(*certRec); err != nil {
		return "", err
	}

	manifest, err := s.LoadManifest()
	if err != nil {
		return "", err
	}

	var entries []x509.RevocationListEntry
	for _, c := range manifest.Certs {
		if c.CAName != caName || !c.Revoked {
			continue
		}
		serialBytes, err := hex.DecodeString(c.SerialHex)
		if err != nil {
			return "", fmt.Errorf("decode serial %q for cert %q: %w", c.SerialHex, c.Name, err)
		}
		serial := new(big.Int).SetBytes(serialBytes)
		revTime := c.RevokedAt
		if revTime.IsZero() {
			revTime = now
		}
		rc := reasonCode
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revTime,
			ReasonCode:     rc,
		})
	}

	caCert, caSigner, err := loadCertAndKey(caRec.CertPath, caRec.KeyPath)
	if err != nil {
		return "", fmt.Errorf("load CA %q for CRL signing: %w", caName, err)
	}

	crlPEM, err := buildCRL(caCert, caSigner, entries)
	if err != nil {
		return "", err
	}

	relCRL := filepath.Join("ca", caName, "crl.pem")
	crlPath, err := s.WritePublic(relCRL, crlPEM)
	if err != nil {
		return "", err
	}

	caRec.CRLPath = crlPath
	if err := s.UpsertCA(*caRec); err != nil {
		return "", err
	}

	return crlPath, nil
}

func GenerateTrustScript(caCertPath, name string) (map[string]string, error) {
	if strings.TrimSpace(caCertPath) == "" {
		return nil, errors.New("caCertPath is required")
	}
	safeName := strings.TrimSpace(name)
	if safeName == "" {
		safeName = "mgtls-ca"
	}

	scripts := map[string]string{
		"debian": fmt.Sprintf(
			"sudo cp %q /usr/local/share/ca-certificates/%s.crt && sudo update-ca-certificates",
			caCertPath, safeName,
		),
		"rhel": fmt.Sprintf(
			"sudo cp %q /etc/pki/ca-trust/source/anchors/%s.crt && sudo update-ca-trust extract",
			caCertPath, safeName,
		),
		"arch": fmt.Sprintf(
			"sudo trust anchor --store %q",
			caCertPath,
		),
		"macos": fmt.Sprintf(
			"sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %q",
			caCertPath,
		),
		"windows": fmt.Sprintf(
			"Import-Certificate -FilePath %q -CertStoreLocation Cert:\\LocalMachine\\Root",
			caCertPath,
		),
	}
	return scripts, nil
}
