package pki

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

// ---- Trust bundle compiler -------------------------------------------------

// DefaultTruststorePassword is the conventional Java truststore password.
const DefaultTruststorePassword = "changeit"

// BundleCompileRequest merges CA certificates from store CAs and/or files into one trust bundle.
type BundleCompileRequest struct {
	CANames  []string `json:"ca_names,omitempty"`
	Inputs   []string `json:"inputs,omitempty"`   // PEM or PKCS#7 (.p7b) files
	Format   string   `json:"format,omitempty"`   // pem (default) | p7b | p12
	Password string   `json:"password,omitempty"` // p12 integrity password (default "changeit")
	OutPath  string   `json:"out_path,omitempty"`
}

// BundleCompileResult is the compiled bundle. Binary formats are returned base64-encoded.
type BundleCompileResult struct {
	Format       string   `json:"format"`
	Certs        int      `json:"certs"`
	Duplicates   int      `json:"duplicates_dropped"`
	Fingerprints []string `json:"fingerprints"`
	Warnings     []string `json:"warnings,omitempty"`
	OutPath      string   `json:"out_path,omitempty"`
	Content      string   `json:"content,omitempty"` // PEM text, or base64 DER for p7b/p12 when no out_path
}

func loadCertsAny(raw []byte) ([]*x509.Certificate, error) {
	if certs, err := parseCertsFromBytes(raw); err == nil && len(certs) > 0 {
		return certs, nil
	}
	return DecodePKCS7CertsOnly(raw)
}

// CompileTrustBundle merges, de-duplicates (by SHA-256 fingerprint) and encodes CA certs.
func CompileTrustBundle(s *store.Store, req BundleCompileRequest) (*BundleCompileResult, error) {
	var all []*x509.Certificate
	for _, n := range req.CANames {
		if s == nil {
			return nil, errors.New("store is nil")
		}
		ca, err := s.GetCA(n)
		if err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(ca.ChainPath)
		if err != nil {
			if raw, err = os.ReadFile(ca.CertPath); err != nil {
				return nil, fmt.Errorf("read CA %q: %w", n, err)
			}
		}
		certs, err := loadCertsAny(raw)
		if err != nil {
			return nil, fmt.Errorf("parse CA %q: %w", n, err)
		}
		all = append(all, certs...)
	}
	for _, p := range req.Inputs {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read input %q: %w", p, err)
		}
		certs, err := loadCertsAny(raw)
		if err != nil {
			return nil, fmt.Errorf("parse input %q: %w", p, err)
		}
		all = append(all, certs...)
	}
	if len(all) == 0 {
		return nil, errors.New("no certificates: provide ca_names and/or inputs")
	}
	res := &BundleCompileResult{}
	seen := map[string]bool{}
	var uniq []*x509.Certificate
	for _, c := range all {
		fp := certFingerprintSHA256(c.Raw)
		if seen[fp] {
			res.Duplicates++
			continue
		}
		seen[fp] = true
		uniq = append(uniq, c)
		res.Fingerprints = append(res.Fingerprints, fp)
		if !c.IsCA {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s is not a CA certificate", c.Subject))
		}
		if time.Now().After(c.NotAfter) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s expired %s", c.Subject, c.NotAfter.UTC().Format(time.RFC3339)))
		}
	}
	res.Certs = len(uniq)

	var out []byte
	switch f := strings.ToLower(strings.TrimSpace(req.Format)); f {
	case "", "pem":
		res.Format = "pem"
		for _, c := range uniq {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
	case "p7b", "pkcs7":
		res.Format = "p7b"
		ders := make([][]byte, len(uniq))
		for i, c := range uniq {
			ders[i] = c.Raw
		}
		der, err := EncodePKCS7CertsOnly(ders...)
		if err != nil {
			return nil, err
		}
		out = der
	case "p12", "pkcs12":
		res.Format = "p12"
		pw := req.Password
		if pw == "" {
			pw = DefaultTruststorePassword
		}
		der, err := EncodePKCS12Truststore(uniq, pw)
		if err != nil {
			return nil, err
		}
		out = der
	default:
		return nil, fmt.Errorf("unsupported bundle format %q (expected pem, p7b, or p12)", f)
	}
	if req.OutPath != "" {
		if err := os.WriteFile(req.OutPath, out, 0o644); err != nil {
			return nil, fmt.Errorf("write bundle: %w", err)
		}
		res.OutPath = req.OutPath
	} else if res.Format == "pem" {
		res.Content = string(out)
	} else {
		res.Content = base64.StdEncoding.EncodeToString(out)
	}
	return res, nil
}

// ---- PKCS#12 truststore (certBags only, HMAC-SHA256 MAC; RFC 7292) ------------

var (
	oidP7Data        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidCertBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509Cert      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidJavaTrusted   = asn1.ObjectIdentifier{2, 16, 840, 1, 113894, 746875, 1, 1}
	oidAnyEKU        = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	p12MACIterations = 10000
)

type p12Attr struct {
	ID     asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type p12SafeBag struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"tag:0,explicit"`
	Attrs []p12Attr     `asn1:"set,omitempty"`
}

type p12ContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"tag:0,explicit"`
}

type p12DigestInfo struct {
	Alg    pkixAlg
	Digest []byte
}

type pkixAlg struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type p12MacData struct {
	Mac        p12DigestInfo
	Salt       []byte
	Iterations int
}

type p12PFX struct {
	Version  int
	AuthSafe p12ContentInfo
	Mac      p12MacData
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func explicit0(inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
}

func bmpString(s string, terminate bool) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u>>8), byte(u))
	}
	if terminate {
		out = append(out, 0, 0)
	}
	return out
}

// p12KDF is the RFC 7292 Appendix B.2 key derivation (SHA-256: u=32, v=64).
func p12KDF(password, salt []byte, id byte, iter, n int) []byte {
	const u, v = 32, 64
	fill := func(b []byte) []byte {
		if len(b) == 0 {
			return nil
		}
		out := make([]byte, v*((len(b)+v-1)/v))
		for i := range out {
			out[i] = b[i%len(b)]
		}
		return out
	}
	D := make([]byte, v)
	for i := range D {
		D[i] = id
	}
	I := append(fill(salt), fill(password)...)
	var out []byte
	for len(out) < n {
		h := sha256.Sum256(append(append([]byte{}, D...), I...))
		A := h[:]
		for i := 1; i < iter; i++ {
			h = sha256.Sum256(A)
			A = h[:]
		}
		out = append(out, A...)
		if len(out) >= n {
			break
		}
		B := make([]byte, v)
		for i := range B {
			B[i] = A[i%u]
		}
		bi := new(big.Int).SetBytes(B)
		bi.Add(bi, big.NewInt(1))
		mod := new(big.Int).Lsh(big.NewInt(1), v*8)
		for j := 0; j < len(I)/v; j++ {
			blk := new(big.Int).SetBytes(I[j*v : (j+1)*v])
			blk.Add(blk, bi).Mod(blk, mod)
			copy(I[j*v:(j+1)*v], blk.FillBytes(make([]byte, v)))
		}
	}
	return out[:n]
}

// EncodePKCS12Truststore builds a password-integrity-protected PKCS#12 holding only trusted
// certificates (Java keytool / OpenSSL compatible; certs are public so no content encryption).
func EncodePKCS12Truststore(certs []*x509.Certificate, password string) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("no certificates")
	}
	var bags []p12SafeBag
	for _, c := range certs {
		name := c.Subject.CommonName
		if name == "" {
			name = certFingerprintSHA256(c.Raw)[:16]
		}
		certBag := mustMarshal(struct {
			ID    asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"tag:0,explicit"`
		}{oidX509Cert, explicit0(mustMarshal(c.Raw))})
		fn := asn1.RawValue{FullBytes: mustMarshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagBMPString, Bytes: bmpString(name, false)})}
		trusted := asn1.RawValue{FullBytes: mustMarshal(oidAnyEKU)}
		bags = append(bags, p12SafeBag{
			ID:    oidCertBag,
			Value: explicit0(certBag),
			Attrs: []p12Attr{
				{oidFriendlyName, setOf(fn)},
				{oidJavaTrusted, setOf(trusted)},
			},
		})
	}
	safeContents := mustMarshal(bags)
	authSafe := mustMarshal([]p12ContentInfo{{oidP7Data, explicit0(mustMarshal(safeContents))}})

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := p12KDF(bmpString(password, true), salt, 3, p12MACIterations, 32)
	mac := hmac.New(sha256.New, key)
	mac.Write(authSafe)

	return asn1.Marshal(p12PFX{
		Version:  3,
		AuthSafe: p12ContentInfo{oidP7Data, explicit0(mustMarshal(authSafe))},
		Mac: p12MacData{
			Mac:        p12DigestInfo{pkixAlg{oidSHA256, asn1.NullRawValue}, mac.Sum(nil)},
			Salt:       salt,
			Iterations: p12MACIterations,
		},
	})
}

func setOf(v asn1.RawValue) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: v.FullBytes}
}

// ---- Concurrent multi-target TLS scanner -----------------------------------

// ScanRequest scans many endpoints concurrently using ProbeEndpoint.
type ScanRequest struct {
	Targets        []string      `json:"targets"` // host:port (":443" assumed if no port)
	CAName         string        `json:"ca_name,omitempty"`
	CACertPath     string        `json:"ca_cert_path,omitempty"`
	ClientCertName string        `json:"client_cert_name,omitempty"`
	Concurrency    int           `json:"concurrency,omitempty"` // default 16, max 256
	Timeout        time.Duration `json:"timeout,omitempty"`
	WarnDays       int           `json:"warn_days,omitempty"` // default 30
}

// ScanResult is one target's outcome.
type ScanResult struct {
	Target   string       `json:"target"`
	Error    string       `json:"error,omitempty"`
	Report   *ProbeReport `json:"report,omitempty"`
	LeafDays *int         `json:"leaf_days_remaining,omitempty"`
	Expiring bool         `json:"expiring,omitempty"`
	Findings []string     `json:"findings,omitempty"`
}

// ScanSummary aggregates the inventory.
type ScanSummary struct {
	Total       int            `json:"total"`
	Reachable   int            `json:"reachable"`
	Unreachable int            `json:"unreachable"`
	Verified    int            `json:"verified"`
	Expiring    int            `json:"expiring"`
	Legacy      int            `json:"legacy_tls"`
	TLSVersions map[string]int `json:"tls_versions"`
}

// ScanReport is the full inventory, in input order.
type ScanReport struct {
	Summary ScanSummary  `json:"summary"`
	Results []ScanResult `json:"results"`
}

const maxScanTargets = 4096

// ScanTargets probes all targets with bounded concurrency.
func ScanTargets(s *store.Store, req ScanRequest) (*ScanReport, error) {
	seen := map[string]bool{}
	var targets []string
	for _, t := range req.Targets {
		if t = strings.TrimSpace(t); t != "" && !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("at least one target is required")
	}
	if len(targets) > maxScanTargets {
		return nil, fmt.Errorf("too many targets (%d > %d)", len(targets), maxScanTargets)
	}
	conc := req.Concurrency
	if conc <= 0 {
		conc = 16
	}
	if conc > 256 {
		conc = 256
	}
	warn := req.WarnDays
	if warn <= 0 {
		warn = 30
	}
	results := make([]ScanResult, len(targets))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r := ScanResult{Target: t}
			rep, err := ProbeEndpoint(s, ProbeRequest{Address: t, CAName: req.CAName, CACertPath: req.CACertPath, ClientCertName: req.ClientCertName, Timeout: req.Timeout})
			switch {
			case err != nil:
				r.Error = err.Error()
			case !rep.Reachable:
				r.Report = rep
				r.Error = "unreachable"
			default:
				r.Report = rep
				if len(rep.PeerCertificates) > 0 {
					d := rep.PeerCertificates[0].DaysRemaining
					r.LeafDays = &d
					if d < warn {
						r.Expiring = true
						r.Findings = append(r.Findings, fmt.Sprintf("leaf expires in %d days", d))
					}
				}
				if rep.TLSVersion == "TLS 1.0" || rep.TLSVersion == "TLS 1.1" {
					r.Findings = append(r.Findings, "legacy "+rep.TLSVersion)
				}
				if !rep.Verified {
					r.Findings = append(r.Findings, "chain not verified: "+rep.VerificationError)
				}
			}
			results[i] = r
		}()
	}
	wg.Wait()

	sum := ScanSummary{Total: len(results), TLSVersions: map[string]int{}}
	for _, r := range results {
		if r.Report == nil || !r.Report.Reachable {
			sum.Unreachable++
			continue
		}
		sum.Reachable++
		if r.Report.Verified {
			sum.Verified++
		}
		if r.Expiring {
			sum.Expiring++
		}
		sum.TLSVersions[r.Report.TLSVersion]++
		if r.Report.TLSVersion == "TLS 1.0" || r.Report.TLSVersion == "TLS 1.1" {
			sum.Legacy++
		}
	}
	return &ScanReport{Summary: sum, Results: results}, nil
}
