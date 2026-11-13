package pki

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestValidateSPIFFEID(t *testing.T) {
	ok := map[string][2]string{
		"spiffe://example.org/ns/prod/sa/web": {"example.org", "/ns/prod/sa/web"},
		"spiffe://a-b_c.d/x":                  {"a-b_c.d", "/x"},
	}
	for in, want := range ok {
		td, p, err := ValidateSPIFFEID(in)
		if err != nil || td != want[0] || p != want[1] {
			t.Errorf("%s: got %q %q %v", in, td, p, err)
		}
	}
	for _, bad := range []string{
		"", "https://example.org/x", "spiffe://", "spiffe://example.org", "spiffe://example.org/",
		"spiffe://Example.org/x", "spiffe://example.org:8080/x", "spiffe://u@example.org/x",
		"spiffe://example.org/x/", "spiffe://example.org/a//b", "spiffe://example.org/../x",
		"spiffe://example.org/./x", "spiffe://example.org/x?q=1", "spiffe://example.org/x#f",
		"spiffe://example.org/a b",
	} {
		if _, _, err := ValidateSPIFFEID(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestSVIDIssueVerifyBundle(t *testing.T) {
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCA(s, CARequest{Name: "root-ca", CommonName: "SPIFFE Root", Algorithm: "ecdsa-p256"}); err != nil {
		t.Fatal(err)
	}
	id := "spiffe://example.org/ns/prod/sa/web"
	res, err := IssueSVID(s, SVIDRequest{Name: "web", SPIFFEID: id, CAName: "root-ca", Algorithm: "ecdsa-p256", DNSNames: []string{"web.example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Record.URIs) != 1 || res.Record.URIs[0] != id || len(res.Record.DNSNames) != 1 {
		t.Fatalf("unexpected SANs: %+v", res.Record)
	}
	if _, err := IssueSVID(s, SVIDRequest{Name: "bad", SPIFFEID: "spiffe://Bad/x", CAName: "root-ca"}); err == nil {
		t.Error("expected invalid SPIFFE ID rejection")
	}

	rep, err := VerifySVID(s, VerifySVIDRequest{CertName: "web", CAName: "root-ca", TrustDomain: "example.org", ExpectedID: id})
	if err != nil || !rep.Valid || rep.SPIFFEID != id || rep.Path != "/ns/prod/sa/web" {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	rep, _ = VerifySVID(s, VerifySVIDRequest{CertName: "web", CAName: "root-ca", TrustDomain: "other.org"})
	if rep.Valid {
		t.Error("expected trust domain mismatch")
	}
	if _, err := VerifySVID(s, VerifySVIDRequest{CertName: "web"}); err == nil {
		t.Error("expected error without CA/bundle")
	}

	// Non-SVID leaf (no URI SAN) must fail.
	if _, err := IssueCert(s, CertRequest{Name: "plain", CAName: "root-ca", Role: "mtls"}); err != nil {
		t.Fatal(err)
	}
	rep, _ = VerifySVID(s, VerifySVIDRequest{CertName: "plain", CAName: "root-ca"})
	if rep.Valid {
		t.Error("cert without URI SAN accepted as SVID")
	}

	// Revocation.
	if _, err := RevokeCert(s, "root-ca", "web", 1); err != nil {
		t.Fatal(err)
	}
	rep, _ = VerifySVID(s, VerifySVIDRequest{CertName: "web", CAName: "root-ca"})
	if rep.Valid || !rep.Revoked {
		t.Errorf("expected revoked SVID: %+v", rep)
	}

	// Bundles.
	out := filepath.Join(t.TempDir(), "b.json")
	b, err := ExportTrustBundle(s, TrustBundleRequest{CAName: "root-ca", Sequence: 7, OutPath: out})
	if err != nil || b.MediaType != SPIFFEBundleMediaType {
		t.Fatal(b, err)
	}
	var doc struct {
		Seq  uint64 `json:"spiffe_sequence"`
		Hint int    `json:"spiffe_refresh_hint"`
		Keys []struct {
			Kty, Use, Crv, X, Y string
			X5C                 []string `json:"x5c"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(b.Content), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Seq != 7 || doc.Hint != 300 || len(doc.Keys) != 1 || doc.Keys[0].Kty != "EC" || doc.Keys[0].Use != "x509-svid" || len(doc.Keys[0].X5C) != 1 || doc.Keys[0].Y == "" {
		t.Errorf("bad bundle doc: %+v", doc)
	}
	p, err := ExportTrustBundle(s, TrustBundleRequest{CAName: "root-ca", Format: "pem"})
	if err != nil || !strings.Contains(p.Content, "BEGIN CERTIFICATE") {
		t.Fatal(p, err)
	}
	if _, err := ExportTrustBundle(s, TrustBundleRequest{CAName: "root-ca", Format: "xml"}); err == nil {
		t.Error("expected bad format error")
	}

	// Ed25519 + RSA JWK mapping.
	for _, alg := range []string{"ed25519", "rsa-2048"} {
		name := "ca-" + alg
		if _, err := CreateCA(s, CARequest{Name: name, CommonName: name, Algorithm: alg}); err != nil {
			t.Fatal(err)
		}
		if _, err := ExportTrustBundle(s, TrustBundleRequest{CAName: name}); err != nil {
			t.Errorf("%s: %v", alg, err)
		}
	}
}
