package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func csrTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, _ := store.New(t.TempDir())
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCA(st, CARequest{Name: "ca", CommonName: "CSR Test CA"}); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestCSRCreateSignVerifyNoLeafKeyInStore(t *testing.T) {
	st := csrTestStore(t)
	dir := t.TempDir()
	c, err := CreateCSR(CSRRequest{Name: "web", CommonName: "web.internal", DNSNames: []string{"web.internal", "alt.internal"}, IPAddresses: []string{"10.0.0.5"}, OutDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(c.KeyPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("key perm %v", info.Mode().Perm())
	}
	// Refuses to clobber the key.
	if _, err := CreateCSR(CSRRequest{Name: "web", OutDir: dir}); err == nil {
		t.Fatal("must not overwrite existing key")
	}

	res, err := SignCSR(st, SignCSRRequest{CAName: "ca", CSRPath: c.CSRPath, Role: "server", ValidDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Record.External || res.Record.KeyPath != "" || res.Record.Name != "web.internal" {
		t.Fatalf("record: %+v", res.Record)
	}
	// No private key material anywhere under the store.
	_ = filepath.Walk(st.BaseDir, func(p string, i os.FileInfo, _ error) error {
		if i != nil && !i.IsDir() && !strings.Contains(p, filepath.Join("ca", "ca")) {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), "PRIVATE KEY") {
				t.Errorf("private key found in store: %s", p)
			}
		}
		return nil
	})
	// Issued cert matches the requester's key and chains to the CA with SANs.
	blk, _ := pem.Decode([]byte(res.CertPEM))
	cert, _ := x509.ParseCertificate(blk.Bytes)
	keyRaw, _ := os.ReadFile(c.KeyPath)
	signer, err := parsePrivateKeyPEM(keyRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(cert.PublicKey) {
		t.Fatal("cert public key != requester key")
	}
	if cert.IsCA || len(cert.DNSNames) != 2 || len(cert.IPAddresses) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("unexpected cert: %+v", cert)
	}
	vr, err := VerifyChain(res.Record.CertPath, res.Record.CAChainPath, "", "web.internal", "server")
	if err != nil || !vr.Valid {
		t.Fatalf("verify: %v %+v", err, vr)
	}
	// Reusing an existing key (renewal) works.
	if _, err := CreateCSR(CSRRequest{Name: "web2", ExistingKey: c.KeyPath, OutDir: dir}); err != nil {
		t.Fatal(err)
	}
}

func buildCSR(t *testing.T, tmpl *x509.CertificateRequest, key any) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestSignCSRRejectsAndIgnoresHostileRequests(t *testing.T) {
	st := csrTestStore(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// CSR requesting CA:TRUE via extension must still yield a leaf.
	bcExt, _ := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{true})
	evil := buildCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "evil.internal"}, DNSNames: []string{"evil.internal"},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bcExt}},
	}, k)
	res, err := SignCSR(st, SignCSRRequest{CAName: "ca", CSRPEM: evil})
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(res.CertPEM))
	cert, _ := x509.ParseCertificate(blk.Bytes)
	if cert.IsCA {
		t.Fatal("CSR must not be able to mint a CA")
	}

	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, tc := range map[string]SignCSRRequest{
		"weak rsa":   {CAName: "ca", CSRPEM: buildCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "w.internal"}}, weak)},
		"no names":   {CAName: "ca", CSRPEM: buildCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "has space"}}, k), Name: ""},
		"not pem":    {CAName: "ca", CSRPEM: "garbage"},
		"no input":   {CAName: "ca"},
		"wrong type": {CAName: "ca", CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}))},
		"unknown ca": {CAName: "nope", CSRPEM: evil},
		"bad role":   {CAName: "ca", CSRPEM: evil, Role: "wizard"},
		"huge":       {CAName: "ca", CSRPEM: strings.Repeat("A", maxCSRBytes+1)},
	} {
		if _, err := SignCSR(st, tc); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Tampered CSR signature fails proof of possession.
	blk2, _ := pem.Decode([]byte(evil))
	blk2.Bytes[len(blk2.Bytes)-3] ^= 0xff
	if _, err := SignCSR(st, SignCSRRequest{CAName: "ca", CSRPEM: string(pem.EncodeToMemory(blk2))}); err == nil {
		t.Error("tampered CSR must fail")
	}
	// CreateCSR input validation.
	for _, n := range []string{"", "../x", "a/b", ".."} {
		if _, err := CreateCSR(CSRRequest{Name: n, OutDir: t.TempDir()}); err == nil {
			t.Errorf("name %q must be rejected", n)
		}
	}
}

func TestCASealedKeyStillSignsAndCSRWorks(t *testing.T) {
	t.Setenv(store.EnvPassphrase, "ca-pass")
	st := csrTestStore(t) // CA created while vault is on
	rec, _ := st.GetCA("ca")
	raw, _ := os.ReadFile(rec.KeyPath)
	if !store.IsSealed(raw) {
		t.Fatal("CA key should be sealed on disk")
	}
	if _, err := IssueCert(st, CertRequest{Name: "leaf", CAName: "ca", DNSNames: []string{"leaf.internal"}}); err != nil {
		t.Fatalf("issue with sealed CA: %v", err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := buildCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "c.internal"}}, k)
	if _, err := SignCSR(st, SignCSRRequest{CAName: "ca", CSRPEM: csr}); err != nil {
		t.Fatalf("csr sign with sealed CA: %v", err)
	}
	if _, err := RevokeCert(st, "ca", "leaf", 0); err != nil {
		t.Fatalf("revoke with sealed CA: %v", err)
	}
	t.Setenv(store.EnvPassphrase, "wrong")
	if _, err := IssueCert(st, CertRequest{Name: "leaf2", CAName: "ca", DNSNames: []string{"x.internal"}}); err == nil {
		t.Fatal("wrong passphrase must fail issuance")
	}
}
