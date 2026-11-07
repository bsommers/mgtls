package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestObtainRejectsNameThatAliasesCAKey(t *testing.T) {
	s, _ := store.New(t.TempDir())
	_, err := ObtainCertificate(context.Background(), s, ObtainRequest{Name: "../ca/root", Domains: []string{"x.internal"}})
	if err == nil {
		t.Fatal("expected ACME name ../ca/root to be rejected")
	}
	if _, statErr := os.Stat(filepath.Join(s.BaseDir, "ca", "root")); statErr == nil {
		t.Fatal("ACME request created files under ca/root")
	}
}

func TestValidACMEToken(t *testing.T) {
	for _, bad := range []string{"", "../../etc/cron.d/x", "a/b", "tok en", "tok\n", "a.b"} {
		if validACMEToken(bad) {
			t.Errorf("validACMEToken(%q) = true", bad)
		}
	}
	if !validACMEToken("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA") {
		t.Error("RFC 8555 example token rejected")
	}
}

func TestValidateIssuedCertRejectsGarbageAndWrongKey(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, _, err := validateIssuedCert([]byte("not a cert"), k1, []string{"a.test"}); err == nil {
		t.Error("garbage chain accepted")
	}
	tlsCert, err := BuildTLSALPN01Cert("a.test", "ka")
	if err != nil {
		t.Fatal(err)
	}
	pemCert := pemEncodeCert(tlsCert.Certificate[0])
	if _, _, err := validateIssuedCert(pemCert, k2, []string{"a.test"}); err == nil {
		t.Error("certificate for a different key accepted")
	}
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
