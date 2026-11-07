package pki

import (
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestNamesWithTraversalAreRejected(t *testing.T) {
	s, _ := store.New(t.TempDir())
	if _, err := CreateCA(s, CARequest{Name: "../certs/web"}); err == nil {
		t.Error("CreateCA accepted ../certs/web")
	}
	if _, err := IssueSelfSigned(s, SelfSignedRequest{Name: "../ca/root", CommonName: "x"}); err == nil {
		t.Error("IssueSelfSigned accepted ../ca/root")
	}
	if _, err := IssueCert(s, CertRequest{Name: "a/b", CAName: "root"}); err == nil {
		t.Error("IssueCert accepted a/b")
	}
}

func TestTrustScriptQuotesShellAndPowerShell(t *testing.T) {
	path := "/tmp/x$(touch pwned)`id`'q.pem"
	scripts, err := GenerateTrustScript(path, "ca")
	if err != nil {
		t.Fatal(err)
	}
	want := `'/tmp/x$(touch pwned)` + "`id`" + `'\''q.pem'`
	for _, k := range []string{"debian", "rhel", "arch", "macos"} {
		if !strings.Contains(scripts[k], want) {
			t.Errorf("%s script not single-quoted: %s", k, scripts[k])
		}
	}
	if !strings.Contains(scripts["windows"], `'/tmp/x$(touch pwned)`+"`id`"+`''q.pem'`) {
		t.Errorf("windows script not single-quoted: %s", scripts["windows"])
	}
	if _, err := GenerateTrustScript("/tmp/a\nrm -rf /", "ca"); err == nil {
		t.Error("newline in caCertPath accepted")
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{"": "''", "a b": "'a b'", "it's": `'it'\''s'`} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
