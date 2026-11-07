package sshca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func newSSHStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateSSHCA(s, SSHCARequest{Name: "users", CAType: "user"}); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateSSHCA(s, SSHCARequest{Name: "hosts", CAType: "host"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignRejectsEmptyAndInjectedPrincipals(t *testing.T) {
	s := newSSHStore(t)
	cases := map[string][]string{
		"empty (= any user)": nil,
		"newline":            {"alice\nroot"},
		"comma":              {"alice,root"},
		"wildcard on user":   {"*"},
		"whitespace":         {" "},
	}
	for name, p := range cases {
		if _, err := SignSSHCert(s, SignSSHRequest{Name: "c", CAName: "users", Principals: p}); err == nil {
			t.Errorf("%s: principals %q accepted", name, p)
		}
	}
	if _, err := SignSSHCert(s, SignSSHRequest{Name: "h", CAName: "hosts", Principals: []string{"*.corp.internal"}}); err != nil {
		t.Errorf("host wildcard principal rejected: %v", err)
	}
}

func TestSignRejectsCATypeMismatchAndHugeValidity(t *testing.T) {
	s := newSSHStore(t)
	_, err := SignSSHCert(s, SignSSHRequest{Name: "c", CAName: "hosts", CertType: "user", Principals: []string{"alice"}})
	if err == nil || !strings.Contains(err.Error(), "cannot sign") {
		t.Errorf("host CA signed a user cert: %v", err)
	}
	if _, err := SignSSHCert(s, SignSSHRequest{Name: "c", CAName: "users", Principals: []string{"alice"}, ValidHours: 1 << 40}); err == nil {
		t.Error("overflowing valid_hours accepted")
	}
	if _, err := SignSSHCert(s, SignSSHRequest{Name: "../x", CAName: "users", Principals: []string{"alice"}}); err == nil {
		t.Error("traversal in SSH cert name accepted")
	}
}

func TestConfigBundleRejectsDirectiveInjection(t *testing.T) {
	s := newSSHStore(t)
	out := t.TempDir()
	if _, err := GenerateSSHConfigBundle(s, SSHConfigRequest{Name: "b", HostCAName: "hosts", HostPatterns: []string{"*.internal\n    ProxyCommand sh -c id"}, OutputDir: out}); err == nil {
		t.Error("newline in host pattern accepted")
	}
	if _, err := GenerateSSHConfigBundle(s, SSHConfigRequest{Name: "b", UserCAName: "users", Principals: []string{"ops\nroot"}, OutputDir: out}); err == nil {
		t.Error("newline in bundle principal accepted")
	}
}

func TestConfigBundlePerAccountPrincipals(t *testing.T) {
	s := newSSHStore(t)
	out := t.TempDir()
	b, err := GenerateSSHConfigBundle(s, SSHConfigRequest{
		Name:              "acct",
		UserCAName:        "users",
		AccountPrincipals: map[string][]string{"deploy": {"alice", "ci"}, "alice": {"alice"}},
		OutputDir:         out,
	})
	if err != nil {
		t.Fatalf("GenerateSSHConfigBundle: %v", err)
	}
	want := map[string]string{"deploy": "alice\nci\n", "alice": "alice\n"}
	for acct, content := range want {
		got, err := os.ReadFile(filepath.Join(b.AuthorizedPrincipalsDir, acct))
		if err != nil || string(got) != content {
			t.Errorf("auth_principals/%s = %q (%v), want %q", acct, got, err, content)
		}
	}
	// "ci" must not be able to log in as root or alice: no file for root, alice's file lacks ci.
	if _, err := os.Stat(filepath.Join(b.AuthorizedPrincipalsDir, "root")); !os.IsNotExist(err) {
		t.Errorf("unexpected auth_principals/root: %v", err)
	}
	conf, _ := os.ReadFile(b.SSHDConfigPath)
	if !strings.Contains(string(conf), "AuthorizedPrincipalsFile "+filepath.Join(out, "auth_principals", "%u")) {
		t.Errorf("drop-in missing %%u directive:\n%s", conf)
	}

	// Re-running without an account removes its file so the grant is revoked.
	if _, err := GenerateSSHConfigBundle(s, SSHConfigRequest{Name: "acct", UserCAName: "users", AccountPrincipals: map[string][]string{"alice": {"alice"}}, OutputDir: out}); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.AuthorizedPrincipalsDir, "deploy")); !os.IsNotExist(err) {
		t.Errorf("stale auth_principals/deploy survived regeneration: %v", err)
	}
}

func TestConfigBundleRejectsBadAccounts(t *testing.T) {
	s := newSSHStore(t)
	out := t.TempDir()
	for _, acct := range []string{"..", "../etc", "a/b", "Root", "-x", "", "%u", "a b", strings.Repeat("a", 33)} {
		if _, err := GenerateSSHConfigBundle(s, SSHConfigRequest{Name: "b", UserCAName: "users", AccountPrincipals: map[string][]string{acct: {"alice"}}, OutputDir: out}); err == nil {
			t.Errorf("account name %q accepted", acct)
		}
	}
	cases := []SSHConfigRequest{
		{Name: "b", UserCAName: "users", AccountPrincipals: map[string][]string{"deploy": {}}, OutputDir: out},
		{Name: "b", UserCAName: "users", AccountPrincipals: map[string][]string{"deploy": {"ops\nroot"}}, OutputDir: out},
		{Name: "b", UserCAName: "users", Principals: []string{"alice"}, AccountPrincipals: map[string][]string{"deploy": {"ci"}}, OutputDir: out},
		// Shorthand principals double as account names, so "alice@corp" must be mapped explicitly.
		{Name: "b", UserCAName: "users", Principals: []string{"alice@corp"}, OutputDir: out},
	}
	for i, req := range cases {
		if _, err := GenerateSSHConfigBundle(s, req); err == nil {
			t.Errorf("case %d accepted: %+v", i, req)
		}
	}
}
