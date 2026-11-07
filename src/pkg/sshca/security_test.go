package sshca

import (
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
