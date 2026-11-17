package store

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestValidNameRejectsTraversalAndMetachars(t *testing.T) {
	for _, bad := range []string{"", "../ca/root", "a/b", ".hidden", "a..b", "x y", "a;b", "a\nb", "-flag", string(make([]byte, MaxNameLen+1))} {
		if err := ValidName("test", bad); err == nil {
			t.Errorf("ValidName(%q) = nil, want error", bad)
		}
	}
	for _, good := range []string{"root", "web-01", "api.internal", "a_b", "A9"} {
		if err := ValidName("test", good); err != nil {
			t.Errorf("ValidName(%q) = %v, want nil", good, err)
		}
	}
}

func TestWriteKeyReplacesSymlinkInsteadOfFollowing(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.Path("certs", "x"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, s.Path("certs", "x", "key.pem")); err != nil {
		t.Fatal(err)
	}
	full, err := s.WriteKey(filepath.Join("certs", "x", "key.pem"), []byte("secret"))
	if err != nil {
		t.Fatalf("WriteKey: %v", err)
	}
	if got, _ := os.ReadFile(outside); string(got) != "original" {
		t.Fatalf("WriteKey wrote through symlink: victim now %q", got)
	}
	fi, err := os.Lstat(full)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0600 {
		t.Fatalf("key file not a 0600 regular file: %v %v", fi.Mode(), err)
	}
}

// Two Store handles on one directory model two processes (watch daemon + CLI).
func TestConcurrentUpsertsFromSeparateHandlesLoseNothing(t *testing.T) {
	dir := t.TempDir()
	a, _ := New(dir)
	b, _ := New(dir)
	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := a
			if i%2 == 1 {
				st = b
			}
			if err := st.UpsertTarget(TargetRecord{Name: "t" + string(rune('A'+i)), TargetType: "nginx"}); err != nil {
				t.Errorf("UpsertTarget: %v", err)
			}
		}(i)
	}
	wg.Wait()
	m, err := a.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Targets) != n {
		t.Fatalf("lost updates: got %d targets, want %d", len(m.Targets), n)
	}
}
