package store

import (
	"os"
	"strings"
	"sync"
	"testing"
)

func TestAuditChain(t *testing.T) {
	s, _ := New(t.TempDir())
	if rep, err := s.VerifyAudit(""); err != nil || !rep.Valid || rep.Entries != 0 || rep.HeadHash != AuditGenesisHash {
		t.Fatalf("empty ledger: %+v %v", rep, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Audit(AuditCertIssue, "c", map[string]string{"b": "2", "a": "1"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	rep, err := s.VerifyAudit("")
	if err != nil || !rep.Valid || rep.Entries != 20 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	head := rep.HeadHash
	if r, _ := s.VerifyAudit(head); !r.Valid {
		t.Error("pinned head should verify")
	}
	_ = s.Audit(AuditVaultSeal, "vault", nil)
	if l, _ := s.ListAudit(AuditVaultSeal, 0); len(l) != 1 {
		t.Errorf("filter: %d", len(l))
	}
	if l, _ := s.ListAudit("", 3); len(l) != 3 || l[2].Event != AuditVaultSeal {
		t.Errorf("last: %+v", l)
	}
	// old head pin must now fail (ledger grew / differs)
	if r, _ := s.VerifyAudit(head); r.Valid {
		t.Error("stale pin accepted")
	}

	raw, _ := os.ReadFile(s.AuditPath())
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	write := func(ls []string) { _ = os.WriteFile(s.AuditPath(), []byte(strings.Join(ls, "\n")+"\n"), 0o600) }
	defer write(lines)

	mod := append([]string{}, lines...)
	mod[4] = strings.Replace(mod[4], `"subject":"c"`, `"subject":"evil"`, 1)
	write(mod)
	if r, _ := s.VerifyAudit(""); r.Valid || r.BrokenSeq != 5 {
		t.Errorf("modification: %+v", r)
	}
	write(append(append([]string{}, lines[:3]...), lines[4:]...))
	if r, _ := s.VerifyAudit(""); r.Valid || r.BrokenSeq != 5 {
		t.Errorf("deletion: %+v", r)
	}
	write(lines[:len(lines)-2])
	if r, _ := s.VerifyAudit(""); !r.Valid {
		t.Error("tail truncation is valid unpinned")
	}
	if r, _ := s.VerifyAudit(head); r.Valid {
		t.Error("truncation must fail when head pinned")
	}
	write(append(append([]string{}, lines...), "{not json"))
	if r, _ := s.VerifyAudit(""); r.Valid {
		t.Error("garbage line accepted")
	}
	if err := s.Audit("x", "y", nil); err == nil {
		t.Error("append to corrupt ledger must be refused")
	}
}
